from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import threading
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any, cast
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from forenx import __version__
from forenx.adapters import PhysicalExtent
from forenx.auth import UserRecord
from forenx.biometrics import (
    BiometricAuthorizationStore,
    FaceDetectionStore,
    FaceDetectionStoreError,
    FaceTrackingStore,
    FaceTrackingStoreError,
)
from forenx.cases import CaseNotFoundError, CaseStatus, CaseStore
from forenx.custody import CustodyLedger
from forenx.evidence import (
    EvidenceCatalog,
    EvidenceCatalogError,
    EvidenceNotFoundError,
    EvidenceRecord,
)
from forenx.package import (
    ArtifactInput,
    KeyManagementError,
    PackageError,
    SourceEvidenceRecord,
    build_evidence_package,
    generate_signing_key,
    load_private_key,
    public_key_fingerprint,
    save_private_key,
)
from forenx.video import MediaInspectionNotFoundError, MediaStore
from forenx.video.inspection import inspection_to_payload

from .certificate import (
    OFFICIAL_BSA_URI,
    CertificateWorksheetRenderingError,
    render_section_63_support_worksheet,
)
from .pdf import ReportRenderingError, render_examination_report

REPORT_SCHEMA = "forenx-examination-report/v4"
MAX_ANALYSIS_PREVIEW_BYTES = 64 * 1024 * 1024
DEFAULT_LIMITATIONS = (
    "The software records technical observations; it does not determine legal admissibility.",
    "An exported clip does not prove completeness of the originating DVR or NVR storage.",
    "Identity conclusions must not be inferred from appearance alone.",
    "Recorder time is qualified by the documented clock offset and collection context.",
)


class ReportPackageError(RuntimeError):
    """Raised when a signed report package cannot be produced or located."""


class ReportPackageNotFoundError(ReportPackageError):
    pass


@dataclass(frozen=True, slots=True)
class ReportPackageRecord:
    package_id: str
    case_id: str
    exhibit_id: str
    source_id: str
    report_title: str
    created_by: str
    created_at: datetime
    manifest_sha256: str
    archive_sha256: str
    public_key_fingerprint: str
    archive_path: Path


class ReportPackageService:
    def __init__(
        self,
        database: str | Path,
        export_directory: str | Path,
        *,
        cases: CaseStore,
        evidence: EvidenceCatalog,
        media: MediaStore,
        biometric_authorizations: BiometricAuthorizationStore | None = None,
        face_detections: FaceDetectionStore | None = None,
        face_tracks: FaceTrackingStore | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._cases = cases
        self._evidence = evidence
        self._media = media
        self._biometric_authorizations = biometric_authorizations
        self._face_detections = face_detections
        self._face_tracks = face_tracks
        self._root = _prepare_directory(Path(export_directory))
        self._packages = _prepare_directory(self._root / "packages")
        self._keys = _prepare_directory(self._root / "keys")
        self._signing_key_path = self._keys / "laboratory-ed25519.pem"
        target = _database_target(database)
        self._connection = sqlite3.connect(target, check_same_thread=False, timeout=5)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if target != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS report_packages (
                    package_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    exhibit_id TEXT NOT NULL REFERENCES exhibits(exhibit_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    report_title TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    archive_name TEXT NOT NULL UNIQUE
                );

                CREATE INDEX IF NOT EXISTS idx_report_packages_case_time
                    ON report_packages(case_id, created_at DESC);

                CREATE TRIGGER IF NOT EXISTS report_packages_no_update
                BEFORE UPDATE ON report_packages BEGIN
                    SELECT RAISE(ABORT, 'report packages are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS report_packages_no_delete
                BEFORE DELETE ON report_packages BEGIN
                    SELECT RAISE(ABORT, 'report packages are immutable');
                END;
                """
            )
            self._connection.execute("PRAGMA optimize")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> ReportPackageService:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def create(
        self,
        source_id: str,
        *,
        user: UserRecord,
        signing_password: str,
        report_title: str,
        purpose: str,
        examiner_conclusion: str,
        limitations: tuple[str, ...] = (),
        created_at: datetime | None = None,
    ) -> ReportPackageRecord:
        title = _required_text(report_title, "Report title", maximum=256)
        normalized_purpose = _required_text(purpose, "Purpose", maximum=5000)
        conclusion = _required_text(
            examiner_conclusion,
            "Examiner conclusion",
            maximum=10_000,
        )
        normalized_limitations = tuple(
            _required_text(value, "Limitation", maximum=2000) for value in limitations
        )
        if len(normalized_limitations) > 50:
            raise ReportPackageError("A report cannot contain more than 50 limitations")
        password = signing_password.encode("utf-8")
        if len(password) < 12 or len(password) > 1024:
            raise ReportPackageError("Signing password must contain between 12 and 1024 bytes")

        try:
            source = self._evidence.get(source_id)
            case = self._cases.get_case(source.case_id)
            exhibit = self._cases.get_exhibit(source.exhibit_id)
            inspection = self._media.latest_inspection(source_id)
        except (
            CaseNotFoundError,
            EvidenceNotFoundError,
            MediaInspectionNotFoundError,
        ) as exc:
            raise ReportPackageError(str(exc)) from exc
        if case.status not in {CaseStatus.APPROVED, CaseStatus.CLOSED}:
            raise ReportPackageError("A signed report requires an approved or closed case")
        activity_verification = self._cases.verify_activity(case.case_id)
        if not activity_verification.valid:
            raise ReportPackageError("Case activity verification failed; export is blocked")
        integrity_verified, observed_sha256 = self._evidence.verify(source_id)
        if not integrity_verified:
            raise ReportPackageError(
                "Source evidence integrity verification failed; export is blocked"
            )
        parent_source: EvidenceRecord | None = None
        parent_observed_sha256: str | None = None
        if source.parent_source_id is not None:
            if source.derivation is None or source.derived_artifact_id is None:
                raise ReportPackageError("Recovered source provenance is incomplete")
            try:
                parent_source = self._evidence.get(source.parent_source_id)
            except EvidenceNotFoundError as exc:
                raise ReportPackageError("Recovered source parent evidence is unavailable") from exc
            if (
                parent_source.case_id != source.case_id
                or parent_source.exhibit_id != source.exhibit_id
            ):
                raise ReportPackageError("Recovered source parent scope is inconsistent")
            parent_valid, parent_observed_sha256 = self._evidence.verify(
                parent_source.source_id
            )
            if not parent_valid:
                raise ReportPackageError(
                    "Parent disk-image integrity verification failed; export is blocked"
                )

        created = (created_at or datetime.now(UTC)).astimezone(UTC)
        package_id = str(uuid4())
        package_directory = self._packages / package_id
        archive_name = f"{package_id}.forenx.zip"
        archive_path = self._packages / archive_name
        try:
            package_directory.mkdir(mode=0o700)
        except OSError as exc:
            raise ReportPackageError("Report package workspace could not be created") from exc

        try:
            key = self._load_or_create_signing_key(password)
            fingerprint = public_key_fingerprint(key)
            activity = self._cases.list_activity(case.case_id)
            bookmarks = self._media.list_bookmarks(source_id)
            authorizations = (
                self._biometric_authorizations.list_for_source(source_id)
                if self._biometric_authorizations is not None
                else ()
            )
            face_detection_store = self._face_detections
            detection_runs = (
                face_detection_store.list_for_source(source_id)
                if face_detection_store is not None
                else ()
            )
            tracking_runs = (
                self._face_tracks.list_for_source(source_id)
                if self._face_tracks is not None
                else ()
            )
            detection_records: list[dict[str, Any]] = []
            detection_artifacts: list[ArtifactInput] = []
            detection_archive_names: list[str] = []
            for run in detection_runs:
                if face_detection_store is None:
                    raise ReportPackageError("Face-detection records are unavailable")
                preview_path, preview_sha256 = face_detection_store.preview(run.run_id)
                preview_bytes = _read_verified_preview(
                    preview_path,
                    expected_sha256=preview_sha256,
                )
                preview_name = f"face-detection-{run.run_id}.png"
                _write_exclusive(package_directory / preview_name, preview_bytes)
                detection_record = _json_record(run)
                detection_record["preview_artifact"] = preview_name
                detection_records.append(detection_record)
                detection_archive_names.append(preview_name)
                detection_artifacts.append(
                    ArtifactInput(
                        relative_path=preview_name,
                        role="face-detection-decoded-frame-preview",
                        source_extents=(PhysicalExtent(0, source.byte_size),),
                        transformation=(
                            "nearest source video frame decoded to PNG for controlled "
                            "face-location review; exact compressed packet extent unavailable"
                        ),
                        media_type="image/png",
                    )
                )
            source_evidence: dict[str, Any] = {
                "source_id": source.source_id,
                "original_filename": source.original_filename,
                "media_kind": source.media_kind.value,
                "byte_size": source.byte_size,
                "sha256": source.sha256,
                "observed_sha256": observed_sha256,
                "integrity_verified": True,
                "ingested_at": _normalized_time(source.created_at),
                "ingested_by": source.created_by,
            }
            if parent_source is not None and parent_observed_sha256 is not None:
                source_evidence["recovery_provenance"] = {
                    "parent_source_id": parent_source.source_id,
                    "parent_original_filename": parent_source.original_filename,
                    "parent_media_kind": parent_source.media_kind.value,
                    "parent_byte_size": parent_source.byte_size,
                    "parent_sha256": parent_source.sha256,
                    "parent_observed_sha256": parent_observed_sha256,
                    "parent_integrity_verified": True,
                    "derived_artifact_id": source.derived_artifact_id,
                    "derivation": source.derivation,
                }
            report = {
                "schema": REPORT_SCHEMA,
                "report_id": package_id,
                "report_title": title,
                "created_at": _normalized_time(created),
                "created_by": user.user_id,
                "created_by_display": user.display_name,
                "created_by_role": user.role.value,
                "tool": {"name": "ForenX", "version": __version__},
                "case": _json_record(case),
                "exhibit": _json_record(exhibit),
                "source_evidence": source_evidence,
                "media_inspection": inspection_to_payload(inspection.result),
                "inspection_recorded_at": _normalized_time(inspection.inspected_at),
                "inspection_recorded_by": inspection.inspected_by,
                "bookmarks": [_json_record(bookmark) for bookmark in bookmarks],
                "biometric_authorizations": [
                    _json_record(authorization) for authorization in authorizations
                ],
                "face_detection_runs": detection_records,
                "face_tracking_runs": [_json_record(run) for run in tracking_runs],
                "section_63_4_support": {
                    "status": "unsigned-worksheet-only",
                    "worksheet_artifact": "section-63-4-support-worksheet.pdf",
                    "hash_report_artifact": "source-hash-report.json",
                    "official_source": OFFICIAL_BSA_URI,
                    "qualification": (
                        "Authorized party and expert must independently verify, complete, "
                        "sign, and obtain legal review of the statutory certificate."
                    ),
                },
                "purpose": normalized_purpose,
                "examiner_conclusion": conclusion,
                "limitations": list((*DEFAULT_LIMITATIONS, *normalized_limitations)),
                "activity_verification": _json_record(activity_verification),
                "activity_events": [_json_record(event) for event in activity],
                "signing_key_fingerprint": fingerprint,
            }
            report_limitations = cast(list[str], report["limitations"])
            json_bytes = _canonical_json(report)
            pdf_bytes = render_examination_report(report)
            report_json = package_directory / "examination-report.json"
            report_pdf = package_directory / "examination-report.pdf"
            worksheet_pdf = package_directory / "section-63-4-support-worksheet.pdf"
            hash_report_json = package_directory / "source-hash-report.json"
            _write_exclusive(report_json, json_bytes)
            _write_exclusive(report_pdf, pdf_bytes)
            _write_exclusive(
                worksheet_pdf,
                render_section_63_support_worksheet(report),
            )
            _write_exclusive(
                hash_report_json,
                _canonical_json(
                    {
                        "schema": "forenx-source-hash-report/v1",
                        "created_at": _normalized_time(created),
                        "report_id": package_id,
                        "source_id": source.source_id,
                        "original_filename": source.original_filename,
                        "byte_size": source.byte_size,
                        "algorithm": "SHA-256",
                        "expected_sha256": source.sha256,
                        "observed_sha256": observed_sha256,
                        "integrity_verified": True,
                        "qualification": (
                            "The authorized signatory and expert must independently confirm "
                            "this hash against the exact electronic record submitted."
                        ),
                    }
                ),
            )
            custody = _export_custody(activity)
            build_result = build_evidence_package(
                package_directory,
                case_id=case.case_id,
                exhibit_id=exhibit.exhibit_id,
                source=SourceEvidenceRecord(
                    source_id=source.source_id,
                    original_filename=source.original_filename,
                    size=source.byte_size,
                    hashes={"sha256": source.sha256},
                    acquisition_method=(
                        "exact source-extent recovery registered in the protected ForenX "
                        "evidence vault"
                        if parent_source is not None
                        else "protected ForenX evidence-vault ingestion"
                    ),
                    read_only=True,
                ),
                artifacts=(
                    ArtifactInput(
                        relative_path=report_json.name,
                        role="structured-examination-report",
                        source_extents=(PhysicalExtent(0, source.byte_size),),
                        transformation=(
                            "case-linked metadata and examiner observations serialized as JSON"
                        ),
                        media_type="application/json",
                    ),
                    ArtifactInput(
                        relative_path=report_pdf.name,
                        role="human-readable-examination-report",
                        source_extents=(PhysicalExtent(0, source.byte_size),),
                        transformation="structured examination report rendered as static PDF",
                        media_type="application/pdf",
                    ),
                    ArtifactInput(
                        relative_path=worksheet_pdf.name,
                        role="section-63-4-certificate-support-worksheet",
                        source_extents=(PhysicalExtent(0, source.byte_size),),
                        transformation=(
                            "verified case and source facts arranged as an unsigned legal "
                            "handoff worksheet; not a statutory certificate"
                        ),
                        media_type="application/pdf",
                    ),
                    ArtifactInput(
                        relative_path=hash_report_json.name,
                        role="source-sha256-hash-report",
                        source_extents=(PhysicalExtent(0, source.byte_size),),
                        transformation=(
                            "source evidence SHA-256 verification facts serialized as JSON"
                        ),
                        media_type="application/json",
                    ),
                    *detection_artifacts,
                ),
                custody=custody,
                private_key=key,
                signer_id=user.user_id,
                limitations=report_limitations,
                created_at=created,
                package_id=package_id,
            )
            for item in package_directory.iterdir():
                os.chmod(item, 0o400)
            os.chmod(package_directory, 0o500)
            _write_archive(
                archive_path,
                package_directory,
                (
                    "examination-report.pdf",
                    "examination-report.json",
                    "manifest.json",
                    "manifest.signature.json",
                    "section-63-4-support-worksheet.pdf",
                    "source-hash-report.json",
                    *detection_archive_names,
                ),
            )
            archive_sha256 = _hash_file(archive_path)
            record = ReportPackageRecord(
                package_id=package_id,
                case_id=case.case_id,
                exhibit_id=exhibit.exhibit_id,
                source_id=source.source_id,
                report_title=title,
                created_by=user.user_id,
                created_at=created,
                manifest_sha256=build_result.manifest_sha256,
                archive_sha256=archive_sha256,
                public_key_fingerprint=fingerprint,
                archive_path=archive_path,
            )
            self._insert(record, archive_name)
        except (
            EvidenceCatalogError,
            FaceDetectionStoreError,
            FaceTrackingStoreError,
            CertificateWorksheetRenderingError,
            KeyManagementError,
            OSError,
            PackageError,
            ReportRenderingError,
            ValueError,
        ) as exc:
            _clean_failed_export(package_directory, archive_path)
            raise ReportPackageError(str(exc)) from exc
        except BaseException:
            _clean_failed_export(package_directory, archive_path)
            raise
        return self.get(package_id)

    def list_for_case(self, case_id: str) -> tuple[ReportPackageRecord, ...]:
        self._cases.get_case(case_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM report_packages WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
        return tuple(self._from_row(row) for row in rows)

    def get(self, package_id: str) -> ReportPackageRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM report_packages WHERE package_id = ?",
                (package_id,),
            ).fetchone()
        if row is None:
            raise ReportPackageNotFoundError("Report package was not found")
        record = self._from_row(row)
        observed_sha256 = _hash_file(record.archive_path)
        if not hmac.compare_digest(observed_sha256, record.archive_sha256):
            raise ReportPackageError("Report package archive integrity verification failed")
        return record

    def _insert(self, record: ReportPackageRecord, archive_name: str) -> None:
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO report_packages(
                        package_id, case_id, exhibit_id, source_id, report_title,
                        created_by, created_at, manifest_sha256, archive_sha256,
                        public_key_fingerprint, archive_name
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.package_id,
                        record.case_id,
                        record.exhibit_id,
                        record.source_id,
                        record.report_title,
                        record.created_by,
                        _normalized_time(record.created_at),
                        record.manifest_sha256,
                        record.archive_sha256,
                        record.public_key_fingerprint,
                        archive_name,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ReportPackageError("Report package record could not be stored") from exc

    def _from_row(self, row: sqlite3.Row) -> ReportPackageRecord:
        archive_name = str(row["archive_name"])
        archive = self._packages / archive_name
        if archive.parent != self._packages or not archive.is_file() or archive.is_symlink():
            raise ReportPackageError("Report package archive is missing or unsafe")
        return ReportPackageRecord(
            package_id=str(row["package_id"]),
            case_id=str(row["case_id"]),
            exhibit_id=str(row["exhibit_id"]),
            source_id=str(row["source_id"]),
            report_title=str(row["report_title"]),
            created_by=str(row["created_by"]),
            created_at=_parsed_time(str(row["created_at"])),
            manifest_sha256=str(row["manifest_sha256"]),
            archive_sha256=str(row["archive_sha256"]),
            public_key_fingerprint=str(row["public_key_fingerprint"]),
            archive_path=archive,
        )

    def _load_or_create_signing_key(self, password: bytes) -> Ed25519PrivateKey:
        with self._lock:
            if self._signing_key_path.exists():
                return load_private_key(self._signing_key_path, password=password)
            key = generate_signing_key()
            save_private_key(key, self._signing_key_path, password=password)
            return key


def _export_custody(activity: tuple[Any, ...]) -> CustodyLedger:
    custody = CustodyLedger()
    for event in activity:
        evidence_hashes: dict[str, str] = {}
        for name in ("sha256", "expected_sha256", "observed_sha256"):
            value = event.details.get(name)
            if isinstance(value, str) and len(value) == 64:
                evidence_hashes[name] = value
        custody.append(
            case_id=event.case_id,
            actor_id=event.actor_id,
            actor_role="role-unavailable-in-source-activity",
            action=event.action,
            details={
                "source_activity_event_id": event.event_id,
                "source_activity_event_hash": event.event_hash,
                "recorded_details": dict(event.details),
            },
            evidence_hashes=evidence_hashes,
            occurred_at=event.occurred_at,
        )
    return custody


def _prepare_directory(candidate: Path) -> Path:
    if candidate.exists() and candidate.is_symlink():
        raise ReportPackageError("Report export directory cannot be a symbolic link")
    try:
        candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        if not resolved.is_dir():
            raise ReportPackageError("Report export location is not a directory")
        os.chmod(resolved, 0o700)
    except OSError as exc:
        raise ReportPackageError("Report export directory could not be prepared securely") from exc
    return resolved


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise ReportPackageError("Report database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise ReportPackageError("Report database directory does not exist") from exc
    return str(parent / candidate.name)


def _json_record(value: Any) -> dict[str, Any]:
    result = _json_value(value)
    if not isinstance(result, dict):
        raise TypeError("Report record did not serialize to an object")
    return cast(dict[str, Any], result)


def _json_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, datetime):
        return _normalized_time(value)
    if hasattr(value, "value"):
        return str(value.value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"Unsupported report value: {type(value).__name__}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return _normalized_time(value)
    if hasattr(value, "value"):
        return str(value.value)
    raise TypeError(f"Unsupported report value: {type(value).__name__}")


def _required_text(value: str, label: str, *, maximum: int) -> str:
    normalized = value.strip()
    if not normalized:
        raise ReportPackageError(f"{label} cannot be empty")
    if len(normalized) > maximum:
        raise ReportPackageError(f"{label} exceeds {maximum} characters")
    return normalized


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ReportPackageError("Report timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReportPackageError("Report artifact returned a short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def _write_archive(archive: Path, package: Path, names: tuple[str, ...]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(archive, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for name in names:
                    bundle.write(package / name, arcname=name)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        archive.unlink(missing_ok=True)
        raise


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_verified_preview(path: Path, *, expected_sha256: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ReportPackageError("Face-detection preview is missing or unsafe")
    size = path.stat().st_size
    if size <= 0 or size > MAX_ANALYSIS_PREVIEW_BYTES:
        raise ReportPackageError("Face-detection preview has an unsafe size")
    content = path.read_bytes()
    if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), expected_sha256):
        raise ReportPackageError("Face-detection preview integrity verification failed")
    return content


def _clean_failed_export(package_directory: Path, archive_path: Path) -> None:
    archive_path.unlink(missing_ok=True)
    if package_directory.exists():
        os.chmod(package_directory, 0o700)
        for child in package_directory.iterdir():
            if child.is_symlink():
                child.unlink()
            else:
                os.chmod(child, 0o600)
        shutil.rmtree(package_directory)
