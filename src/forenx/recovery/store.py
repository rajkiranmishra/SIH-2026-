from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import uuid4

from forenx.adapters import (
    AdapterProbeFailure,
    DvrFilesystemAdapter,
    MultiVendorProbeReport,
    PhysicalExtent,
    ProbeEvidence,
    ProbeResult,
    ReadableEvidence,
    RecordingDescriptor,
    RecordingState,
)


class RecoveryStoreError(RuntimeError):
    pass


class RecoveryScanNotFoundError(RecoveryStoreError):
    pass


class RecoveryArtifactNotFoundError(RecoveryStoreError):
    pass


class RecoveryArtifactExistsError(RecoveryStoreError):
    pass


@dataclass(frozen=True, slots=True)
class RecoveryArtifact:
    artifact_id: str
    scan_id: str
    case_id: str
    source_id: str
    recording_id: str
    filename: str
    byte_size: int
    sha256: str
    source_extents: tuple[PhysicalExtent, ...]
    warnings: tuple[str, ...]
    format_hint: str | None
    validation_evidence: tuple[str, ...]
    created_by: str
    created_at: datetime
    stored_path: Path
    examination_source_id: str | None


@dataclass(frozen=True, slots=True)
class RecoveryScan:
    scan_id: str
    case_id: str
    source_id: str
    source_sha256: str
    adapter_id: str
    adapter_version: str
    vendor: str
    filesystem: str
    confidence: float
    capabilities: tuple[str, ...]
    warnings: tuple[str, ...]
    probe_evidence: tuple[ProbeEvidence, ...]
    probe_results: tuple[ProbeResult, ...]
    probe_failures: tuple[AdapterProbeFailure, ...]
    recordings: tuple[RecordingDescriptor, ...]
    created_by: str
    created_at: datetime


class RecoveryStore:
    def __init__(self, database: str | Path, vault_directory: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._vault = _prepare_vault(Path(vault_directory))
        database_target = _database_target(database)
        self._connection = sqlite3.connect(
            database_target,
            check_same_thread=False,
            timeout=5,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if database_target != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS recovery_scans (
                    scan_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    source_sha256 TEXT NOT NULL,
                    adapter_id TEXT NOT NULL,
                    adapter_version TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    filesystem TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_recovery_scans_source
                    ON recovery_scans(source_id, created_at);

                CREATE TABLE IF NOT EXISTS recovery_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES recovery_scans(scan_id),
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    recording_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    byte_size INTEGER NOT NULL CHECK(byte_size > 0),
                    sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_by TEXT NOT NULL REFERENCES users(user_id),
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, recording_id)
                );

                CREATE INDEX IF NOT EXISTS idx_recovery_artifacts_scan
                    ON recovery_artifacts(scan_id, created_at);

                CREATE TRIGGER IF NOT EXISTS recovery_scans_scope_insert
                BEFORE INSERT ON recovery_scans
                BEGIN
                    SELECT CASE WHEN NOT EXISTS (
                        SELECT 1 FROM evidence_sources AS source
                        JOIN cases AS case_record ON case_record.case_id = source.case_id
                        JOIN users AS actor ON actor.user_id = NEW.created_by
                        WHERE source.source_id = NEW.source_id
                          AND source.case_id = NEW.case_id
                          AND source.media_kind = 'raw-disk-image'
                          AND case_record.status != 'closed'
                          AND actor.active = 1
                          AND (
                              actor.role = 'administrator'
                              OR EXISTS (
                                  SELECT 1 FROM case_assignments AS assignment
                                  WHERE assignment.case_id = NEW.case_id
                                    AND assignment.user_id = NEW.created_by
                                    AND assignment.revoked_at IS NULL
                              )
                          )
                    ) THEN RAISE(ABORT, 'Recovery scan is outside its active case scope') END;
                END;

                CREATE TRIGGER IF NOT EXISTS recovery_artifacts_scope_insert
                BEFORE INSERT ON recovery_artifacts
                BEGIN
                    SELECT CASE WHEN NOT EXISTS (
                        SELECT 1 FROM recovery_scans AS scan
                        JOIN cases AS case_record ON case_record.case_id = scan.case_id
                        JOIN users AS actor ON actor.user_id = NEW.created_by
                        WHERE scan.scan_id = NEW.scan_id
                          AND scan.case_id = NEW.case_id
                          AND scan.source_id = NEW.source_id
                          AND case_record.status != 'closed'
                          AND actor.active = 1
                          AND (
                              actor.role = 'administrator'
                              OR EXISTS (
                                  SELECT 1 FROM case_assignments AS assignment
                                  WHERE assignment.case_id = NEW.case_id
                                    AND assignment.user_id = NEW.created_by
                                    AND assignment.revoked_at IS NULL
                              )
                          )
                    ) THEN RAISE(ABORT, 'Recovery artifact is outside its active case scope') END;
                END;

                CREATE TRIGGER IF NOT EXISTS recovery_scans_no_update
                BEFORE UPDATE ON recovery_scans
                BEGIN
                    SELECT RAISE(ABORT, 'Recovery scans are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS recovery_scans_no_delete
                BEFORE DELETE ON recovery_scans
                BEGIN
                    SELECT RAISE(ABORT, 'Recovery scans are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS recovery_artifacts_no_update
                BEFORE UPDATE ON recovery_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'Recovery artifacts are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS recovery_artifacts_no_delete
                BEFORE DELETE ON recovery_artifacts
                BEGIN
                    SELECT RAISE(ABORT, 'Recovery artifacts are immutable');
                END;
                """
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> RecoveryStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def save_scan(
        self,
        *,
        case_id: str,
        source_id: str,
        source_sha256: str,
        adapter: DvrFilesystemAdapter,
        best_match: ProbeResult,
        probe_report: MultiVendorProbeReport,
        recordings: tuple[RecordingDescriptor, ...],
        created_by: str,
        occurred_at: datetime | None = None,
    ) -> RecoveryScan:
        if best_match.adapter_id != adapter.adapter_id:
            raise ValueError("Recovery adapter does not match the selected probe result")
        if len(source_sha256) != 64:
            raise ValueError("Recovery scan requires the verified source SHA-256")
        scan_id = str(uuid4())
        created_at = occurred_at or datetime.now(UTC)
        payload = {
            "capabilities": sorted(item.value for item in best_match.capabilities),
            "warnings": list(best_match.warnings),
            "probe_evidence": [_probe_evidence_payload(item) for item in best_match.evidence],
            "probe_results": [_probe_result_payload(item) for item in probe_report.results],
            "probe_failures": [
                {
                    "adapter_id": item.adapter_id,
                    "error_type": item.error_type,
                    "message": item.message,
                }
                for item in probe_report.failures
            ],
            "recordings": [_recording_payload(item) for item in recordings],
        }
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO recovery_scans(
                        scan_id, case_id, source_id, source_sha256, adapter_id,
                        adapter_version, vendor, filesystem, confidence, payload_json,
                        created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        case_id,
                        source_id,
                        source_sha256,
                        adapter.adapter_id,
                        adapter.version,
                        best_match.vendor,
                        best_match.filesystem,
                        best_match.confidence,
                        json.dumps(payload, sort_keys=True, separators=(",", ":")),
                        created_by,
                        _normalized_time(created_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RecoveryStoreError(str(exc)) from exc
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> RecoveryScan:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM recovery_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            raise RecoveryScanNotFoundError("Recovery scan was not found")
        return _scan_from_row(row)

    def list_for_source(self, source_id: str) -> tuple[RecoveryScan, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM recovery_scans
                WHERE source_id = ?
                ORDER BY created_at, scan_id
                """,
                (source_id,),
            ).fetchall()
        return tuple(_scan_from_row(row) for row in rows)

    def extract(
        self,
        *,
        scan: RecoveryScan,
        recording: RecordingDescriptor,
        source: ReadableEvidence,
        adapter: DvrFilesystemAdapter,
        created_by: str,
        occurred_at: datetime | None = None,
    ) -> RecoveryArtifact:
        if adapter.adapter_id != scan.adapter_id:
            raise ValueError("Recovery adapter does not match the stored scan")
        if recording not in scan.recordings:
            raise ValueError("Recording is not part of the stored recovery scan")
        with self._lock:
            existing = self._connection.execute(
                """
                SELECT 1 FROM recovery_artifacts
                WHERE scan_id = ? AND recording_id = ?
                """,
                (scan.scan_id, recording.recording_id),
            ).fetchone()
        if existing is not None:
            raise RecoveryArtifactExistsError(
                "This recording has already been extracted from the scan"
            )
        artifact_id = str(uuid4())
        stored_name = f"{artifact_id}.bin"
        target = self._vault / stored_name
        created_at = occurred_at or datetime.now(UTC)
        try:
            result = adapter.extract(source, recording, target)
            if result.output_path.resolve(strict=True) != target.resolve(strict=True):
                raise RecoveryStoreError("Adapter returned an unexpected extraction path")
            if result.bytes_written <= 0 or target.stat().st_size != result.bytes_written:
                raise RecoveryStoreError("Extracted artifact size does not match its record")
            observed_sha256 = _sha256_file(target)
            if not hmac.compare_digest(observed_sha256, result.sha256):
                raise RecoveryStoreError("Extracted artifact SHA-256 does not match its record")
            os.chmod(target, 0o400)
            extension = result.format_hint if result.format_hint in {"h264", "h265"} else "bin"
            filename = f"recovered-{artifact_id}.{extension}"
            payload = {
                "source_extents": [
                    {"offset": extent.offset, "length": extent.length}
                    for extent in result.source_extents
                ],
                "warnings": list(result.warnings),
                "format_hint": result.format_hint,
                "validation_evidence": list(result.validation_evidence),
            }
            with self._lock, self._connection:
                try:
                    self._connection.execute(
                        """
                        INSERT INTO recovery_artifacts(
                            artifact_id, scan_id, case_id, source_id, recording_id,
                            filename, stored_name, byte_size, sha256, payload_json,
                            created_by, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            artifact_id,
                            scan.scan_id,
                            scan.case_id,
                            scan.source_id,
                            recording.recording_id,
                            filename,
                            stored_name,
                            result.bytes_written,
                            result.sha256,
                            json.dumps(payload, sort_keys=True, separators=(",", ":")),
                            created_by,
                            _normalized_time(created_at),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    if "UNIQUE constraint failed" in str(exc):
                        raise RecoveryArtifactExistsError(
                            "This recording has already been extracted from the scan"
                        ) from exc
                    raise RecoveryStoreError(str(exc)) from exc
        except BaseException:
            if target.exists():
                os.chmod(target, 0o600)
                target.unlink()
            raise
        return self.get_artifact(artifact_id)

    def get_artifact(self, artifact_id: str) -> RecoveryArtifact:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT artifact.*, examination.source_id AS examination_source_id
                FROM recovery_artifacts AS artifact
                LEFT JOIN evidence_sources AS examination
                    ON examination.derived_artifact_id = artifact.artifact_id
                WHERE artifact.artifact_id = ?
                """,
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise RecoveryArtifactNotFoundError("Recovered artifact was not found")
        return self._artifact_from_row(row)

    def list_artifacts(self, scan_id: str) -> tuple[RecoveryArtifact, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT artifact.*, examination.source_id AS examination_source_id
                FROM recovery_artifacts AS artifact
                LEFT JOIN evidence_sources AS examination
                    ON examination.derived_artifact_id = artifact.artifact_id
                WHERE artifact.scan_id = ?
                ORDER BY artifact.created_at, artifact.artifact_id
                """,
                (scan_id,),
            ).fetchall()
        return tuple(self._artifact_from_row(row) for row in rows)

    def verify_artifact(self, artifact_id: str) -> tuple[RecoveryArtifact, bool, str]:
        artifact = self.get_artifact(artifact_id)
        try:
            observed = _sha256_file(artifact.stored_path)
        except OSError as exc:
            raise RecoveryStoreError("Recovered artifact cannot be read") from exc
        return artifact, hmac.compare_digest(observed, artifact.sha256), observed

    def _artifact_from_row(self, row: sqlite3.Row) -> RecoveryArtifact:
        payload = json.loads(str(row["payload_json"]))
        stored_path = self._vault / str(row["stored_name"])
        if stored_path.is_symlink() or not stored_path.is_file():
            raise RecoveryStoreError("Recovered artifact file is unavailable")
        try:
            stored_path.resolve(strict=True).relative_to(self._vault)
        except (OSError, ValueError) as exc:
            raise RecoveryStoreError("Recovered artifact path is outside its vault") from exc
        return RecoveryArtifact(
            artifact_id=str(row["artifact_id"]),
            scan_id=str(row["scan_id"]),
            case_id=str(row["case_id"]),
            source_id=str(row["source_id"]),
            recording_id=str(row["recording_id"]),
            filename=str(row["filename"]),
            byte_size=int(row["byte_size"]),
            sha256=str(row["sha256"]),
            source_extents=tuple(
                PhysicalExtent(offset=int(item["offset"]), length=int(item["length"]))
                for item in payload["source_extents"]
            ),
            warnings=tuple(str(item) for item in payload["warnings"]),
            format_hint=(
                str(payload["format_hint"]) if payload["format_hint"] is not None else None
            ),
            validation_evidence=tuple(
                str(item) for item in payload["validation_evidence"]
            ),
            created_by=str(row["created_by"]),
            created_at=_parsed_time(str(row["created_at"])),
            stored_path=stored_path,
            examination_source_id=(
                str(row["examination_source_id"])
                if row["examination_source_id"] is not None
                else None
            ),
        )


def _scan_from_row(row: sqlite3.Row) -> RecoveryScan:
    payload = json.loads(str(row["payload_json"]))
    return RecoveryScan(
        scan_id=str(row["scan_id"]),
        case_id=str(row["case_id"]),
        source_id=str(row["source_id"]),
        source_sha256=str(row["source_sha256"]),
        adapter_id=str(row["adapter_id"]),
        adapter_version=str(row["adapter_version"]),
        vendor=str(row["vendor"]),
        filesystem=str(row["filesystem"]),
        confidence=float(row["confidence"]),
        capabilities=tuple(str(item) for item in payload["capabilities"]),
        warnings=tuple(str(item) for item in payload["warnings"]),
        probe_evidence=tuple(
            ProbeEvidence(
                description=str(item["description"]),
                offset=int(item["offset"]),
                observed_hex=str(item["observed_hex"]),
            )
            for item in payload["probe_evidence"]
        ),
        probe_results=tuple(_probe_result_from_payload(item) for item in payload["probe_results"]),
        probe_failures=tuple(
            AdapterProbeFailure(
                adapter_id=str(item["adapter_id"]),
                error_type=str(item["error_type"]),
                message=str(item["message"]),
            )
            for item in payload["probe_failures"]
        ),
        recordings=tuple(_recording_from_payload(item) for item in payload["recordings"]),
        created_by=str(row["created_by"]),
        created_at=_parsed_time(str(row["created_at"])),
    )


def _probe_evidence_payload(item: ProbeEvidence) -> dict[str, object]:
    return {
        "description": item.description,
        "offset": item.offset,
        "observed_hex": item.observed_hex,
    }


def _probe_result_payload(item: ProbeResult) -> dict[str, object]:
    return {
        "adapter_id": item.adapter_id,
        "vendor": item.vendor,
        "filesystem": item.filesystem,
        "confidence": item.confidence,
        "evidence": [_probe_evidence_payload(evidence) for evidence in item.evidence],
        "capabilities": sorted(capability.value for capability in item.capabilities),
        "warnings": list(item.warnings),
    }


def _probe_result_from_payload(item: dict[str, Any]) -> ProbeResult:
    from forenx.adapters import AdapterCapability

    return ProbeResult(
        adapter_id=str(item["adapter_id"]),
        vendor=str(item["vendor"]),
        filesystem=str(item["filesystem"]),
        confidence=float(item["confidence"]),
        evidence=tuple(
            ProbeEvidence(
                description=str(evidence["description"]),
                offset=int(evidence["offset"]),
                observed_hex=str(evidence["observed_hex"]),
            )
            for evidence in item["evidence"]
        ),
        capabilities=frozenset(
            AdapterCapability(str(capability))
            for capability in item["capabilities"]
        ),
        warnings=tuple(str(warning) for warning in item["warnings"]),
    )


def _recording_payload(item: RecordingDescriptor) -> dict[str, object]:
    return {
        "recording_id": item.recording_id,
        "channel": item.channel,
        "start_time": _normalized_time(item.start_time) if item.start_time else None,
        "end_time": _normalized_time(item.end_time) if item.end_time else None,
        "timestamp_source": item.timestamp_source,
        "state": item.state.value,
        "extents": [
            {"offset": extent.offset, "length": extent.length} for extent in item.extents
        ],
        "codec_hint": item.codec_hint,
        "confidence": item.confidence,
        "warnings": list(item.warnings),
    }


def _recording_from_payload(item: dict[str, Any]) -> RecordingDescriptor:
    start_time = item["start_time"]
    end_time = item["end_time"]
    return RecordingDescriptor(
        recording_id=str(item["recording_id"]),
        channel=str(item["channel"]) if item["channel"] is not None else None,
        start_time=_parsed_time(str(start_time)) if start_time is not None else None,
        end_time=_parsed_time(str(end_time)) if end_time is not None else None,
        timestamp_source=(
            str(item["timestamp_source"]) if item["timestamp_source"] is not None else None
        ),
        state=RecordingState(str(item["state"])),
        extents=tuple(
            PhysicalExtent(offset=int(extent["offset"]), length=int(extent["length"]))
            for extent in item["extents"]
        ),
        codec_hint=str(item["codec_hint"]) if item["codec_hint"] is not None else None,
        confidence=float(item["confidence"]),
        warnings=tuple(str(warning) for warning in item["warnings"]),
    )


def _prepare_vault(candidate: Path) -> Path:
    expanded = candidate.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise RecoveryStoreError("Recovery vault cannot be a symbolic link")
    try:
        expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = expanded.resolve(strict=True)
        if not resolved.is_dir():
            raise RecoveryStoreError("Recovery vault is not a directory")
        os.chmod(resolved, 0o700)
    except OSError as exc:
        raise RecoveryStoreError("Recovery vault could not be created securely") from exc
    return resolved


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise RecoveryStoreError("Recovery database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise RecoveryStoreError("Recovery database directory does not exist") from exc
    if not parent.is_dir():
        raise RecoveryStoreError("Recovery database parent is not a directory")
    return str(parent / candidate.name)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Recovery timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
