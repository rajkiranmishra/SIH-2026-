from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from forenx import __version__
from forenx.adapters.base import PhysicalExtent
from forenx.custody.ledger import GENESIS_HASH, CustodyLedger

SCHEMA_VERSION = "forenx-evidence-package/v1"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.signature.json"
MAX_CONTROL_FILE_SIZE = 16 * 1024 * 1024
MAX_ARTIFACTS = 10_000
MAX_CUSTODY_EVENTS = 100_000


class PackageError(RuntimeError):
    """Raised when an evidence package cannot be created safely."""


@dataclass(frozen=True, slots=True)
class SourceEvidenceRecord:
    source_id: str
    original_filename: str
    size: int
    hashes: Mapping[str, str]
    acquisition_method: str
    read_only: bool

    def __post_init__(self) -> None:
        if not self.source_id.strip() or not self.original_filename.strip():
            raise ValueError("Source evidence identifiers cannot be empty")
        if self.size < 0:
            raise ValueError("Source evidence size cannot be negative")
        _validate_hashes(self.hashes)
        if not self.acquisition_method.strip():
            raise ValueError("Source evidence acquisition method cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "original_filename": self.original_filename,
            "size": self.size,
            "hashes": dict(self.hashes),
            "acquisition_method": self.acquisition_method,
            "read_only": self.read_only,
        }


@dataclass(frozen=True, slots=True)
class ArtifactInput:
    relative_path: str
    role: str
    source_extents: tuple[PhysicalExtent, ...]
    transformation: str
    media_type: str | None = None

    def __post_init__(self) -> None:
        _validate_relative_path(self.relative_path)
        if not self.role.strip() or not self.transformation.strip():
            raise ValueError("Artifact role and transformation cannot be empty")
        if not self.source_extents:
            raise ValueError("Artifact requires source-byte provenance")


@dataclass(frozen=True, slots=True)
class PackageBuildResult:
    package_id: str
    manifest_path: Path
    signature_path: Path
    manifest_sha256: str
    public_key_fingerprint: str
    artifact_count: int


@dataclass(frozen=True, slots=True)
class VerificationIssue:
    code: str
    message: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class PackageVerification:
    valid: bool
    signature_valid: bool
    signer_trusted: bool
    public_key_fingerprint: str | None
    checked_artifacts: int
    checked_custody_events: int
    issues: tuple[VerificationIssue, ...]
    warnings: tuple[str, ...]


def build_evidence_package(
    package_root: str | Path,
    *,
    case_id: str,
    exhibit_id: str,
    source: SourceEvidenceRecord,
    artifacts: Iterable[ArtifactInput],
    custody: CustodyLedger,
    private_key: Ed25519PrivateKey,
    signer_id: str,
    limitations: Iterable[str] = (),
    created_at: datetime | None = None,
    package_id: str | None = None,
) -> PackageBuildResult:
    required = {
        "case_id": case_id,
        "exhibit_id": exhibit_id,
        "signer_id": signer_id,
    }
    empty = [name for name, value in required.items() if not value.strip()]
    if empty:
        raise PackageError(f"Evidence-package fields cannot be empty: {', '.join(empty)}")

    root = _resolve_package_root(package_root)
    manifest_path = root / MANIFEST_NAME
    signature_path = root / SIGNATURE_NAME
    if manifest_path.exists() or signature_path.exists():
        raise PackageError("Package control files already exist and will not be overwritten")

    custody_verification = custody.verify()
    if not custody_verification.valid:
        raise PackageError(f"Custody ledger is invalid: {custody_verification.message}")
    if any(event.case_id != case_id for event in custody.events):
        raise PackageError("Custody event case identifiers do not match the package case")

    artifact_inputs = tuple(artifacts)
    if len(artifact_inputs) > MAX_ARTIFACTS:
        raise PackageError(f"Artifact count exceeds the safety limit of {MAX_ARTIFACTS}")
    artifact_records = [
        _inventory_artifact(root, artifact_input) for artifact_input in artifact_inputs
    ]
    limitation_values = tuple(limitations)
    if any(not limitation.strip() for limitation in limitation_values):
        raise PackageError("Package limitations cannot contain empty values")

    created = _normalized_time(created_at or datetime.now(UTC))
    resolved_package_id = package_id or str(uuid4())
    custody_head = custody.events[-1].event_hash if custody.events else GENESIS_HASH
    manifest = {
        "schema": SCHEMA_VERSION,
        "package_id": resolved_package_id,
        "created_at": created,
        "case_id": case_id,
        "exhibit_id": exhibit_id,
        "tool": {"name": "ForenX", "version": __version__},
        "source_evidence": source.to_dict(),
        "artifacts": artifact_records,
        "custody_events": [event.to_dict() for event in custody.events],
        "custody_head_hash": custody_head,
        "limitations": list(limitation_values),
    }
    manifest_bytes = _canonical_json(manifest)
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    public_bytes = private_key.public_key().public_bytes_raw()
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    signature = private_key.sign(manifest_bytes)
    envelope = {
        "algorithm": "Ed25519",
        "manifest_sha256": manifest_digest,
        "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
        "public_key_fingerprint_sha256": fingerprint,
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "signed_at": created,
        "signer_id": signer_id,
    }

    _write_exclusive(manifest_path, manifest_bytes)
    try:
        _write_exclusive(signature_path, _canonical_json(envelope))
    except BaseException:
        manifest_path.unlink(missing_ok=True)
        raise

    return PackageBuildResult(
        package_id=resolved_package_id,
        manifest_path=manifest_path,
        signature_path=signature_path,
        manifest_sha256=manifest_digest,
        public_key_fingerprint=fingerprint,
        artifact_count=len(artifact_records),
    )


def verify_evidence_package(
    package_root: str | Path,
    *,
    trusted_public_key_fingerprint: str | None = None,
) -> PackageVerification:
    issues: list[VerificationIssue] = []
    warnings: list[str] = []
    checked_artifacts = 0
    checked_events = 0
    signature_valid = False
    signer_trusted = False
    fingerprint: str | None = None

    try:
        root = _resolve_package_root(package_root)
        manifest_bytes = _read_control_file(root / MANIFEST_NAME)
        envelope_bytes = _read_control_file(root / SIGNATURE_NAME)
    except PackageError as exc:
        return PackageVerification(
            valid=False,
            signature_valid=False,
            signer_trusted=False,
            public_key_fingerprint=None,
            checked_artifacts=0,
            checked_custody_events=0,
            issues=(VerificationIssue("CONTROL_FILE_ERROR", str(exc)),),
            warnings=(),
        )

    manifest = _decode_json_object(manifest_bytes, MANIFEST_NAME, issues)
    envelope = _decode_json_object(envelope_bytes, SIGNATURE_NAME, issues)
    if envelope is not None:
        signature_valid, fingerprint = _verify_signature(manifest_bytes, envelope, issues)

    if trusted_public_key_fingerprint is None:
        warnings.append(
            "No trusted public-key fingerprint was supplied; signer identity is not established"
        )
    elif fingerprint is None or not hmac.compare_digest(
        trusted_public_key_fingerprint.strip().lower(), fingerprint
    ):
        issues.append(
            VerificationIssue(
                "SIGNER_TRUST_MISMATCH",
                "Embedded signing key does not match the supplied trust fingerprint",
            )
        )
    else:
        signer_trusted = signature_valid

    if manifest is not None:
        _verify_manifest_schema(manifest, issues)
        checked_artifacts = _verify_artifacts(root, manifest, issues)
        checked_events = _verify_custody(manifest, issues)

    return PackageVerification(
        valid=signature_valid and not issues,
        signature_valid=signature_valid,
        signer_trusted=signer_trusted,
        public_key_fingerprint=fingerprint,
        checked_artifacts=checked_artifacts,
        checked_custody_events=checked_events,
        issues=tuple(issues),
        warnings=tuple(warnings),
    )


def _inventory_artifact(root: Path, artifact: ArtifactInput) -> dict[str, Any]:
    target = _contained_artifact_path(root, artifact.relative_path)
    if target.is_symlink():
        raise PackageError(f"Artifact cannot be a symbolic link: {artifact.relative_path}")
    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        raise PackageError(f"Artifact does not exist: {artifact.relative_path}") from exc
    if not resolved.is_file():
        raise PackageError(f"Artifact is not a regular file: {artifact.relative_path}")
    if not _is_within(root, resolved):
        raise PackageError(f"Artifact resolves outside the package: {artifact.relative_path}")

    size, digest = _hash_file(resolved)
    return {
        "path": artifact.relative_path,
        "role": artifact.role,
        "size": size,
        "sha256": digest,
        "source_extents": [
            {"offset": extent.offset, "length": extent.length}
            for extent in artifact.source_extents
        ],
        "transformation": artifact.transformation,
        "media_type": artifact.media_type,
    }


def _verify_signature(
    manifest_bytes: bytes,
    envelope: dict[str, Any],
    issues: list[VerificationIssue],
) -> tuple[bool, str | None]:
    try:
        if envelope["algorithm"] != "Ed25519":
            raise ValueError("Unsupported signature algorithm")
        expected_manifest_digest = _required_string(envelope, "manifest_sha256")
        public_bytes = base64.b64decode(
            _required_string(envelope, "public_key_base64"), validate=True
        )
        signature = base64.b64decode(
            _required_string(envelope, "signature_base64"), validate=True
        )
        declared_fingerprint = _required_string(
            envelope, "public_key_fingerprint_sha256"
        ).lower()
        actual_manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        actual_fingerprint = hashlib.sha256(public_bytes).hexdigest()
        if not hmac.compare_digest(expected_manifest_digest.lower(), actual_manifest_digest):
            raise ValueError("Manifest SHA-256 does not match the signature envelope")
        if not hmac.compare_digest(declared_fingerprint, actual_fingerprint):
            raise ValueError("Public-key fingerprint does not match the embedded key")
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, manifest_bytes)
    except (KeyError, TypeError, ValueError, binascii.Error, InvalidSignature) as exc:
        issues.append(VerificationIssue("SIGNATURE_INVALID", str(exc)))
        return False, None
    return True, actual_fingerprint


def _verify_manifest_schema(
    manifest: dict[str, Any],
    issues: list[VerificationIssue],
) -> None:
    if manifest.get("schema") != SCHEMA_VERSION:
        issues.append(VerificationIssue("SCHEMA_UNSUPPORTED", "Unsupported manifest schema"))
    for field in ("package_id", "created_at", "case_id", "exhibit_id"):
        value = manifest.get(field)
        if not isinstance(value, str) or not value.strip():
            issues.append(
                VerificationIssue("MANIFEST_FIELD_INVALID", f"Manifest field is invalid: {field}")
            )


def _verify_artifacts(
    root: Path,
    manifest: dict[str, Any],
    issues: list[VerificationIssue],
) -> int:
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list):
        issues.append(VerificationIssue("ARTIFACT_LIST_INVALID", "Artifact list is missing"))
        return 0
    if len(raw_artifacts) > MAX_ARTIFACTS:
        issues.append(VerificationIssue("ARTIFACT_LIMIT", "Artifact count exceeds safety limit"))
        return 0

    checked = 0
    for raw_artifact in raw_artifacts:
        if not isinstance(raw_artifact, dict):
            issues.append(VerificationIssue("ARTIFACT_INVALID", "Artifact record is not an object"))
            continue
        relative_path = raw_artifact.get("path")
        expected_size = raw_artifact.get("size")
        expected_digest = raw_artifact.get("sha256")
        if (
            not isinstance(relative_path, str)
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or not _is_sha256(expected_digest)
        ):
            issues.append(VerificationIssue("ARTIFACT_INVALID", "Artifact fields are invalid"))
            continue
        try:
            target = _contained_artifact_path(root, relative_path)
            if target.is_symlink():
                raise PackageError("Artifact is a symbolic link")
            resolved = target.resolve(strict=True)
            if not resolved.is_file() or not _is_within(root, resolved):
                raise PackageError("Artifact is missing, non-regular, or outside the package")
            actual_size, actual_digest = _hash_file(resolved)
        except (OSError, PackageError, ValueError) as exc:
            issues.append(VerificationIssue("ARTIFACT_UNREADABLE", str(exc), relative_path))
            continue

        checked += 1
        if actual_size != expected_size:
            issues.append(
                VerificationIssue(
                    "ARTIFACT_SIZE_MISMATCH",
                    f"Expected {expected_size} bytes, observed {actual_size}",
                    relative_path,
                )
            )
        if not hmac.compare_digest(str(expected_digest).lower(), actual_digest):
            issues.append(
                VerificationIssue(
                    "ARTIFACT_HASH_MISMATCH",
                    "Artifact SHA-256 does not match the manifest",
                    relative_path,
                )
            )
    return checked


def _verify_custody(
    manifest: dict[str, Any],
    issues: list[VerificationIssue],
) -> int:
    raw_events = manifest.get("custody_events")
    if not isinstance(raw_events, list):
        issues.append(VerificationIssue("CUSTODY_LIST_INVALID", "Custody event list is missing"))
        return 0
    if len(raw_events) > MAX_CUSTODY_EVENTS:
        issues.append(
            VerificationIssue("CUSTODY_LIMIT", "Custody event count exceeds safety limit")
        )
        return 0

    previous_hash = GENESIS_HASH
    case_id = manifest.get("case_id")
    checked = 0
    payload_fields = (
        "event_id",
        "sequence",
        "case_id",
        "actor_id",
        "actor_role",
        "action",
        "occurred_at",
        "details",
        "evidence_hashes",
        "previous_hash",
    )
    for expected_sequence, raw_event in enumerate(raw_events, start=1):
        if not isinstance(raw_event, dict):
            issues.append(
                VerificationIssue(
                    "CUSTODY_EVENT_INVALID",
                    "Custody event is not an object",
                )
            )
            break
        if raw_event.get("sequence") != expected_sequence:
            issues.append(
                VerificationIssue("CUSTODY_SEQUENCE", "Custody sequence is not contiguous")
            )
            break
        if raw_event.get("case_id") != case_id:
            issues.append(
                VerificationIssue("CUSTODY_CASE_MISMATCH", "Custody event case does not match")
            )
            break
        if raw_event.get("previous_hash") != previous_hash:
            issues.append(
                VerificationIssue("CUSTODY_PREVIOUS_HASH", "Custody previous hash does not match")
            )
            break
        event_hash = raw_event.get("event_hash")
        if not _is_sha256(event_hash):
            issues.append(VerificationIssue("CUSTODY_HASH_INVALID", "Custody hash is invalid"))
            break
        if any(field not in raw_event for field in payload_fields):
            issues.append(
                VerificationIssue("CUSTODY_EVENT_INVALID", "Custody event fields are incomplete")
            )
            break
        payload = {field: raw_event[field] for field in payload_fields}
        calculated = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if not hmac.compare_digest(str(event_hash).lower(), calculated):
            issues.append(
                VerificationIssue("CUSTODY_HASH_MISMATCH", "Custody event hash does not match")
            )
            break
        previous_hash = str(event_hash)
        checked += 1

    if manifest.get("custody_head_hash") != previous_hash:
        issues.append(
            VerificationIssue("CUSTODY_HEAD_MISMATCH", "Custody head hash does not match")
        )
    return checked


def _resolve_package_root(package_root: str | Path) -> Path:
    try:
        root = Path(package_root).expanduser().resolve(strict=True)
    except OSError as exc:
        raise PackageError("Evidence package directory does not exist") from exc
    if not root.is_dir():
        raise PackageError("Evidence package root must be a directory")
    return root


def _contained_artifact_path(root: Path, relative_path: str) -> Path:
    parts = _validate_relative_path(relative_path)
    return root.joinpath(*parts)


def _validate_relative_path(relative_path: str) -> tuple[str, ...]:
    if not relative_path or "\\" in relative_path:
        raise ValueError("Artifact path must be a non-empty POSIX relative path")
    candidate = PurePosixPath(relative_path)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError("Artifact path must remain inside the evidence package")
    if candidate.name in (MANIFEST_NAME, SIGNATURE_NAME):
        raise ValueError("Artifact path conflicts with a package control file")
    return candidate.parts


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _hash_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def _read_control_file(path: Path) -> bytes:
    if path.is_symlink():
        raise PackageError(f"Package control file cannot be a symbolic link: {path.name}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PackageError(f"Package control file is missing: {path.name}") from exc
    if size > MAX_CONTROL_FILE_SIZE:
        raise PackageError(f"Package control file exceeds safety limit: {path.name}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PackageError(f"Package control file cannot be read: {path.name}") from exc


def _decode_json_object(
    data: bytes,
    name: str,
    issues: list[VerificationIssue],
) -> dict[str, Any] | None:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        issues.append(VerificationIssue("JSON_INVALID", f"Invalid {name}: {exc}"))
        return None
    if not isinstance(value, dict):
        issues.append(VerificationIssue("JSON_INVALID", f"{name} must contain an object"))
        return None
    return value


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise PackageError(f"Package control file already exists: {path.name}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PackageError("Package control file returned a short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PackageError("Evidence-package timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate_hashes(hashes: Mapping[str, str]) -> None:
    if not hashes:
        raise ValueError("Source evidence requires at least one hash")
    for algorithm, digest in hashes.items():
        if not algorithm.strip() or not digest.strip():
            raise ValueError("Source evidence hash names and values cannot be empty")
        if algorithm.lower() == "sha256" and not _is_sha256(digest):
            raise ValueError("Source evidence SHA-256 is invalid")


def _required_string(value: dict[str, Any], field: str) -> str:
    observed = value[field]
    if not isinstance(observed, str) or not observed:
        raise ValueError(f"Signature field is invalid: {field}")
    return observed


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdefABCDEF" for character in value
    )
