from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
from collections.abc import AsyncIterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any
from urllib.parse import unquote
from uuid import uuid4


class EvidenceCatalogError(RuntimeError):
    pass


class EvidenceNotFoundError(EvidenceCatalogError):
    pass


class EvidenceMediaKind(StrEnum):
    RAW_DISK_IMAGE = "raw-disk-image"
    VIDEO_FILE = "video-file"


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    source_id: str
    case_id: str
    exhibit_id: str
    original_filename: str
    media_kind: EvidenceMediaKind
    byte_size: int
    sha256: str
    created_by: str
    created_at: datetime
    stored_path: Path
    parent_source_id: str | None = None
    derived_artifact_id: str | None = None
    derivation: dict[str, Any] | None = None


class EvidenceCatalog:
    DEFAULT_MAX_INGEST_BYTES = 16 * 1024**4

    def __init__(
        self,
        database: str | Path,
        vault_directory: str | Path,
        *,
        max_ingest_bytes: int = DEFAULT_MAX_INGEST_BYTES,
    ) -> None:
        if (
            isinstance(max_ingest_bytes, bool)
            or not isinstance(max_ingest_bytes, int)
            or max_ingest_bytes <= 0
        ):
            raise ValueError("Maximum ingest size must be a positive integer")
        self._max_ingest_bytes = max_ingest_bytes
        self._lock = threading.RLock()
        self._closed = False
        self._vault = self._prepare_vault(Path(vault_directory))

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
                CREATE TABLE IF NOT EXISTS evidence_sources (
                    source_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    exhibit_id TEXT NOT NULL REFERENCES exhibits(exhibit_id),
                    original_filename TEXT NOT NULL,
                    stored_name TEXT NOT NULL UNIQUE,
                    media_kind TEXT NOT NULL,
                    byte_size INTEGER NOT NULL CHECK(byte_size > 0),
                    sha256 TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    parent_source_id TEXT REFERENCES evidence_sources(source_id),
                    derived_artifact_id TEXT,
                    derivation_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_evidence_case
                    ON evidence_sources(case_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_evidence_exhibit
                    ON evidence_sources(exhibit_id, created_at);
                """
            )
            columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(evidence_sources)"
                ).fetchall()
            }
            for name, definition in (
                ("parent_source_id", "TEXT REFERENCES evidence_sources(source_id)"),
                ("derived_artifact_id", "TEXT"),
                ("derivation_json", "TEXT"),
            ):
                if name not in columns:
                    self._connection.execute(
                        f"ALTER TABLE evidence_sources ADD COLUMN {name} {definition}"
                    )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_derived_artifact
                ON evidence_sources(derived_artifact_id)
                WHERE derived_artifact_id IS NOT NULL
                """
            )

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def __enter__(self) -> EvidenceCatalog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    async def ingest(
        self,
        chunks: AsyncIterable[bytes],
        *,
        case_id: str,
        exhibit_id: str,
        original_filename: str,
        media_kind: EvidenceMediaKind,
        created_by: str,
        declared_size: int | None = None,
        occurred_at: datetime | None = None,
    ) -> EvidenceRecord:
        display_filename, suffix = _safe_filename(original_filename)
        _require_identifier(case_id, "Case identifier")
        _require_identifier(exhibit_id, "Exhibit identifier")
        _require_identifier(created_by, "Creator identifier")
        if declared_size is not None:
            if declared_size <= 0:
                raise EvidenceCatalogError("Evidence content length must be positive")
            if declared_size > self._max_ingest_bytes:
                raise EvidenceCatalogError("Evidence exceeds the configured ingest limit")

        source_id = str(uuid4())
        stored_name = f"{source_id}{suffix}"
        target = self._vault / stored_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(target, flags, 0o600)
        except OSError as exc:
            raise EvidenceCatalogError("Evidence vault destination could not be created") from exc

        digest = hashlib.sha256()
        byte_size = 0
        try:
            async for chunk in chunks:
                if not isinstance(chunk, bytes):
                    raise EvidenceCatalogError("Evidence stream returned a non-byte chunk")
                if not chunk:
                    continue
                byte_size += len(chunk)
                if byte_size > self._max_ingest_bytes:
                    raise EvidenceCatalogError("Evidence exceeds the configured ingest limit")
                _write_all(descriptor, chunk)
                digest.update(chunk)
            if byte_size == 0:
                raise EvidenceCatalogError("Evidence stream is empty")
            if declared_size is not None and byte_size != declared_size:
                raise EvidenceCatalogError("Evidence content length did not match received bytes")
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            target.unlink(missing_ok=True)
            raise
        else:
            os.close(descriptor)

        os.chmod(target, 0o400)
        created_at = occurred_at or datetime.now(UTC)
        created = _normalized_time(created_at)
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO evidence_sources(
                        source_id, case_id, exhibit_id, original_filename, stored_name,
                        media_kind, byte_size, sha256, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id,
                        case_id,
                        exhibit_id,
                        display_filename,
                        stored_name,
                        media_kind.value,
                        byte_size,
                        digest.hexdigest(),
                        created_by,
                        created,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            os.chmod(target, 0o600)
            target.unlink(missing_ok=True)
            raise EvidenceCatalogError("Evidence could not be linked to the case exhibit") from exc
        return self.get(source_id)

    def register_derived_file(
        self,
        source_path: str | Path,
        *,
        case_id: str,
        exhibit_id: str,
        parent_source_id: str,
        derived_artifact_id: str,
        original_filename: str,
        media_kind: EvidenceMediaKind,
        expected_sha256: str,
        derivation: dict[str, Any],
        created_by: str,
        occurred_at: datetime | None = None,
    ) -> EvidenceRecord:
        display_filename, suffix = _safe_filename(original_filename)
        for value, label in (
            (case_id, "Case identifier"),
            (exhibit_id, "Exhibit identifier"),
            (parent_source_id, "Parent source identifier"),
            (derived_artifact_id, "Derived artifact identifier"),
            (created_by, "Creator identifier"),
        ):
            _require_identifier(value, label)
        if not _valid_sha256(expected_sha256):
            raise EvidenceCatalogError("Derived evidence requires a valid expected SHA-256")
        parent = self.get(parent_source_id)
        if parent.case_id != case_id or parent.exhibit_id != exhibit_id:
            raise EvidenceCatalogError("Derived evidence must remain with its parent exhibit")
        candidate = Path(source_path)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            source_descriptor = os.open(candidate, flags)
        except OSError as exc:
            raise EvidenceCatalogError(
                "Derived evidence source could not be opened safely"
            ) from exc
        try:
            source_stat = os.fstat(source_descriptor)
            if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size <= 0:
                raise EvidenceCatalogError("Derived evidence source must be a non-empty file")
            if source_stat.st_size > self._max_ingest_bytes:
                raise EvidenceCatalogError("Derived evidence exceeds the configured ingest limit")
        except BaseException:
            os.close(source_descriptor)
            raise

        source_id = str(uuid4())
        stored_name = f"{source_id}{suffix}"
        target = self._vault / stored_name
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            target_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            target_flags |= os.O_NOFOLLOW
        try:
            target_descriptor = os.open(target, target_flags, 0o600)
        except OSError as exc:
            os.close(source_descriptor)
            raise EvidenceCatalogError("Derived evidence destination could not be created") from exc

        digest = hashlib.sha256()
        byte_size = 0
        try:
            while chunk := os.read(source_descriptor, 8 * 1024 * 1024):
                byte_size += len(chunk)
                _write_all(target_descriptor, chunk)
                digest.update(chunk)
            os.fsync(target_descriptor)
        except BaseException:
            os.close(source_descriptor)
            os.close(target_descriptor)
            target.unlink(missing_ok=True)
            raise
        else:
            os.close(source_descriptor)
            os.close(target_descriptor)
        observed_sha256 = digest.hexdigest()
        if not hmac.compare_digest(observed_sha256, expected_sha256):
            target.unlink(missing_ok=True)
            raise EvidenceCatalogError("Derived evidence SHA-256 does not match its source record")

        os.chmod(target, 0o400)
        created_at = occurred_at or datetime.now(UTC)
        try:
            derivation_json = json.dumps(derivation, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            os.chmod(target, 0o600)
            target.unlink(missing_ok=True)
            raise EvidenceCatalogError("Derived evidence provenance is not serializable") from exc
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO evidence_sources(
                        source_id, case_id, exhibit_id, original_filename, stored_name,
                        media_kind, byte_size, sha256, created_by, created_at,
                        parent_source_id, derived_artifact_id, derivation_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_id,
                        case_id,
                        exhibit_id,
                        display_filename,
                        stored_name,
                        media_kind.value,
                        byte_size,
                        observed_sha256,
                        created_by,
                        _normalized_time(created_at),
                        parent_source_id,
                        derived_artifact_id,
                        derivation_json,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            os.chmod(target, 0o600)
            target.unlink(missing_ok=True)
            if "derived_artifact_id" in str(exc):
                raise EvidenceCatalogError(
                    "Recovered artifact is already registered for examination"
                ) from exc
            raise EvidenceCatalogError(
                "Derived evidence could not be linked to the case exhibit"
            ) from exc
        return self.get(source_id)

    def get(self, source_id: str) -> EvidenceRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM evidence_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            raise EvidenceNotFoundError("Evidence source was not found")
        return self._record_from_row(row)

    def list_for_case(self, case_id: str) -> tuple[EvidenceRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM evidence_sources
                WHERE case_id = ? ORDER BY created_at, source_id
                """,
                (case_id,),
            ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    def verify(self, source_id: str) -> tuple[bool, str]:
        record = self.get(source_id)
        digest = hashlib.sha256()
        try:
            with record.stored_path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise EvidenceCatalogError(
                "Evidence source could not be read for verification"
            ) from exc
        observed = digest.hexdigest()
        return hmac.compare_digest(observed, record.sha256), observed

    def _record_from_row(self, row: sqlite3.Row) -> EvidenceRecord:
        stored_name = str(row["stored_name"])
        if Path(stored_name).name != stored_name:
            raise EvidenceCatalogError("Stored evidence name is invalid")
        stored_path = self._vault / stored_name
        if not stored_path.is_file() or stored_path.is_symlink():
            raise EvidenceCatalogError("Stored evidence file is missing or unsafe")
        return EvidenceRecord(
            source_id=str(row["source_id"]),
            case_id=str(row["case_id"]),
            exhibit_id=str(row["exhibit_id"]),
            original_filename=str(row["original_filename"]),
            media_kind=EvidenceMediaKind(row["media_kind"]),
            byte_size=int(row["byte_size"]),
            sha256=str(row["sha256"]),
            created_by=str(row["created_by"]),
            created_at=_parsed_time(str(row["created_at"])),
            stored_path=stored_path,
            parent_source_id=(
                str(row["parent_source_id"])
                if row["parent_source_id"] is not None
                else None
            ),
            derived_artifact_id=(
                str(row["derived_artifact_id"])
                if row["derived_artifact_id"] is not None
                else None
            ),
            derivation=(
                json.loads(str(row["derivation_json"]))
                if row["derivation_json"] is not None
                else None
            ),
        )

    @staticmethod
    def _prepare_vault(candidate: Path) -> Path:
        expanded = candidate.expanduser()
        if expanded.exists() and expanded.is_symlink():
            raise EvidenceCatalogError("Evidence vault cannot be a symbolic link")
        try:
            expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
            resolved = expanded.resolve(strict=True)
            if not resolved.is_dir():
                raise EvidenceCatalogError("Evidence vault is not a directory")
            os.chmod(resolved, 0o700)
        except OSError as exc:
            raise EvidenceCatalogError("Evidence vault could not be created securely") from exc
        return resolved


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise EvidenceCatalogError("Evidence catalog database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise EvidenceCatalogError("Evidence catalog directory does not exist") from exc
    if not parent.is_dir():
        raise EvidenceCatalogError("Evidence catalog parent is not a directory")
    return str(parent / candidate.name)


def _safe_filename(value: str) -> tuple[str, str]:
    decoded = unquote(value).strip()
    if not decoded or len(decoded) > 255 or any(ord(character) < 32 for character in decoded):
        raise EvidenceCatalogError("Evidence filename is invalid")
    if Path(decoded).name != decoded or decoded in {".", ".."}:
        raise EvidenceCatalogError("Evidence filename must not contain a path")
    suffix = Path(decoded).suffix.lower()
    if len(suffix) > 12 or any(
        character not in ".abcdefghijklmnopqrstuvwxyz0123456789" for character in suffix
    ):
        suffix = ".bin"
    return decoded, suffix or ".bin"


def _require_identifier(value: str, label: str) -> None:
    if not value.strip() or len(value) > 256:
        raise EvidenceCatalogError(f"{label} is invalid")


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise EvidenceCatalogError("Evidence vault returned a short write")
        remaining = remaining[written:]


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Evidence timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
