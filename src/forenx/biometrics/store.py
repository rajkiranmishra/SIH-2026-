from __future__ import annotations

import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forenx.biometrics.domain import (
    BiometricAuthorizationRecord,
    BiometricComparisonMode,
)


class BiometricAuthorizationError(RuntimeError):
    """Base error for controlled biometric-analysis authorization."""


class BiometricAuthorizationNotFoundError(BiometricAuthorizationError):
    pass


class BiometricAuthorizationStore:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self._closed = False
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
                CREATE TABLE IF NOT EXISTS biometric_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    mode TEXT NOT NULL CHECK(mode = 'one-to-one'),
                    purpose TEXT NOT NULL,
                    legal_authority_reference TEXT NOT NULL,
                    reference_provenance TEXT NOT NULL,
                    retention_until TEXT NOT NULL,
                    threshold_policy TEXT NOT NULL,
                    authorized_by TEXT NOT NULL,
                    authorized_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_biometric_authorizations_source_time
                    ON biometric_authorizations(source_id, authorized_at DESC);
                CREATE INDEX IF NOT EXISTS idx_biometric_authorizations_source_retention
                    ON biometric_authorizations(source_id, retention_until);

                CREATE TRIGGER IF NOT EXISTS biometric_authorizations_scope_guard
                BEFORE INSERT ON biometric_authorizations
                WHEN NOT EXISTS (
                    SELECT 1 FROM evidence_sources
                    JOIN cases ON cases.case_id = evidence_sources.case_id
                    WHERE evidence_sources.source_id = NEW.source_id
                      AND evidence_sources.case_id = NEW.case_id
                      AND cases.status != 'closed'
                )
                BEGIN
                    SELECT RAISE(ABORT, 'biometric authorization scope is invalid');
                END;

                CREATE TRIGGER IF NOT EXISTS biometric_authorizations_no_update
                BEFORE UPDATE ON biometric_authorizations BEGIN
                    SELECT RAISE(ABORT, 'biometric authorizations are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS biometric_authorizations_no_delete
                BEFORE DELETE ON biometric_authorizations BEGIN
                    SELECT RAISE(ABORT, 'biometric authorizations are immutable');
                END;
                """
            )
            self._connection.execute("PRAGMA optimize")

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def authorize(
        self,
        *,
        case_id: str,
        source_id: str,
        mode: BiometricComparisonMode,
        purpose: str,
        legal_authority_reference: str,
        reference_provenance: str,
        retention_until: datetime,
        threshold_policy: str,
        authorized_by: str,
        authorized_at: datetime | None = None,
    ) -> BiometricAuthorizationRecord:
        _require_text(
            case_id=case_id,
            source_id=source_id,
            purpose=purpose,
            legal_authority_reference=legal_authority_reference,
            reference_provenance=reference_provenance,
            threshold_policy=threshold_policy,
            authorized_by=authorized_by,
        )
        if mode is not BiometricComparisonMode.ONE_TO_ONE:
            raise BiometricAuthorizationError(
                "Only case-specific one-to-one comparison may be authorized"
            )
        authorization_time = authorized_at or datetime.now(UTC)
        authorized = _normalized_time(authorization_time)
        retained_until = _normalized_time(retention_until)
        if retention_until.astimezone(UTC) <= authorization_time.astimezone(UTC):
            raise BiometricAuthorizationError(
                "Biometric retention deadline must be after authorization time"
            )

        authorization_id = str(uuid4())
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO biometric_authorizations(
                        authorization_id, case_id, source_id, mode, purpose,
                        legal_authority_reference, reference_provenance,
                        retention_until, threshold_policy, authorized_by, authorized_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        authorization_id,
                        case_id.strip(),
                        source_id.strip(),
                        mode.value,
                        purpose.strip(),
                        legal_authority_reference.strip(),
                        reference_provenance.strip(),
                        retained_until,
                        threshold_policy.strip(),
                        authorized_by.strip(),
                        authorized,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise BiometricAuthorizationError(
                    "Biometric authorization could not be linked to this evidence"
                ) from exc
        return self.get(authorization_id)

    def get(self, authorization_id: str) -> BiometricAuthorizationRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM biometric_authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        if row is None:
            raise BiometricAuthorizationNotFoundError(
                "Biometric authorization was not found"
            )
        return _record_from_row(row)

    def list_for_source(
        self,
        source_id: str,
    ) -> tuple[BiometricAuthorizationRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM biometric_authorizations WHERE source_id = ?
                ORDER BY authorized_at DESC, authorization_id DESC
                """,
                (source_id,),
            ).fetchall()
        return tuple(_record_from_row(row) for row in rows)

    def latest_active(
        self,
        source_id: str,
        *,
        at: datetime | None = None,
    ) -> BiometricAuthorizationRecord:
        current = _normalized_time(at or datetime.now(UTC))
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM biometric_authorizations
                WHERE source_id = ? AND retention_until > ?
                ORDER BY authorized_at DESC, authorization_id DESC LIMIT 1
                """,
                (source_id, current),
            ).fetchone()
        if row is None:
            raise BiometricAuthorizationNotFoundError(
                "No active biometric authorization exists for this evidence"
            )
        return _record_from_row(row)


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise BiometricAuthorizationError(
            "Biometric authorization database cannot be a symbolic link"
        )
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise BiometricAuthorizationError(
            "Biometric authorization database directory does not exist"
        ) from exc
    if not parent.is_dir():
        raise BiometricAuthorizationError(
            "Biometric authorization database parent is not a directory"
        )
    target = parent / candidate.name
    if target.exists():
        os.chmod(target, 0o600)
    return str(target)


def _record_from_row(row: sqlite3.Row) -> BiometricAuthorizationRecord:
    return BiometricAuthorizationRecord(
        authorization_id=str(row["authorization_id"]),
        case_id=str(row["case_id"]),
        source_id=str(row["source_id"]),
        mode=BiometricComparisonMode(str(row["mode"])),
        purpose=str(row["purpose"]),
        legal_authority_reference=str(row["legal_authority_reference"]),
        reference_provenance=str(row["reference_provenance"]),
        retention_until=_parsed_time(str(row["retention_until"])),
        threshold_policy=str(row["threshold_policy"]),
        authorized_by=str(row["authorized_by"]),
        authorized_at=_parsed_time(str(row["authorized_at"])),
    )


def _require_text(**values: str) -> None:
    maximum_lengths = {
        "case_id": 128,
        "source_id": 128,
        "purpose": 2000,
        "legal_authority_reference": 1000,
        "reference_provenance": 2000,
        "threshold_policy": 2000,
        "authorized_by": 128,
    }
    for name, value in values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name.replace('_', ' ').capitalize()} cannot be empty")
        if len(value.strip()) > maximum_lengths[name]:
            raise ValueError(
                f"{name.replace('_', ' ').capitalize()} exceeds "
                f"{maximum_lengths[name]} characters"
            )


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Biometric authorization timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
