from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from forenx.cases.domain import (
    ALLOWED_CASE_TRANSITIONS,
    ActivityEvent,
    ActivityVerification,
    CaseRecord,
    CaseStatus,
    ExhibitRecord,
)
from forenx.custody.ledger import GENESIS_HASH

SCHEMA_VERSION = 1


class CaseStoreError(RuntimeError):
    """Base error for durable case storage."""


class CaseNotFoundError(CaseStoreError):
    pass


class DuplicateCaseReferenceError(CaseStoreError):
    pass


class DuplicateExhibitNumberError(CaseStoreError):
    pass


class InvalidCaseTransitionError(CaseStoreError):
    pass


class ConcurrentCaseUpdateError(CaseStoreError):
    pass


class CaseStore:
    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = threading.RLock()
        self._closed = False
        database_target: str
        file_path: Path | None = None
        if str(database) == ":memory:":
            database_target = ":memory:"
        else:
            candidate = Path(database).expanduser()
            if candidate.is_symlink():
                raise CaseStoreError("Case database cannot be a symbolic link")
            try:
                parent = candidate.parent.resolve(strict=True)
            except OSError as exc:
                raise CaseStoreError("Case database directory does not exist") from exc
            if not parent.is_dir():
                raise CaseStoreError("Case database parent is not a directory")
            file_path = parent / candidate.name
            database_target = str(file_path)

        self._connection = sqlite3.connect(
            database_target,
            check_same_thread=False,
            timeout=5,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if file_path is not None:
            self._connection.execute("PRAGMA journal_mode = WAL")
            os.chmod(file_path, 0o600)
        self.initialize()

    def initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    case_reference TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    agency TEXT NOT NULL,
                    police_station TEXT,
                    investigating_officer TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS exhibits (
                    exhibit_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    exhibit_number TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    manufacturer TEXT,
                    model TEXT,
                    serial_number TEXT,
                    channel_count INTEGER CHECK (channel_count IS NULL OR channel_count > 0),
                    working_channels_observed INTEGER CHECK (
                        working_channels_observed IS NULL OR working_channels_observed >= 0
                    ),
                    recorder_time_observed TEXT,
                    clock_offset_seconds INTEGER,
                    seal_number TEXT,
                    seal_condition TEXT NOT NULL,
                    packaging TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    collection_location TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    authorization_reference TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(case_id, exhibit_number)
                );

                CREATE TABLE IF NOT EXISTS activity_events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    sequence INTEGER NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    UNIQUE(case_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
                CREATE INDEX IF NOT EXISTS idx_exhibits_case ON exhibits(case_id);
                CREATE INDEX IF NOT EXISTS idx_activity_case_sequence
                    ON activity_events(case_id, sequence);

                CREATE TRIGGER IF NOT EXISTS activity_events_no_update
                BEFORE UPDATE ON activity_events
                BEGIN
                    SELECT RAISE(ABORT, 'activity events are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS activity_events_no_delete
                BEFORE DELETE ON activity_events
                BEGIN
                    SELECT RAISE(ABORT, 'activity events are immutable');
                END;
                """
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO schema_metadata(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = self._connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise CaseStoreError("Unsupported case database schema version")

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def create_case(
        self,
        *,
        case_reference: str,
        agency: str,
        investigating_officer: str,
        classification: str,
        actor_id: str,
        police_station: str | None = None,
        occurred_at: datetime | None = None,
    ) -> CaseRecord:
        _require_text(
            case_reference=case_reference,
            agency=agency,
            investigating_officer=investigating_officer,
            classification=classification,
            actor_id=actor_id,
        )
        now = occurred_at or datetime.now(UTC)
        normalized = _normalized_time(now)
        case_id = str(uuid4())
        with self._lock:
            try:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT INTO cases(
                            case_id, case_reference, agency, police_station,
                            investigating_officer, classification, status, version,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (
                            case_id,
                            case_reference.strip(),
                            agency.strip(),
                            _optional_text(police_station),
                            investigating_officer.strip(),
                            classification.strip(),
                            CaseStatus.INTAKE.value,
                            normalized,
                            normalized,
                        ),
                    )
                    self._append_activity(
                        case_id=case_id,
                        actor_id=actor_id,
                        action="CASE_CREATED",
                        details={"case_reference": case_reference.strip()},
                        occurred_at=now,
                    )
            except sqlite3.IntegrityError as exc:
                raise DuplicateCaseReferenceError(
                    "Case reference already exists"
                ) from exc
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> CaseRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise CaseNotFoundError("Case was not found")
        return _case_from_row(row)

    def list_cases(self, *, status: CaseStatus | None = None) -> tuple[CaseRecord, ...]:
        with self._lock:
            if status is None:
                rows = self._connection.execute(
                    "SELECT * FROM cases ORDER BY created_at DESC, case_id"
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC, case_id",
                    (status.value,),
                ).fetchall()
        return tuple(_case_from_row(row) for row in rows)

    def transition_case(
        self,
        case_id: str,
        target_status: CaseStatus,
        *,
        expected_version: int,
        actor_id: str,
        reason: str,
        occurred_at: datetime | None = None,
    ) -> CaseRecord:
        _require_text(actor_id=actor_id, reason=reason)
        now = occurred_at or datetime.now(UTC)
        normalized = _normalized_time(now)
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT status, version FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                raise CaseNotFoundError("Case was not found")
            current_status = CaseStatus(row["status"])
            current_version = int(row["version"])
            if current_version != expected_version:
                raise ConcurrentCaseUpdateError("Case was changed by another operation")
            if target_status not in ALLOWED_CASE_TRANSITIONS[current_status]:
                raise InvalidCaseTransitionError(
                    f"Case cannot move from {current_status.value} to {target_status.value}"
                )
            updated = self._connection.execute(
                """
                UPDATE cases
                SET status = ?, version = version + 1, updated_at = ?
                WHERE case_id = ? AND version = ?
                """,
                (target_status.value, normalized, case_id, expected_version),
            )
            if updated.rowcount != 1:
                raise ConcurrentCaseUpdateError("Case was changed by another operation")
            self._append_activity(
                case_id=case_id,
                actor_id=actor_id,
                action="CASE_STATUS_CHANGED",
                details={
                    "from": current_status.value,
                    "to": target_status.value,
                    "reason": reason.strip(),
                },
                occurred_at=now,
            )
        return self.get_case(case_id)

    def add_exhibit(
        self,
        case_id: str,
        *,
        exhibit_number: str,
        device_type: str,
        seal_condition: str,
        packaging: str,
        collector: str,
        collection_location: str,
        collected_at: datetime,
        authorization_reference: str,
        actor_id: str,
        manufacturer: str | None = None,
        model: str | None = None,
        serial_number: str | None = None,
        channel_count: int | None = None,
        working_channels_observed: int | None = None,
        recorder_time_observed: datetime | None = None,
        clock_offset_seconds: int | None = None,
        seal_number: str | None = None,
    ) -> ExhibitRecord:
        _require_text(
            exhibit_number=exhibit_number,
            device_type=device_type,
            seal_condition=seal_condition,
            packaging=packaging,
            collector=collector,
            collection_location=collection_location,
            authorization_reference=authorization_reference,
            actor_id=actor_id,
        )
        if channel_count is not None and channel_count <= 0:
            raise ValueError("Channel count must be positive")
        if working_channels_observed is not None and working_channels_observed < 0:
            raise ValueError("Working-channel count cannot be negative")
        if (
            channel_count is not None
            and working_channels_observed is not None
            and working_channels_observed > channel_count
        ):
            raise ValueError("Working-channel count cannot exceed total channels")

        collected = _normalized_time(collected_at)
        recorder_time = (
            _normalized_time(recorder_time_observed)
            if recorder_time_observed is not None
            else None
        )
        now = datetime.now(UTC)
        created = _normalized_time(now)
        exhibit_id = str(uuid4())
        with self._lock:
            try:
                with self._connection:
                    if not self._case_exists(case_id):
                        raise CaseNotFoundError("Case was not found")
                    self._connection.execute(
                        """
                        INSERT INTO exhibits(
                            exhibit_id, case_id, exhibit_number, device_type, manufacturer,
                            model, serial_number, channel_count, working_channels_observed,
                            recorder_time_observed, clock_offset_seconds, seal_number,
                            seal_condition, packaging, collector, collection_location,
                            collected_at, authorization_reference, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            exhibit_id,
                            case_id,
                            exhibit_number.strip(),
                            device_type.strip(),
                            _optional_text(manufacturer),
                            _optional_text(model),
                            _optional_text(serial_number),
                            channel_count,
                            working_channels_observed,
                            recorder_time,
                            clock_offset_seconds,
                            _optional_text(seal_number),
                            seal_condition.strip(),
                            packaging.strip(),
                            collector.strip(),
                            collection_location.strip(),
                            collected,
                            authorization_reference.strip(),
                            created,
                        ),
                    )
                    self._append_activity(
                        case_id=case_id,
                        actor_id=actor_id,
                        action="EXHIBIT_REGISTERED",
                        details={
                            "exhibit_id": exhibit_id,
                            "exhibit_number": exhibit_number.strip(),
                            "seal_condition": seal_condition.strip(),
                        },
                        occurred_at=now,
                    )
            except sqlite3.IntegrityError as exc:
                raise DuplicateExhibitNumberError(
                    "Exhibit number already exists in this case"
                ) from exc
        return self.get_exhibit(exhibit_id)

    def get_exhibit(self, exhibit_id: str) -> ExhibitRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM exhibits WHERE exhibit_id = ?",
                (exhibit_id,),
            ).fetchone()
        if row is None:
            raise CaseNotFoundError("Exhibit was not found")
        return _exhibit_from_row(row)

    def list_exhibits(self, case_id: str) -> tuple[ExhibitRecord, ...]:
        with self._lock:
            if not self._case_exists(case_id):
                raise CaseNotFoundError("Case was not found")
            rows = self._connection.execute(
                "SELECT * FROM exhibits WHERE case_id = ? ORDER BY created_at, exhibit_id",
                (case_id,),
            ).fetchall()
        return tuple(_exhibit_from_row(row) for row in rows)

    def list_activity(self, case_id: str) -> tuple[ActivityEvent, ...]:
        with self._lock:
            if not self._case_exists(case_id):
                raise CaseNotFoundError("Case was not found")
            rows = self._connection.execute(
                "SELECT * FROM activity_events WHERE case_id = ? ORDER BY sequence",
                (case_id,),
            ).fetchall()
        return tuple(_activity_from_row(row) for row in rows)

    def verify_activity(self, case_id: str) -> ActivityVerification:
        events = self.list_activity(case_id)
        previous_hash = GENESIS_HASH
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence:
                return ActivityVerification(
                    False,
                    expected_sequence - 1,
                    "Activity sequence is not contiguous",
                    event.sequence,
                )
            if event.previous_hash != previous_hash:
                return ActivityVerification(
                    False,
                    expected_sequence - 1,
                    "Previous activity hash does not match",
                    event.sequence,
                )
            payload = _activity_payload(
                event_id=event.event_id,
                case_id=event.case_id,
                sequence=event.sequence,
                actor_id=event.actor_id,
                action=event.action,
                occurred_at=_normalized_time(event.occurred_at),
                details=event.details,
                previous_hash=event.previous_hash,
            )
            calculated = hashlib.sha256(_canonical_json(payload)).hexdigest()
            if calculated != event.event_hash:
                return ActivityVerification(
                    False,
                    expected_sequence - 1,
                    "Activity event hash does not match",
                    event.sequence,
                )
            previous_hash = event.event_hash
        return ActivityVerification(True, len(events))

    def record_activity(
        self,
        case_id: str,
        *,
        actor_id: str,
        action: str,
        details: Mapping[str, Any],
        occurred_at: datetime | None = None,
    ) -> ActivityEvent:
        _require_text(actor_id=actor_id, action=action)
        if not isinstance(details, Mapping):
            raise ValueError("Activity details must be a mapping")
        now = occurred_at or datetime.now(UTC)
        with self._lock, self._connection:
            if not self._case_exists(case_id):
                raise CaseNotFoundError("Case was not found")
            self._append_activity(
                case_id=case_id,
                actor_id=actor_id,
                action=action,
                details=details,
                occurred_at=now,
            )
            row = self._connection.execute(
                "SELECT * FROM activity_events WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        if row is None:
            raise CaseStoreError("Recorded activity could not be read back")
        return _activity_from_row(row)

    def _case_exists(self, case_id: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            is not None
        )

    def _append_activity(
        self,
        *,
        case_id: str,
        actor_id: str,
        action: str,
        details: Mapping[str, Any],
        occurred_at: datetime,
    ) -> None:
        latest = self._connection.execute(
            """
            SELECT sequence, event_hash FROM activity_events
            WHERE case_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        sequence = int(latest["sequence"]) + 1 if latest is not None else 1
        previous_hash = str(latest["event_hash"]) if latest is not None else GENESIS_HASH
        event_id = str(uuid4())
        occurred = _normalized_time(occurred_at)
        safe_details = json.loads(_canonical_json(dict(details)).decode())
        payload = _activity_payload(
            event_id=event_id,
            case_id=case_id,
            sequence=sequence,
            actor_id=actor_id.strip(),
            action=action,
            occurred_at=occurred,
            details=safe_details,
            previous_hash=previous_hash,
        )
        event_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()
        self._connection.execute(
            """
            INSERT INTO activity_events(
                event_id, case_id, sequence, actor_id, action, occurred_at,
                details_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                case_id,
                sequence,
                actor_id.strip(),
                action,
                occurred,
                _canonical_json(safe_details).decode(),
                previous_hash,
                event_hash,
            ),
        )


def _case_from_row(row: sqlite3.Row) -> CaseRecord:
    return CaseRecord(
        case_id=str(row["case_id"]),
        case_reference=str(row["case_reference"]),
        agency=str(row["agency"]),
        police_station=str(row["police_station"]) if row["police_station"] is not None else None,
        investigating_officer=str(row["investigating_officer"]),
        classification=str(row["classification"]),
        status=CaseStatus(row["status"]),
        version=int(row["version"]),
        created_at=_parsed_time(str(row["created_at"])),
        updated_at=_parsed_time(str(row["updated_at"])),
    )


def _exhibit_from_row(row: sqlite3.Row) -> ExhibitRecord:
    return ExhibitRecord(
        exhibit_id=str(row["exhibit_id"]),
        case_id=str(row["case_id"]),
        exhibit_number=str(row["exhibit_number"]),
        device_type=str(row["device_type"]),
        manufacturer=_row_optional_text(row, "manufacturer"),
        model=_row_optional_text(row, "model"),
        serial_number=_row_optional_text(row, "serial_number"),
        channel_count=int(row["channel_count"]) if row["channel_count"] is not None else None,
        working_channels_observed=(
            int(row["working_channels_observed"])
            if row["working_channels_observed"] is not None
            else None
        ),
        recorder_time_observed=(
            _parsed_time(str(row["recorder_time_observed"]))
            if row["recorder_time_observed"] is not None
            else None
        ),
        clock_offset_seconds=(
            int(row["clock_offset_seconds"])
            if row["clock_offset_seconds"] is not None
            else None
        ),
        seal_number=_row_optional_text(row, "seal_number"),
        seal_condition=str(row["seal_condition"]),
        packaging=str(row["packaging"]),
        collector=str(row["collector"]),
        collection_location=str(row["collection_location"]),
        collected_at=_parsed_time(str(row["collected_at"])),
        authorization_reference=str(row["authorization_reference"]),
        created_at=_parsed_time(str(row["created_at"])),
    )


def _activity_from_row(row: sqlite3.Row) -> ActivityEvent:
    details = json.loads(str(row["details_json"]))
    return ActivityEvent(
        event_id=str(row["event_id"]),
        case_id=str(row["case_id"]),
        sequence=int(row["sequence"]),
        actor_id=str(row["actor_id"]),
        action=str(row["action"]),
        occurred_at=_parsed_time(str(row["occurred_at"])),
        details=MappingProxyType(details),
        previous_hash=str(row["previous_hash"]),
        event_hash=str(row["event_hash"]),
    )


def _activity_payload(
    *,
    event_id: str,
    case_id: str,
    sequence: int,
    actor_id: str,
    action: str,
    occurred_at: str,
    details: Mapping[str, Any],
    previous_hash: str,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "case_id": case_id,
        "sequence": sequence,
        "actor_id": actor_id,
        "action": action,
        "occurred_at": occurred_at,
        "details": dict(details),
        "previous_hash": previous_hash,
    }


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Case timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _require_text(**values: str) -> None:
    empty = [name for name, value in values.items() if not value.strip()]
    if empty:
        raise ValueError(f"Required case fields cannot be empty: {', '.join(empty)}")


def _optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _row_optional_text(row: sqlite3.Row, field: str) -> str | None:
    value = row[field]
    return str(value) if value is not None else None
