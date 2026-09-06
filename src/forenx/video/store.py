from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forenx.video.inspection import (
    MediaInspection,
    _inspection_from_payload,
    inspection_to_payload,
)


class MediaStoreError(RuntimeError):
    pass


class MediaInspectionNotFoundError(MediaStoreError):
    pass


@dataclass(frozen=True, slots=True)
class StoredMediaInspection:
    inspection_id: str
    source_id: str
    result: MediaInspection
    inspected_by: str
    inspected_at: datetime


@dataclass(frozen=True, slots=True)
class BookmarkRecord:
    bookmark_id: str
    case_id: str
    source_id: str
    timestamp_ms: int
    title: str
    note: str | None
    created_by: str
    created_at: datetime


class MediaStore:
    def __init__(self, database: str | Path) -> None:
        self._lock = threading.RLock()
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
                CREATE TABLE IF NOT EXISTS media_inspections (
                    inspection_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    result_json TEXT NOT NULL,
                    inspected_by TEXT NOT NULL,
                    inspected_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_media_inspections_source_time
                    ON media_inspections(source_id, inspected_at DESC);

                CREATE TABLE IF NOT EXISTS media_bookmarks (
                    bookmark_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms >= 0),
                    title TEXT NOT NULL,
                    note TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_media_bookmarks_source_time
                    ON media_bookmarks(source_id, timestamp_ms, created_at);

                CREATE TRIGGER IF NOT EXISTS media_inspections_no_update
                BEFORE UPDATE ON media_inspections BEGIN
                    SELECT RAISE(ABORT, 'media inspections are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS media_inspections_no_delete
                BEFORE DELETE ON media_inspections BEGIN
                    SELECT RAISE(ABORT, 'media inspections are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS media_bookmarks_no_update
                BEFORE UPDATE ON media_bookmarks BEGIN
                    SELECT RAISE(ABORT, 'media bookmarks are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS media_bookmarks_no_delete
                BEFORE DELETE ON media_bookmarks BEGIN
                    SELECT RAISE(ABORT, 'media bookmarks are immutable');
                END;
                """
            )
            self._connection.execute("PRAGMA optimize")

    def save_inspection(
        self,
        source_id: str,
        result: MediaInspection,
        *,
        inspected_by: str,
        inspected_at: datetime | None = None,
    ) -> StoredMediaInspection:
        inspection_id = str(uuid4())
        timestamp = inspected_at or datetime.now(UTC)
        result_json = json.dumps(
            inspection_to_payload(result),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO media_inspections(
                        inspection_id, source_id, result_json, inspected_by, inspected_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        source_id,
                        result_json,
                        inspected_by,
                        _normalized_time(timestamp),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MediaStoreError("Inspection could not be linked to evidence") from exc
        return self.latest_inspection(source_id)

    def latest_inspection(self, source_id: str) -> StoredMediaInspection:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM media_inspections WHERE source_id = ?
                ORDER BY inspected_at DESC, inspection_id DESC LIMIT 1
                """,
                (source_id,),
            ).fetchone()
        if row is None:
            raise MediaInspectionNotFoundError("Media source has not been inspected")
        return _inspection_from_row(row)

    def add_bookmark(
        self,
        *,
        case_id: str,
        source_id: str,
        timestamp_ms: int,
        title: str,
        note: str | None,
        created_by: str,
        created_at: datetime | None = None,
    ) -> BookmarkRecord:
        if isinstance(timestamp_ms, bool) or timestamp_ms < 0:
            raise ValueError("Bookmark timestamp cannot be negative")
        normalized_title = title.strip()
        if not normalized_title or len(normalized_title) > 256:
            raise ValueError("Bookmark title must contain between 1 and 256 characters")
        normalized_note = note.strip() if note is not None else None
        if normalized_note == "":
            normalized_note = None
        if normalized_note is not None and len(normalized_note) > 4000:
            raise ValueError("Bookmark note exceeds 4000 characters")
        bookmark_id = str(uuid4())
        timestamp = created_at or datetime.now(UTC)
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO media_bookmarks(
                        bookmark_id, case_id, source_id, timestamp_ms,
                        title, note, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        bookmark_id,
                        case_id,
                        source_id,
                        timestamp_ms,
                        normalized_title,
                        normalized_note,
                        created_by,
                        _normalized_time(timestamp),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MediaStoreError("Bookmark could not be linked to evidence") from exc
        return self.get_bookmark(bookmark_id)

    def get_bookmark(self, bookmark_id: str) -> BookmarkRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM media_bookmarks WHERE bookmark_id = ?",
                (bookmark_id,),
            ).fetchone()
        if row is None:
            raise MediaStoreError("Bookmark was not found")
        return _bookmark_from_row(row)

    def list_bookmarks(self, source_id: str) -> tuple[BookmarkRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM media_bookmarks WHERE source_id = ?
                ORDER BY timestamp_ms, created_at, bookmark_id
                """,
                (source_id,),
            ).fetchall()
        return tuple(_bookmark_from_row(row) for row in rows)


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise MediaStoreError("Media database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise MediaStoreError("Media database directory does not exist") from exc
    if not parent.is_dir():
        raise MediaStoreError("Media database parent is not a directory")
    target = parent / candidate.name
    if target.exists():
        os.chmod(target, 0o600)
    return str(target)


def _inspection_from_row(row: sqlite3.Row) -> StoredMediaInspection:
    result = _inspection_from_payload(json.loads(str(row["result_json"])))
    return StoredMediaInspection(
        inspection_id=str(row["inspection_id"]),
        source_id=str(row["source_id"]),
        result=result,
        inspected_by=str(row["inspected_by"]),
        inspected_at=_parsed_time(str(row["inspected_at"])),
    )


def _bookmark_from_row(row: sqlite3.Row) -> BookmarkRecord:
    return BookmarkRecord(
        bookmark_id=str(row["bookmark_id"]),
        case_id=str(row["case_id"]),
        source_id=str(row["source_id"]),
        timestamp_ms=int(row["timestamp_ms"]),
        title=str(row["title"]),
        note=str(row["note"]) if row["note"] is not None else None,
        created_by=str(row["created_by"]),
        created_at=_parsed_time(str(row["created_at"])),
    )


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Media timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
