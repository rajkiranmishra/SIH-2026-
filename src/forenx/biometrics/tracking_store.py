from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forenx.biometrics.tracking import FaceTrackingResult


class FaceTrackingStoreError(RuntimeError):
    pass


class FaceTrackingRunNotFoundError(FaceTrackingStoreError):
    pass


@dataclass(frozen=True, slots=True)
class StoredFaceTrackObservation:
    observation_id: str
    sequence: int
    run_id: str
    detection_id: str
    observed_timestamp_ms: int
    source_frame_sha256: str
    frame_width: int
    frame_height: int
    x: float
    y: float
    width: float
    height: float
    confidence: float
    association_iou: float | None


@dataclass(frozen=True, slots=True)
class StoredFaceTrack:
    track_id: str
    sequence: int
    observations: tuple[StoredFaceTrackObservation, ...]


@dataclass(frozen=True, slots=True)
class FaceTrackingRun:
    tracking_run_id: str
    case_id: str
    source_id: str
    authorization_id: str
    start_timestamp_ms: int
    end_timestamp_ms: int
    iou_threshold: float
    max_gap_ms: int
    algorithm: str
    algorithm_version: str
    included_run_ids: tuple[str, ...]
    distinct_frame_count: int
    created_by: str
    created_at: datetime
    tracks: tuple[StoredFaceTrack, ...]


class FaceTrackingStore:
    def __init__(self, database: str | Path) -> None:
        self._lock = threading.RLock()
        self._closed = False
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
                CREATE TABLE IF NOT EXISTS face_tracking_runs (
                    tracking_run_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    authorization_id TEXT NOT NULL
                        REFERENCES biometric_authorizations(authorization_id),
                    start_timestamp_ms INTEGER NOT NULL CHECK(start_timestamp_ms >= 0),
                    end_timestamp_ms INTEGER NOT NULL CHECK(
                        end_timestamp_ms >= start_timestamp_ms
                    ),
                    iou_threshold REAL NOT NULL CHECK(
                        iou_threshold >= 0.05 AND iou_threshold <= 0.95
                    ),
                    max_gap_ms INTEGER NOT NULL CHECK(max_gap_ms > 0),
                    algorithm TEXT NOT NULL,
                    algorithm_version TEXT NOT NULL,
                    included_run_ids_json TEXT NOT NULL,
                    distinct_frame_count INTEGER NOT NULL CHECK(distinct_frame_count >= 2),
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS face_tracks (
                    track_id TEXT PRIMARY KEY,
                    tracking_run_id TEXT NOT NULL
                        REFERENCES face_tracking_runs(tracking_run_id),
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    UNIQUE(tracking_run_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS face_track_observations (
                    observation_id TEXT PRIMARY KEY,
                    tracking_run_id TEXT NOT NULL
                        REFERENCES face_tracking_runs(tracking_run_id),
                    track_id TEXT NOT NULL REFERENCES face_tracks(track_id),
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    run_id TEXT NOT NULL REFERENCES face_detection_runs(run_id),
                    detection_id TEXT NOT NULL REFERENCES face_detections(detection_id),
                    observed_timestamp_ms INTEGER NOT NULL CHECK(observed_timestamp_ms >= 0),
                    source_frame_sha256 TEXT NOT NULL,
                    frame_width INTEGER NOT NULL CHECK(frame_width > 0),
                    frame_height INTEGER NOT NULL CHECK(frame_height > 0),
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    width REAL NOT NULL CHECK(width > 0),
                    height REAL NOT NULL CHECK(height > 0),
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    association_iou REAL CHECK(
                        association_iou IS NULL
                        OR (association_iou >= 0 AND association_iou <= 1)
                    ),
                    UNIQUE(track_id, sequence),
                    UNIQUE(tracking_run_id, detection_id)
                );

                CREATE INDEX IF NOT EXISTS idx_face_tracking_source_time
                    ON face_tracking_runs(source_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_face_tracks_run_sequence
                    ON face_tracks(tracking_run_id, sequence);
                CREATE INDEX IF NOT EXISTS idx_face_track_observations_track_sequence
                    ON face_track_observations(track_id, sequence);

                CREATE TRIGGER IF NOT EXISTS face_tracking_runs_scope_guard
                BEFORE INSERT ON face_tracking_runs
                WHEN NOT EXISTS (
                    SELECT 1 FROM evidence_sources
                    JOIN biometric_authorizations
                      ON biometric_authorizations.source_id = evidence_sources.source_id
                    JOIN cases ON cases.case_id = evidence_sources.case_id
                    WHERE evidence_sources.source_id = NEW.source_id
                      AND evidence_sources.case_id = NEW.case_id
                      AND biometric_authorizations.authorization_id = NEW.authorization_id
                      AND biometric_authorizations.case_id = NEW.case_id
                      AND biometric_authorizations.retention_until > NEW.created_at
                      AND cases.status != 'closed'
                )
                BEGIN
                    SELECT RAISE(ABORT, 'face-tracking run scope is invalid');
                END;

                CREATE TRIGGER IF NOT EXISTS face_track_observations_scope_guard
                BEFORE INSERT ON face_track_observations
                WHEN NOT EXISTS (
                    SELECT 1 FROM face_detections
                    JOIN face_detection_runs
                      ON face_detection_runs.run_id = face_detections.run_id
                    JOIN face_tracking_runs
                      ON face_tracking_runs.tracking_run_id = NEW.tracking_run_id
                    JOIN face_tracks ON face_tracks.track_id = NEW.track_id
                    WHERE face_detections.detection_id = NEW.detection_id
                      AND face_detections.run_id = NEW.run_id
                      AND face_detection_runs.source_id = face_tracking_runs.source_id
                      AND face_tracks.tracking_run_id = NEW.tracking_run_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'face-track observation scope is invalid');
                END;

                CREATE TRIGGER IF NOT EXISTS face_tracking_runs_no_update
                BEFORE UPDATE ON face_tracking_runs BEGIN
                    SELECT RAISE(ABORT, 'face-tracking runs are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS face_tracking_runs_no_delete
                BEFORE DELETE ON face_tracking_runs BEGIN
                    SELECT RAISE(ABORT, 'face-tracking runs are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS face_tracks_no_update
                BEFORE UPDATE ON face_tracks BEGIN
                    SELECT RAISE(ABORT, 'face tracks are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS face_tracks_no_delete
                BEFORE DELETE ON face_tracks BEGIN
                    SELECT RAISE(ABORT, 'face tracks are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS face_track_observations_no_update
                BEFORE UPDATE ON face_track_observations BEGIN
                    SELECT RAISE(ABORT, 'face-track observations are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS face_track_observations_no_delete
                BEFORE DELETE ON face_track_observations BEGIN
                    SELECT RAISE(ABORT, 'face-track observations are immutable');
                END;
                """
            )
            self._connection.execute("PRAGMA optimize")

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    def save(
        self,
        *,
        case_id: str,
        source_id: str,
        authorization_id: str,
        result: FaceTrackingResult,
        created_by: str,
        created_at: datetime | None = None,
    ) -> FaceTrackingRun:
        for value, label in (
            (case_id, "Case identifier"),
            (source_id, "Source identifier"),
            (authorization_id, "Authorization identifier"),
            (created_by, "Creator identifier"),
        ):
            _require_identifier(value, label)
        timestamp = created_at or datetime.now(UTC)
        normalized_time = _normalized_time(timestamp)
        tracking_run_id = str(uuid4())
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO face_tracking_runs(
                        tracking_run_id, case_id, source_id, authorization_id,
                        start_timestamp_ms, end_timestamp_ms, iou_threshold,
                        max_gap_ms, algorithm, algorithm_version,
                        included_run_ids_json, distinct_frame_count, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tracking_run_id,
                        case_id,
                        source_id,
                        authorization_id,
                        result.start_timestamp_ms,
                        result.end_timestamp_ms,
                        result.iou_threshold,
                        result.max_gap_ms,
                        result.algorithm,
                        result.algorithm_version,
                        json.dumps(list(result.included_run_ids), separators=(",", ":")),
                        result.distinct_frame_count,
                        created_by,
                        normalized_time,
                    ),
                )
                for track in result.tracks:
                    track_id = str(uuid4())
                    self._connection.execute(
                        "INSERT INTO face_tracks VALUES (?, ?, ?)",
                        (track_id, tracking_run_id, track.sequence),
                    )
                    for observation in track.observations:
                        self._connection.execute(
                            """
                            INSERT INTO face_track_observations(
                                observation_id, tracking_run_id, track_id, sequence,
                                run_id, detection_id, observed_timestamp_ms,
                                source_frame_sha256, frame_width, frame_height,
                                x, y, width, height, confidence, association_iou
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                str(uuid4()),
                                tracking_run_id,
                                track_id,
                                observation.sequence,
                                observation.run_id,
                                observation.detection_id,
                                observation.observed_timestamp_ms,
                                observation.source_frame_sha256,
                                observation.frame_width,
                                observation.frame_height,
                                observation.x,
                                observation.y,
                                observation.width,
                                observation.height,
                                observation.confidence,
                                observation.association_iou,
                            ),
                        )
        except sqlite3.IntegrityError as exc:
            raise FaceTrackingStoreError(
                "Face-tracking result could not be stored safely"
            ) from exc
        return self.get(tracking_run_id)

    def get(self, tracking_run_id: str) -> FaceTrackingRun:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM face_tracking_runs WHERE tracking_run_id = ?",
                (tracking_run_id,),
            ).fetchone()
            if row is None:
                raise FaceTrackingRunNotFoundError("Face-tracking run was not found")
            track_rows = self._connection.execute(
                """
                SELECT * FROM face_tracks WHERE tracking_run_id = ? ORDER BY sequence
                """,
                (tracking_run_id,),
            ).fetchall()
            tracks = tuple(self._track_from_row(track_row) for track_row in track_rows)
        return FaceTrackingRun(
            tracking_run_id=str(row["tracking_run_id"]),
            case_id=str(row["case_id"]),
            source_id=str(row["source_id"]),
            authorization_id=str(row["authorization_id"]),
            start_timestamp_ms=int(row["start_timestamp_ms"]),
            end_timestamp_ms=int(row["end_timestamp_ms"]),
            iou_threshold=float(row["iou_threshold"]),
            max_gap_ms=int(row["max_gap_ms"]),
            algorithm=str(row["algorithm"]),
            algorithm_version=str(row["algorithm_version"]),
            included_run_ids=tuple(json.loads(str(row["included_run_ids_json"]))),
            distinct_frame_count=int(row["distinct_frame_count"]),
            created_by=str(row["created_by"]),
            created_at=_parsed_time(str(row["created_at"])),
            tracks=tracks,
        )

    def _track_from_row(self, row: sqlite3.Row) -> StoredFaceTrack:
        observations = self._connection.execute(
            """
            SELECT * FROM face_track_observations
            WHERE track_id = ? ORDER BY sequence
            """,
            (str(row["track_id"]),),
        ).fetchall()
        return StoredFaceTrack(
            track_id=str(row["track_id"]),
            sequence=int(row["sequence"]),
            observations=tuple(_observation_from_row(item) for item in observations),
        )

    def list_for_source(self, source_id: str) -> tuple[FaceTrackingRun, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT tracking_run_id FROM face_tracking_runs
                WHERE source_id = ? ORDER BY created_at, tracking_run_id
                """,
                (source_id,),
            ).fetchall()
        return tuple(self.get(str(row["tracking_run_id"])) for row in rows)


def _observation_from_row(row: sqlite3.Row) -> StoredFaceTrackObservation:
    return StoredFaceTrackObservation(
        observation_id=str(row["observation_id"]),
        sequence=int(row["sequence"]),
        run_id=str(row["run_id"]),
        detection_id=str(row["detection_id"]),
        observed_timestamp_ms=int(row["observed_timestamp_ms"]),
        source_frame_sha256=str(row["source_frame_sha256"]),
        frame_width=int(row["frame_width"]),
        frame_height=int(row["frame_height"]),
        x=float(row["x"]),
        y=float(row["y"]),
        width=float(row["width"]),
        height=float(row["height"]),
        confidence=float(row["confidence"]),
        association_iou=(
            float(row["association_iou"])
            if row["association_iou"] is not None
            else None
        ),
    )


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise FaceTrackingStoreError("Tracking database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise FaceTrackingStoreError("Tracking database directory does not exist") from exc
    if not parent.is_dir():
        raise FaceTrackingStoreError("Tracking database parent is not a directory")
    target = parent / candidate.name
    if target.exists():
        os.chmod(target, 0o600)
    return str(target)


def _require_identifier(value: str, label: str) -> None:
    if not value.strip() or len(value) > 128:
        raise ValueError(f"{label} must contain between 1 and 128 characters")


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Face-tracking timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
