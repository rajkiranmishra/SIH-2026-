from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from forenx.biometrics.detection import DetectedFace, FaceDetectionResult, FacePoint


class FaceDetectionStoreError(RuntimeError):
    pass


class FaceDetectionRunNotFoundError(FaceDetectionStoreError):
    pass


@dataclass(frozen=True, slots=True)
class StoredFaceDetection:
    detection_id: str
    sequence: int
    x: float
    y: float
    width: float
    height: float
    landmarks: tuple[FacePoint, ...]
    confidence: float
    quality_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FaceDetectionRun:
    run_id: str
    case_id: str
    source_id: str
    authorization_id: str
    requested_timestamp_ms: int
    observed_timestamp_ms: int
    source_frame_sha256: str
    frame_width: int
    frame_height: int
    analysis_width: int
    analysis_height: int
    model_id: str
    model_name: str
    model_version: str
    model_sha256: str
    model_license: str
    model_source_uri: str
    runtime: str
    runtime_version: str
    score_threshold: float
    nms_threshold: float
    max_dimension: int
    preview_sha256: str
    created_by: str
    created_at: datetime
    faces: tuple[StoredFaceDetection, ...]


class FaceDetectionStore:
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
                CREATE TABLE IF NOT EXISTS face_detection_runs (
                    run_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
                    authorization_id TEXT NOT NULL
                        REFERENCES biometric_authorizations(authorization_id),
                    requested_timestamp_ms INTEGER NOT NULL
                        CHECK(requested_timestamp_ms >= 0),
                    observed_timestamp_ms INTEGER NOT NULL
                        CHECK(observed_timestamp_ms >= 0),
                    source_frame_sha256 TEXT NOT NULL,
                    frame_width INTEGER NOT NULL CHECK(frame_width > 0),
                    frame_height INTEGER NOT NULL CHECK(frame_height > 0),
                    analysis_width INTEGER NOT NULL CHECK(analysis_width > 0),
                    analysis_height INTEGER NOT NULL CHECK(analysis_height > 0),
                    model_id TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    model_sha256 TEXT NOT NULL,
                    model_license TEXT NOT NULL,
                    model_source_uri TEXT NOT NULL,
                    runtime TEXT NOT NULL,
                    runtime_version TEXT NOT NULL,
                    score_threshold REAL NOT NULL CHECK(
                        score_threshold >= 0 AND score_threshold <= 1
                    ),
                    nms_threshold REAL NOT NULL CHECK(
                        nms_threshold >= 0 AND nms_threshold <= 1
                    ),
                    max_dimension INTEGER NOT NULL CHECK(max_dimension > 0),
                    preview_name TEXT NOT NULL UNIQUE,
                    preview_sha256 TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS face_detections (
                    detection_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES face_detection_runs(run_id),
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    x REAL NOT NULL,
                    y REAL NOT NULL,
                    width REAL NOT NULL CHECK(width > 0),
                    height REAL NOT NULL CHECK(height > 0),
                    landmarks_json TEXT NOT NULL,
                    confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
                    quality_flags_json TEXT NOT NULL,
                    UNIQUE(run_id, sequence)
                );

                CREATE INDEX IF NOT EXISTS idx_face_runs_source_time
                    ON face_detection_runs(source_id, observed_timestamp_ms, created_at);
                CREATE INDEX IF NOT EXISTS idx_face_detections_run_sequence
                    ON face_detections(run_id, sequence);

                CREATE TRIGGER IF NOT EXISTS face_detection_runs_scope_guard
                BEFORE INSERT ON face_detection_runs
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
                    SELECT RAISE(ABORT, 'face-detection run scope is invalid');
                END;

                CREATE TRIGGER IF NOT EXISTS face_detection_runs_no_update
                BEFORE UPDATE ON face_detection_runs BEGIN
                    SELECT RAISE(ABORT, 'face-detection runs are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS face_detection_runs_no_delete
                BEFORE DELETE ON face_detection_runs BEGIN
                    SELECT RAISE(ABORT, 'face-detection runs are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS face_detections_no_update
                BEFORE UPDATE ON face_detections BEGIN
                    SELECT RAISE(ABORT, 'face detections are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS face_detections_no_delete
                BEFORE DELETE ON face_detections BEGIN
                    SELECT RAISE(ABORT, 'face detections are immutable');
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
        result: FaceDetectionResult,
        created_by: str,
        created_at: datetime | None = None,
    ) -> FaceDetectionRun:
        _require_identifier(case_id, "Case identifier")
        _require_identifier(source_id, "Source identifier")
        _require_identifier(authorization_id, "Authorization identifier")
        _require_identifier(created_by, "Creator identifier")
        timestamp = created_at or datetime.now(UTC)
        normalized_time = _normalized_time(timestamp)
        run_id = str(uuid4())
        preview_name = f"{run_id}.png"
        preview_path = self._vault / preview_name
        if hashlib.sha256(result.preview_png).hexdigest() != result.preview_sha256:
            raise FaceDetectionStoreError("Decoded-frame preview hash does not match result")
        try:
            _write_immutable(preview_path, result.preview_png)
        except OSError as exc:
            raise FaceDetectionStoreError(
                "Decoded-frame preview could not be stored safely"
            ) from exc
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO face_detection_runs(
                        run_id, case_id, source_id, authorization_id,
                        requested_timestamp_ms, observed_timestamp_ms,
                        source_frame_sha256, frame_width, frame_height,
                        analysis_width, analysis_height, model_id, model_name,
                        model_version, model_sha256, model_license, model_source_uri,
                        runtime, runtime_version, score_threshold, nms_threshold,
                        max_dimension, preview_name, preview_sha256, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        case_id,
                        source_id,
                        authorization_id,
                        result.requested_timestamp_ms,
                        result.observed_timestamp_ms,
                        result.source_frame_sha256,
                        result.frame_width,
                        result.frame_height,
                        result.analysis_width,
                        result.analysis_height,
                        result.model.model_id,
                        result.model.display_name,
                        result.model.version,
                        result.model.sha256,
                        result.model.license_spdx,
                        result.model.source_uri,
                        result.runtime,
                        result.runtime_version,
                        result.score_threshold,
                        result.nms_threshold,
                        result.max_dimension,
                        preview_name,
                        result.preview_sha256,
                        created_by,
                        normalized_time,
                    ),
                )
                for face in result.faces:
                    self._insert_face(run_id, face)
        except (OSError, sqlite3.IntegrityError) as exc:
            _remove_failed_preview(preview_path)
            raise FaceDetectionStoreError(
                "Face-detection result could not be stored safely"
            ) from exc
        return self.get(run_id)

    def _insert_face(self, run_id: str, face: DetectedFace) -> None:
        self._connection.execute(
            """
            INSERT INTO face_detections(
                detection_id, run_id, sequence, x, y, width, height,
                landmarks_json, confidence, quality_flags_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                run_id,
                face.sequence,
                face.x,
                face.y,
                face.width,
                face.height,
                json.dumps(
                    [{"x": point.x, "y": point.y} for point in face.landmarks],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                face.confidence,
                json.dumps(list(face.quality_flags), separators=(",", ":")),
            ),
        )

    def get(self, run_id: str) -> FaceDetectionRun:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM face_detection_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise FaceDetectionRunNotFoundError("Face-detection run was not found")
            face_rows = self._connection.execute(
                "SELECT * FROM face_detections WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        return _run_from_rows(row, face_rows)

    def list_for_source(self, source_id: str) -> tuple[FaceDetectionRun, ...]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT run_id FROM face_detection_runs WHERE source_id = ?
                ORDER BY observed_timestamp_ms, created_at, run_id
                """,
                (source_id,),
            ).fetchall()
        return tuple(self.get(str(row["run_id"])) for row in rows)

    def preview(self, run_id: str) -> tuple[Path, str]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT preview_name, preview_sha256
                FROM face_detection_runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            raise FaceDetectionRunNotFoundError("Face-detection run was not found")
        path = self._vault / str(row["preview_name"])
        if path.is_symlink() or not path.is_file():
            raise FaceDetectionStoreError("Decoded-frame preview is unavailable")
        observed = _sha256_file(path)
        expected = str(row["preview_sha256"])
        if observed != expected:
            raise FaceDetectionStoreError("Decoded-frame preview failed integrity verification")
        return path, expected


def _run_from_rows(row: sqlite3.Row, face_rows: list[sqlite3.Row]) -> FaceDetectionRun:
    return FaceDetectionRun(
        run_id=str(row["run_id"]),
        case_id=str(row["case_id"]),
        source_id=str(row["source_id"]),
        authorization_id=str(row["authorization_id"]),
        requested_timestamp_ms=int(row["requested_timestamp_ms"]),
        observed_timestamp_ms=int(row["observed_timestamp_ms"]),
        source_frame_sha256=str(row["source_frame_sha256"]),
        frame_width=int(row["frame_width"]),
        frame_height=int(row["frame_height"]),
        analysis_width=int(row["analysis_width"]),
        analysis_height=int(row["analysis_height"]),
        model_id=str(row["model_id"]),
        model_name=str(row["model_name"]),
        model_version=str(row["model_version"]),
        model_sha256=str(row["model_sha256"]),
        model_license=str(row["model_license"]),
        model_source_uri=str(row["model_source_uri"]),
        runtime=str(row["runtime"]),
        runtime_version=str(row["runtime_version"]),
        score_threshold=float(row["score_threshold"]),
        nms_threshold=float(row["nms_threshold"]),
        max_dimension=int(row["max_dimension"]),
        preview_sha256=str(row["preview_sha256"]),
        created_by=str(row["created_by"]),
        created_at=_parsed_time(str(row["created_at"])),
        faces=tuple(_face_from_row(face_row) for face_row in face_rows),
    )


def _face_from_row(row: sqlite3.Row) -> StoredFaceDetection:
    landmarks = json.loads(str(row["landmarks_json"]))
    quality_flags = json.loads(str(row["quality_flags_json"]))
    return StoredFaceDetection(
        detection_id=str(row["detection_id"]),
        sequence=int(row["sequence"]),
        x=float(row["x"]),
        y=float(row["y"]),
        width=float(row["width"]),
        height=float(row["height"]),
        landmarks=tuple(
            FacePoint(x=float(point["x"]), y=float(point["y"])) for point in landmarks
        ),
        confidence=float(row["confidence"]),
        quality_flags=tuple(str(flag) for flag in quality_flags),
    )


def _prepare_vault(candidate: Path) -> Path:
    expanded = candidate.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise FaceDetectionStoreError("Analysis vault cannot be a symbolic link")
    try:
        expanded.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = expanded.resolve(strict=True)
        if not resolved.is_dir():
            raise FaceDetectionStoreError("Analysis vault is not a directory")
        os.chmod(resolved, 0o700)
    except OSError as exc:
        raise FaceDetectionStoreError("Analysis vault could not be prepared securely") from exc
    return resolved


def _database_target(database: str | Path) -> str:
    if str(database) == ":memory:":
        return ":memory:"
    candidate = Path(database).expanduser()
    if candidate.is_symlink():
        raise FaceDetectionStoreError("Analysis database cannot be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise FaceDetectionStoreError("Analysis database directory does not exist") from exc
    if not parent.is_dir():
        raise FaceDetectionStoreError("Analysis database parent is not a directory")
    target = parent / candidate.name
    if target.exists():
        os.chmod(target, 0o600)
    return str(target)


def _write_immutable(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o400)
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def _remove_failed_preview(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_identifier(value: str, label: str) -> None:
    if not value.strip() or len(value) > 128:
        raise ValueError(f"{label} must contain between 1 and 128 characters")


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Face-detection timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
