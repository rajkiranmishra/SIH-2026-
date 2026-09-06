import asyncio
import hashlib
import sqlite3
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from forenx.biometrics import (
    BiometricAuthorizationStore,
    BiometricComparisonMode,
    DetectedFace,
    FaceDetectionResult,
    FaceDetectionRun,
    FaceDetectionStore,
    FacePoint,
    FaceTrackingError,
    FaceTrackingRunNotFoundError,
    FaceTrackingStore,
    StoredFaceDetection,
    associate_face_detections,
    bundled_face_detector,
)
from forenx.cases import CaseStore
from forenx.evidence import EvidenceCatalog, EvidenceMediaKind


async def _content(value: bytes) -> AsyncIterator[bytes]:
    yield value


def _face(sequence: int, detection_id: str, x: float) -> StoredFaceDetection:
    return StoredFaceDetection(
        detection_id=detection_id,
        sequence=sequence,
        x=x,
        y=20,
        width=20,
        height=24,
        landmarks=tuple(FacePoint(x + index, 25 + index) for index in range(5)),
        confidence=0.97,
        quality_flags=(),
    )


def _run(
    run_id: str,
    timestamp_ms: int,
    frame_hash: str,
    faces: tuple[StoredFaceDetection, ...],
) -> FaceDetectionRun:
    return FaceDetectionRun(
        run_id=run_id,
        case_id="case-1",
        source_id="source-1",
        authorization_id="authorization-1",
        requested_timestamp_ms=timestamp_ms,
        observed_timestamp_ms=timestamp_ms,
        source_frame_sha256=frame_hash,
        frame_width=100,
        frame_height=100,
        analysis_width=100,
        analysis_height=100,
        model_id="test-model",
        model_name="Test detector",
        model_version="1",
        model_sha256="a" * 64,
        model_license="MIT",
        model_source_uri="https://example.invalid/model",
        runtime="test",
        runtime_version="1",
        score_threshold=0.9,
        nms_threshold=0.3,
        max_dimension=1280,
        preview_sha256="b" * 64,
        created_by="examiner-1",
        created_at=datetime(2026, 9, 6, tzinfo=UTC)
        + timedelta(milliseconds=timestamp_ms),
        faces=faces,
    )


def test_geometric_tracker_associates_overlapping_boxes_without_identity_claims():
    first = _run(
        "run-1",
        100,
        "1" * 64,
        (_face(1, "face-1", 10), _face(2, "face-2", 70)),
    )
    second = _run(
        "run-2",
        500,
        "2" * 64,
        (_face(1, "face-3", 12), _face(2, "face-4", 68)),
    )

    result = associate_face_detections(
        (second, first),
        start_timestamp_ms=0,
        end_timestamp_ms=1000,
        iou_threshold=0.25,
        max_gap_ms=1000,
    )

    assert result.algorithm == "forenx-normalized-iou-greedy"
    assert result.included_run_ids == ("run-1", "run-2")
    assert result.distinct_frame_count == 2
    assert len(result.tracks) == 2
    assert [len(track.observations) for track in result.tracks] == [2, 2]
    assert result.tracks[0].observations[0].association_iou is None
    assert result.tracks[0].observations[1].association_iou == pytest.approx(9 / 11)
    assert result.tracks[0].observations[1].source_frame_sha256 == "2" * 64


def test_geometric_tracker_deduplicates_frames_and_rejects_mixed_sources():
    first = _run("run-1", 100, "1" * 64, (_face(1, "face-1", 10),))
    duplicate = replace(first, run_id="run-duplicate")
    second = _run("run-2", 500, "2" * 64, (_face(1, "face-2", 12),))

    result = associate_face_detections(
        (first, duplicate, second),
        start_timestamp_ms=0,
        end_timestamp_ms=1000,
    )
    assert result.included_run_ids == ("run-1", "run-2")

    with pytest.raises(FaceTrackingError, match="one case and source"):
        associate_face_detections(
            (first, replace(second, source_id="other-source")),
            start_timestamp_ms=0,
            end_timestamp_ms=1000,
        )


@pytest.mark.parametrize(
    ("start", "end", "iou", "gap", "message"),
    [
        (-1, 10, 0.25, 1000, "start"),
        (10, 9, 0.25, 1000, "end"),
        (0, 10, 0.01, 1000, "IoU"),
        (0, 10, 0.25, 0, "gap"),
    ],
)
def test_geometric_tracker_rejects_unsafe_parameters(
    start: int,
    end: int,
    iou: float,
    gap: int,
    message: str,
):
    with pytest.raises(ValueError, match=message):
        associate_face_detections(
            (),
            start_timestamp_ms=start,
            end_timestamp_ms=end,
            iou_threshold=iou,
            max_gap_ms=gap,
        )


def test_geometric_tracker_requires_two_distinct_detected_frames():
    run = _run("run-1", 100, "1" * 64, ())
    with pytest.raises(FaceTrackingError, match="two distinct"):
        associate_face_detections(
            (run,),
            start_timestamp_ms=0,
            end_timestamp_ms=1000,
        )


def test_face_tracking_store_preserves_provenance_and_is_database_immutable(
    tmp_path: Path,
):
    database = tmp_path / "forenx.sqlite3"
    cases = CaseStore(database)
    case = cases.create_case(
        case_reference="TRACK/2026/01",
        agency="Test laboratory",
        investigating_officer="Inspector Track",
        classification="Restricted",
        actor_id="intake-1",
    )
    exhibit = cases.add_exhibit(
        case.case_id,
        exhibit_number="VIDEO-01",
        device_type="Video export",
        seal_condition="Intact",
        packaging="Evidence bag",
        collector="Inspector Track",
        collection_location="Laboratory",
        collected_at=datetime(2026, 9, 6, tzinfo=UTC),
        authorization_reference="AUTH-TRACK-1",
        actor_id="intake-1",
    )
    catalog = EvidenceCatalog(database, tmp_path / "evidence")
    source = asyncio.run(
        catalog.ingest(
            _content(b"synthetic video bytes"),
            case_id=case.case_id,
            exhibit_id=exhibit.exhibit_id,
            original_filename="controlled.mp4",
            media_kind=EvidenceMediaKind.VIDEO_FILE,
            created_by="intake-1",
        )
    )
    authorized_at = datetime.now(UTC) - timedelta(minutes=1)
    authorization = BiometricAuthorizationStore(database).authorize(
        case_id=case.case_id,
        source_id=source.source_id,
        mode=BiometricComparisonMode.ONE_TO_ONE,
        purpose="Geometric tracking test",
        legal_authority_reference="AUTH-TRACK-1",
        reference_provenance="No recognition reference used.",
        retention_until=authorized_at + timedelta(days=1),
        threshold_policy="Fixed detector and tracking thresholds.",
        authorized_by="supervisor-1",
        authorized_at=authorized_at,
    )
    detection_store = FaceDetectionStore(database, tmp_path / "frames")
    detection_runs = []
    for index, x in enumerate((10.0, 12.0), start=1):
        preview = f"preview-{index}".encode()
        result = FaceDetectionResult(
            requested_timestamp_ms=index * 100,
            observed_timestamp_ms=index * 100,
            source_frame_sha256=str(index) * 64,
            frame_width=100,
            frame_height=100,
            analysis_width=100,
            analysis_height=100,
            model=bundled_face_detector(),
            runtime="test-runtime",
            runtime_version="1",
            score_threshold=0.9,
            nms_threshold=0.3,
            max_dimension=1280,
            preview_sha256=hashlib.sha256(preview).hexdigest(),
            preview_png=preview,
            faces=(
                DetectedFace(
                    sequence=1,
                    x=x,
                    y=20,
                    width=20,
                    height=24,
                    landmarks=tuple(FacePoint(x + point, 25 + point) for point in range(5)),
                    confidence=0.97,
                    quality_flags=(),
                ),
            ),
        )
        detection_runs.append(
            detection_store.save(
                case_id=case.case_id,
                source_id=source.source_id,
                authorization_id=authorization.authorization_id,
                result=result,
                created_by="examiner-1",
            )
        )
    result = associate_face_detections(
        tuple(detection_runs),
        start_timestamp_ms=0,
        end_timestamp_ms=500,
    )
    store = FaceTrackingStore(database)
    saved = store.save(
        case_id=case.case_id,
        source_id=source.source_id,
        authorization_id=authorization.authorization_id,
        result=result,
        created_by="examiner-1",
    )

    assert saved.included_run_ids == tuple(run.run_id for run in detection_runs)
    assert len(saved.tracks) == 1
    assert len(saved.tracks[0].observations) == 2
    assert store.list_for_source(source.source_id) == (saved,)
    with pytest.raises(FaceTrackingRunNotFoundError, match="not found"):
        store.get("missing")

    external = sqlite3.connect(database)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        external.execute(
            "UPDATE face_tracking_runs SET algorithm = 'altered' WHERE tracking_run_id = ?",
            (saved.tracking_run_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        external.execute(
            "DELETE FROM face_track_observations WHERE tracking_run_id = ?",
            (saved.tracking_run_id,),
        )
    external.close()
    store.close()
    store.close()
