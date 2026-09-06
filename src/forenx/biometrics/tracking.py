from __future__ import annotations

from dataclasses import dataclass

from forenx.biometrics.detection_store import FaceDetectionRun, StoredFaceDetection

TRACKING_ALGORITHM = "forenx-normalized-iou-greedy"
TRACKING_ALGORITHM_VERSION = "1.0"


class FaceTrackingError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FaceTrackObservation:
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
class FaceTrackResult:
    sequence: int
    observations: tuple[FaceTrackObservation, ...]


@dataclass(frozen=True, slots=True)
class FaceTrackingResult:
    start_timestamp_ms: int
    end_timestamp_ms: int
    iou_threshold: float
    max_gap_ms: int
    algorithm: str
    algorithm_version: str
    included_run_ids: tuple[str, ...]
    distinct_frame_count: int
    tracks: tuple[FaceTrackResult, ...]


def associate_face_detections(
    runs: tuple[FaceDetectionRun, ...],
    *,
    start_timestamp_ms: int,
    end_timestamp_ms: int,
    iou_threshold: float = 0.25,
    max_gap_ms: int = 2000,
) -> FaceTrackingResult:
    _validate_parameters(
        start_timestamp_ms=start_timestamp_ms,
        end_timestamp_ms=end_timestamp_ms,
        iou_threshold=iou_threshold,
        max_gap_ms=max_gap_ms,
    )
    selected = _distinct_runs(runs, start_timestamp_ms, end_timestamp_ms)
    if len(selected) < 2:
        raise FaceTrackingError(
            "At least two distinct detected frames are required in the selected range"
        )
    source_ids = {run.source_id for run in selected}
    case_ids = {run.case_id for run in selected}
    if len(source_ids) != 1 or len(case_ids) != 1:
        raise FaceTrackingError("Tracking inputs must belong to one case and source")

    working_tracks: list[list[FaceTrackObservation]] = []
    for run in selected:
        candidates: list[tuple[float, int, StoredFaceDetection]] = []
        for track_index, observations in enumerate(working_tracks):
            previous = observations[-1]
            gap = run.observed_timestamp_ms - previous.observed_timestamp_ms
            if gap < 0 or gap > max_gap_ms:
                continue
            for detection in run.faces:
                overlap = _normalized_iou(previous, detection, run)
                if overlap >= iou_threshold:
                    candidates.append((overlap, track_index, detection))

        matched_tracks: set[int] = set()
        matched_detections: set[str] = set()
        for overlap, track_index, detection in sorted(
            candidates,
            key=lambda item: (-item[0], item[1], item[2].sequence),
        ):
            if track_index in matched_tracks or detection.detection_id in matched_detections:
                continue
            working_tracks[track_index].append(
                _observation(run, detection, len(working_tracks[track_index]) + 1, overlap)
            )
            matched_tracks.add(track_index)
            matched_detections.add(detection.detection_id)

        for detection in sorted(run.faces, key=lambda item: item.sequence):
            if detection.detection_id in matched_detections:
                continue
            working_tracks.append([_observation(run, detection, 1, None)])

    tracks = tuple(
        FaceTrackResult(sequence=index, observations=tuple(observations))
        for index, observations in enumerate(working_tracks, start=1)
    )
    return FaceTrackingResult(
        start_timestamp_ms=start_timestamp_ms,
        end_timestamp_ms=end_timestamp_ms,
        iou_threshold=iou_threshold,
        max_gap_ms=max_gap_ms,
        algorithm=TRACKING_ALGORITHM,
        algorithm_version=TRACKING_ALGORITHM_VERSION,
        included_run_ids=tuple(run.run_id for run in selected),
        distinct_frame_count=len(selected),
        tracks=tracks,
    )


def _validate_parameters(
    *,
    start_timestamp_ms: int,
    end_timestamp_ms: int,
    iou_threshold: float,
    max_gap_ms: int,
) -> None:
    if isinstance(start_timestamp_ms, bool) or start_timestamp_ms < 0:
        raise ValueError("Tracking start timestamp cannot be negative")
    if isinstance(end_timestamp_ms, bool) or end_timestamp_ms < start_timestamp_ms:
        raise ValueError("Tracking end timestamp must not precede its start")
    if end_timestamp_ms - start_timestamp_ms > 24 * 60 * 60 * 1000:
        raise ValueError("Tracking range cannot exceed 24 hours")
    if isinstance(iou_threshold, bool) or not 0.05 <= iou_threshold <= 0.95:
        raise ValueError("Tracking IoU threshold must be between 0.05 and 0.95")
    if isinstance(max_gap_ms, bool) or not 1 <= max_gap_ms <= 60_000:
        raise ValueError("Tracking maximum gap must be between 1 and 60000 milliseconds")


def _distinct_runs(
    runs: tuple[FaceDetectionRun, ...],
    start_timestamp_ms: int,
    end_timestamp_ms: int,
) -> tuple[FaceDetectionRun, ...]:
    distinct: list[FaceDetectionRun] = []
    seen_frames: set[tuple[int, str]] = set()
    for run in sorted(
        runs,
        key=lambda item: (item.observed_timestamp_ms, item.created_at, item.run_id),
    ):
        if not start_timestamp_ms <= run.observed_timestamp_ms <= end_timestamp_ms:
            continue
        frame_key = (run.observed_timestamp_ms, run.source_frame_sha256)
        if frame_key in seen_frames:
            continue
        seen_frames.add(frame_key)
        distinct.append(run)
    return tuple(distinct)


def _observation(
    run: FaceDetectionRun,
    detection: StoredFaceDetection,
    sequence: int,
    association_iou: float | None,
) -> FaceTrackObservation:
    return FaceTrackObservation(
        sequence=sequence,
        run_id=run.run_id,
        detection_id=detection.detection_id,
        observed_timestamp_ms=run.observed_timestamp_ms,
        source_frame_sha256=run.source_frame_sha256,
        frame_width=run.frame_width,
        frame_height=run.frame_height,
        x=detection.x,
        y=detection.y,
        width=detection.width,
        height=detection.height,
        confidence=detection.confidence,
        association_iou=association_iou,
    )


def _normalized_iou(
    previous: FaceTrackObservation,
    current: StoredFaceDetection,
    current_run: FaceDetectionRun,
) -> float:
    left_a = previous.x / previous.frame_width
    top_a = previous.y / previous.frame_height
    right_a = (previous.x + previous.width) / previous.frame_width
    bottom_a = (previous.y + previous.height) / previous.frame_height
    left_b = current.x / current_run.frame_width
    top_b = current.y / current_run.frame_height
    right_b = (current.x + current.width) / current_run.frame_width
    bottom_b = (current.y + current.height) / current_run.frame_height
    intersection_width = max(0.0, min(right_a, right_b) - max(left_a, left_b))
    intersection_height = max(0.0, min(bottom_a, bottom_b) - max(top_a, top_b))
    intersection = intersection_width * intersection_height
    union = (right_a - left_a) * (bottom_a - top_a) + (
        (right_b - left_b) * (bottom_b - top_b)
    ) - intersection
    return intersection / union if union > 0 else 0.0
