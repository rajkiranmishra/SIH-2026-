from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

import av
import numpy as np
import onnxruntime as ort  # type: ignore[import-untyped]
from PIL import Image

STRIDES = (8, 16, 32)
OUTPUT_NAMES = (
    "cls_8",
    "cls_16",
    "cls_32",
    "obj_8",
    "obj_16",
    "obj_32",
    "bbox_8",
    "bbox_16",
    "bbox_32",
    "kps_8",
    "kps_16",
    "kps_32",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_frame(path: Path, timestamp_ms: int) -> tuple[av.VideoFrame, int]:
    av.logging.set_level(av.logging.PANIC)
    with av.open(str(path), mode="r", metadata_errors="ignore") as container:
        stream = next((item for item in container.streams if item.type == "video"), None)
        if stream is None or stream.time_base is None:
            raise ValueError("Evidence does not contain a seekable video stream")
        start_pts = stream.start_time or 0
        target_pts = start_pts + int((timestamp_ms / 1000) / float(stream.time_base))
        container.seek(target_pts, stream=stream, any_frame=False, backward=True)
        chosen: av.VideoFrame | None = None
        chosen_timestamp = 0
        chosen_distance = sys.maxsize
        for index, frame in enumerate(container.decode(stream)):
            if index >= 500:
                break
            if not isinstance(frame, av.VideoFrame):
                continue
            if frame.pts is None or frame.time_base is None:
                continue
            relative_seconds = float((frame.pts - start_pts) * frame.time_base)
            current_timestamp = max(0, round(relative_seconds * 1000))
            distance = abs(current_timestamp - timestamp_ms)
            if distance < chosen_distance:
                chosen = frame
                chosen_timestamp = current_timestamp
                chosen_distance = distance
            if current_timestamp >= timestamp_ms:
                break
        if chosen is None:
            raise ValueError("Requested video frame could not be decoded")
        return chosen, chosen_timestamp


def _prepare_image(
    bgr: np.ndarray[Any, np.dtype[np.uint8]],
    max_dimension: int,
) -> tuple[np.ndarray[Any, np.dtype[np.float32]], int, int, float, float]:
    original_height, original_width = bgr.shape[:2]
    scale = min(1.0, max_dimension / max(original_width, original_height))
    analysis_width = max(1, round(original_width * scale))
    analysis_height = max(1, round(original_height * scale))
    if (analysis_width, analysis_height) == (original_width, original_height):
        analysis_bgr = bgr
    else:
        rgb = Image.fromarray(bgr[:, :, ::-1], mode="RGB")
        resized = rgb.resize((analysis_width, analysis_height), Image.Resampling.BILINEAR)
        analysis_bgr = np.asarray(resized, dtype=np.uint8)[:, :, ::-1].copy()
    padded_width = math.ceil(analysis_width / 32) * 32
    padded_height = math.ceil(analysis_height / 32) * 32
    padded = np.zeros((padded_height, padded_width, 3), dtype=np.uint8)
    padded[:analysis_height, :analysis_width] = analysis_bgr
    blob = np.transpose(padded, (2, 0, 1))[None].astype(np.float32)
    return (
        blob,
        analysis_width,
        analysis_height,
        original_width / analysis_width,
        original_height / analysis_height,
    )


def _iou(left: list[float], right: list[float]) -> float:
    x1 = max(left[0], right[0])
    y1 = max(left[1], right[1])
    x2 = min(left[0] + left[2], right[0] + right[2])
    y2 = min(left[1] + left[3], right[1] + right[3])
    intersection = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    union = left[2] * left[3] + right[2] * right[3] - intersection
    return intersection / union if union > 0 else 0.0


def _nms(faces: list[list[float]], threshold: float, *, maximum: int = 100) -> list[list[float]]:
    remaining = sorted(faces, key=lambda item: item[14], reverse=True)[:5000]
    selected: list[list[float]] = []
    while remaining and len(selected) < maximum:
        candidate = remaining.pop(0)
        selected.append(candidate)
        remaining = [item for item in remaining if _iou(candidate, item) < threshold]
    return selected


def _infer(
    blob: np.ndarray[Any, np.dtype[np.float32]],
    model: Path,
    score_threshold: float,
    nms_threshold: float,
    scale_x: float,
    scale_y: float,
    frame_width: int,
    frame_height: int,
) -> list[dict[str, Any]]:
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.enable_mem_pattern = False
    session = ort.InferenceSession(
        str(model),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )
    outputs = session.run(list(OUTPUT_NAMES), {"input": blob})
    padded_height, padded_width = blob.shape[2:]
    decoded: list[list[float]] = []
    for stride_index, stride in enumerate(STRIDES):
        cols = padded_width // stride
        rows = padded_height // stride
        classifications = outputs[stride_index].reshape(-1)
        objects = outputs[stride_index + 3].reshape(-1)
        boxes = outputs[stride_index + 6].reshape(-1, 4)
        keypoints = outputs[stride_index + 9].reshape(-1, 10)
        expected = rows * cols
        if not (
            len(classifications) == len(objects) == len(boxes) == len(keypoints) == expected
        ):
            raise ValueError("Detector returned an unexpected tensor shape")
        scores = np.sqrt(np.clip(classifications, 0, 1) * np.clip(objects, 0, 1))
        for index in np.flatnonzero(scores >= score_threshold):
            row, column = divmod(int(index), cols)
            box = boxes[index]
            center_x = (column + float(box[0])) * stride
            center_y = (row + float(box[1])) * stride
            width = math.exp(float(box[2])) * stride
            height = math.exp(float(box[3])) * stride
            x = center_x - width / 2
            y = center_y - height / 2
            face = [x, y, width, height]
            for landmark_index in range(5):
                face.extend(
                    [
                        (float(keypoints[index, landmark_index * 2]) + column) * stride,
                        (float(keypoints[index, landmark_index * 2 + 1]) + row) * stride,
                    ]
                )
            face.append(float(scores[index]))
            decoded.append(face)

    results: list[dict[str, Any]] = []
    for face in _nms(decoded, nms_threshold):
        x = min(max(0.0, face[0] * scale_x), float(frame_width - 1))
        y = min(max(0.0, face[1] * scale_y), float(frame_height - 1))
        width = min(face[2] * scale_x, frame_width - x)
        height = min(face[3] * scale_y, frame_height - y)
        if width < 1 or height < 1:
            continue
        landmarks = [
            {
                "x": min(max(0.0, face[4 + index * 2] * scale_x), float(frame_width)),
                "y": min(
                    max(0.0, face[5 + index * 2] * scale_y),
                    float(frame_height),
                ),
            }
            for index in range(5)
        ]
        flags: list[str] = []
        if min(width, height) < 40:
            flags.append("small-face")
        if x <= 1 or y <= 1 or x + width >= frame_width - 1 or y + height >= frame_height - 1:
            flags.append("frame-edge")
        if width * height < frame_width * frame_height * 0.01:
            flags.append("low-relative-area")
        results.append(
            {
                "sequence": len(results) + 1,
                "x": x,
                "y": y,
                "width": width,
                "height": height,
                "landmarks": landmarks,
                "confidence": face[14],
                "quality_flags": flags,
            }
        )
    return results


def detect(
    evidence: Path,
    model: Path,
    preview: Path,
    timestamp_ms: int,
    score_threshold: float,
    nms_threshold: float,
    max_dimension: int,
) -> dict[str, Any]:
    frame, observed_timestamp_ms = _decode_frame(evidence, timestamp_ms)
    if frame.width <= 0 or frame.height <= 0 or frame.width > 8192 or frame.height > 8192:
        raise ValueError("Decoded frame dimensions exceed the supported bound")
    if frame.width * frame.height > 33_554_432:
        raise ValueError("Decoded frame contains too many pixels")
    bgr = np.asarray(frame.to_ndarray(format="bgr24"), dtype=np.uint8)
    frame_digest = hashlib.sha256()
    frame_digest.update(frame.width.to_bytes(4, "big"))
    frame_digest.update(frame.height.to_bytes(4, "big"))
    frame_digest.update(bgr.tobytes())
    rgb_image = Image.fromarray(bgr[:, :, ::-1], mode="RGB")
    descriptor = os.open(preview, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        rgb_image.save(output, format="PNG", optimize=False)
        output.flush()
        os.fsync(output.fileno())
    preview_sha256 = _sha256_file(preview)
    blob, analysis_width, analysis_height, scale_x, scale_y = _prepare_image(
        bgr,
        max_dimension,
    )
    faces = _infer(
        blob,
        model,
        score_threshold,
        nms_threshold,
        scale_x,
        scale_y,
        frame.width,
        frame.height,
    )
    return {
        "requested_timestamp_ms": timestamp_ms,
        "observed_timestamp_ms": observed_timestamp_ms,
        "source_frame_sha256": frame_digest.hexdigest(),
        "frame_width": frame.width,
        "frame_height": frame.height,
        "analysis_width": analysis_width,
        "analysis_height": analysis_height,
        "model_sha256": _sha256_file(model),
        "runtime": "ONNX Runtime CPUExecutionProvider",
        "runtime_version": ort.__version__,
        "score_threshold": score_threshold,
        "nms_threshold": nms_threshold,
        "max_dimension": max_dimension,
        "preview_sha256": preview_sha256,
        "faces": faces,
    }


def main() -> int:
    if len(sys.argv) != 8:
        print(json.dumps({"error": "worker requires seven arguments"}))
        return 2
    try:
        payload = detect(
            Path(sys.argv[1]),
            Path(sys.argv[2]),
            Path(sys.argv[3]),
            int(sys.argv[4]),
            float(sys.argv[5]),
            float(sys.argv[6]),
            int(sys.argv[7]),
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": "face detection failed",
                    "error_type": type(exc).__name__,
                    "detail": str(exc)[:2000],
                }
            )
        )
        return 1
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
