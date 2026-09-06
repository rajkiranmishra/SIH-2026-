from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forenx.biometrics.models import DetectorModel, bundled_face_detector


class FaceDetectionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FacePoint:
    x: float
    y: float


@dataclass(frozen=True, slots=True)
class DetectedFace:
    sequence: int
    x: float
    y: float
    width: float
    height: float
    landmarks: tuple[FacePoint, ...]
    confidence: float
    quality_flags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FaceDetectionResult:
    requested_timestamp_ms: int
    observed_timestamp_ms: int
    source_frame_sha256: str
    frame_width: int
    frame_height: int
    analysis_width: int
    analysis_height: int
    model: DetectorModel
    runtime: str
    runtime_version: str
    score_threshold: float
    nms_threshold: float
    max_dimension: int
    preview_sha256: str
    preview_png: bytes
    faces: tuple[DetectedFace, ...]


class FaceDetector:
    SCORE_THRESHOLD = 0.9
    NMS_THRESHOLD = 0.3
    MAX_DIMENSION = 1280
    MAX_PREVIEW_BYTES = 64 * 1024 * 1024

    def __init__(self, *, timeout_seconds: int = 90) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("Detection timeout must be between 1 and 600 seconds")
        self._timeout_seconds = timeout_seconds
        self._worker = Path(__file__).with_name("detect_worker.py").resolve(strict=True)

    def detect(self, evidence_path: Path, *, timestamp_ms: int) -> FaceDetectionResult:
        if isinstance(timestamp_ms, bool) or timestamp_ms < 0:
            raise ValueError("Detection timestamp cannot be negative")
        evidence = _safe_file(evidence_path, "Evidence")
        model = bundled_face_detector()
        environment = {
            "LC_ALL": "C",
            "PYTHONIOENCODING": "utf-8",
            "OMP_NUM_THREADS": "1",
            "ORT_DISABLE_TELEMETRY": "1",
        }
        with tempfile.TemporaryDirectory(prefix="forenx-face-") as temp_directory:
            Path(temp_directory).chmod(0o700)
            preview_path = Path(temp_directory) / "decoded-frame.png"
            command = [
                sys.executable,
                "-I",
                str(self._worker),
                str(evidence),
                str(model.path),
                str(preview_path),
                str(timestamp_ms),
                str(self.SCORE_THRESHOLD),
                str(self.NMS_THRESHOLD),
                str(self.MAX_DIMENSION),
            ]
            try:
                completed = subprocess.run(  # noqa: S603 - fixed worker and arguments
                    command,
                    cwd=evidence.parent,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise FaceDetectionError("Face detection exceeded its time limit") from exc
            except OSError as exc:
                raise FaceDetectionError("Face-detection worker could not start") from exc
            if len(completed.stdout) > 2 * 1024 * 1024:
                raise FaceDetectionError("Face detection returned excessive metadata")
            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise FaceDetectionError("Face detection returned an invalid result") from exc
            if completed.returncode != 0:
                detail = str(payload.get("detail") or payload.get("error") or "unknown error")
                raise FaceDetectionError(f"Face detection failed: {detail}")
            preview_png = _read_preview(preview_path, self.MAX_PREVIEW_BYTES)
            if hashlib.sha256(preview_png).hexdigest() != payload.get("preview_sha256"):
                raise FaceDetectionError("Decoded-frame preview failed integrity verification")
            try:
                return _result_from_payload(payload, model, preview_png)
            except (KeyError, TypeError, ValueError) as exc:
                raise FaceDetectionError("Face-detection result was incomplete") from exc


def _result_from_payload(
    payload: dict[str, Any],
    model: DetectorModel,
    preview_png: bytes,
) -> FaceDetectionResult:
    if payload["model_sha256"] != model.sha256:
        raise ValueError("Worker model identity differs from trusted model")
    frame_width = _bounded_int(payload["frame_width"], minimum=1, maximum=8192)
    frame_height = _bounded_int(payload["frame_height"], minimum=1, maximum=8192)
    faces_payload = payload["faces"]
    if not isinstance(faces_payload, list) or len(faces_payload) > 100:
        raise ValueError("Face list exceeds the supported bound")
    faces: list[DetectedFace] = []
    for expected_sequence, item in enumerate(faces_payload, start=1):
        if not isinstance(item, dict):
            raise TypeError("Face entry must be an object")
        landmarks_payload = item["landmarks"]
        if not isinstance(landmarks_payload, list) or len(landmarks_payload) != 5:
            raise ValueError("Each face must contain five landmarks")
        landmarks = tuple(
            FacePoint(
                _bounded_float(point["x"], minimum=0, maximum=frame_width),
                _bounded_float(point["y"], minimum=0, maximum=frame_height),
            )
            for point in landmarks_payload
            if isinstance(point, dict)
        )
        if len(landmarks) != 5:
            raise TypeError("Face landmark must be an object")
        flags_payload = item["quality_flags"]
        if not isinstance(flags_payload, list) or len(flags_payload) > 16:
            raise ValueError("Quality flags exceed the supported bound")
        face = DetectedFace(
            sequence=_bounded_int(item["sequence"], minimum=1, maximum=100),
            x=_bounded_float(item["x"], minimum=0, maximum=frame_width),
            y=_bounded_float(item["y"], minimum=0, maximum=frame_height),
            width=_bounded_float(item["width"], minimum=1, maximum=frame_width),
            height=_bounded_float(item["height"], minimum=1, maximum=frame_height),
            landmarks=landmarks,
            confidence=_bounded_float(item["confidence"], minimum=0, maximum=1),
            quality_flags=tuple(str(flag)[:128] for flag in flags_payload),
        )
        if face.sequence != expected_sequence:
            raise ValueError("Face sequence is not contiguous")
        if face.x + face.width > frame_width + 0.01:
            raise ValueError("Face box exceeds frame width")
        if face.y + face.height > frame_height + 0.01:
            raise ValueError("Face box exceeds frame height")
        faces.append(face)
    return FaceDetectionResult(
        requested_timestamp_ms=_bounded_int(
            payload["requested_timestamp_ms"], minimum=0, maximum=2**53 - 1
        ),
        observed_timestamp_ms=_bounded_int(
            payload["observed_timestamp_ms"], minimum=0, maximum=2**53 - 1
        ),
        source_frame_sha256=_sha256_text(payload["source_frame_sha256"]),
        frame_width=frame_width,
        frame_height=frame_height,
        analysis_width=_bounded_int(payload["analysis_width"], minimum=1, maximum=8192),
        analysis_height=_bounded_int(payload["analysis_height"], minimum=1, maximum=8192),
        model=model,
        runtime=str(payload["runtime"])[:128],
        runtime_version=str(payload["runtime_version"])[:128],
        score_threshold=_bounded_float(
            payload["score_threshold"], minimum=0, maximum=1
        ),
        nms_threshold=_bounded_float(payload["nms_threshold"], minimum=0, maximum=1),
        max_dimension=_bounded_int(payload["max_dimension"], minimum=320, maximum=4096),
        preview_sha256=_sha256_text(payload["preview_sha256"]),
        preview_png=preview_png,
        faces=tuple(faces),
    )


def _safe_file(candidate: Path, label: str) -> Path:
    path = Path(candidate)
    if path.is_symlink():
        raise FaceDetectionError(f"{label} path is not a safe regular file")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise FaceDetectionError(f"{label} path is not a safe regular file") from exc
    if not resolved.is_file():
        raise FaceDetectionError(f"{label} path is not a safe regular file")
    return resolved


def _read_preview(path: Path, maximum_bytes: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise FaceDetectionError("Face-detection worker did not produce a safe preview")
    size = path.stat().st_size
    if size <= 0 or size > maximum_bytes:
        raise FaceDetectionError("Decoded-frame preview has an unsafe size")
    return path.read_bytes()


def _bounded_int(value: object, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise TypeError("Result is not integer-compatible")
    result = int(value)
    if result < minimum or result > maximum:
        raise ValueError("Integer result is outside its supported bound")
    return result


def _bounded_float(value: object, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise TypeError("Result is not number-compatible")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError("Numeric result is outside its supported bound")
    return result


def _sha256_text(value: object) -> str:
    text = str(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError("Result contains an invalid SHA-256 value")
    return text
