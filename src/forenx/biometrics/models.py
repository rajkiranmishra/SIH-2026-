from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


class DetectorModelError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DetectorModel:
    model_id: str
    display_name: str
    version: str
    task: str
    sha256: str
    license_spdx: str
    source_uri: str
    path: Path


YUNET_2026MAY_SHA256 = "ebafce4e3c118d6554634be5c27ab333b4c047a9a8c3faf1d7cf93101c22f0f0"


def bundled_face_detector() -> DetectorModel:
    model_path = (
        Path(__file__).resolve().parents[1]
        / "models"
        / "face_detection_yunet_2026may.onnx"
    )
    if model_path.is_symlink() or not model_path.is_file():
        raise DetectorModelError("Bundled face-detector model is unavailable")
    observed = _sha256_file(model_path)
    if observed != YUNET_2026MAY_SHA256:
        raise DetectorModelError("Bundled face-detector model failed integrity verification")
    return DetectorModel(
        model_id="opencv-yunet-2026may",
        display_name="YuNet face detector",
        version="2026may",
        task="face-detection",
        sha256=observed,
        license_spdx="MIT",
        source_uri=(
            "https://github.com/opencv/opencv_zoo/tree/main/"
            "models/face_detection_yunet"
        ),
        path=model_path,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
