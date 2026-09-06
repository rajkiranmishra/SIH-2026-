from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class MediaInspectionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MediaStreamInfo:
    index: int
    type: str
    codec_name: str | None
    codec_long_name: str | None
    duration_seconds: float | None
    start_time_seconds: float | None
    frame_count: int | None
    time_base: str | None
    width: int | None
    height: int | None
    pixel_format: str | None
    average_frame_rate: float | None
    sample_rate: int | None
    channels: int | None
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class MediaInspection:
    format_name: str
    format_long_name: str
    duration_seconds: float | None
    start_time_seconds: float | None
    bit_rate: int | None
    metadata: dict[str, str]
    streams: tuple[MediaStreamInfo, ...]
    warnings: tuple[str, ...]
    library: str
    library_version: str


class MediaInspector:
    def __init__(self, *, timeout_seconds: int = 60) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("Inspection timeout must be between 1 and 600 seconds")
        self._timeout_seconds = timeout_seconds
        self._worker = Path(__file__).with_name("inspect_worker.py").resolve(strict=True)

    def inspect(self, evidence_path: Path) -> MediaInspection:
        candidate = Path(evidence_path)
        if candidate.is_symlink():
            raise MediaInspectionError("Evidence path is not a safe regular file")
        path = candidate.resolve(strict=True)
        if not path.is_file():
            raise MediaInspectionError("Evidence path is not a safe regular file")
        environment = {"LC_ALL": "C", "PYTHONIOENCODING": "utf-8"}
        try:
            result = subprocess.run(  # noqa: S603 - fixed worker, no shell interpolation
                [sys.executable, "-I", str(self._worker), str(path)],
                cwd=path.parent,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise MediaInspectionError("Media inspection exceeded its time limit") from exc
        except OSError as exc:
            raise MediaInspectionError("Media inspection worker could not start") from exc
        if len(result.stdout) > 2 * 1024 * 1024:
            raise MediaInspectionError("Media inspection returned excessive metadata")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise MediaInspectionError("Media inspection returned an invalid result") from exc
        if result.returncode != 0:
            detail = str(payload.get("detail") or payload.get("error") or "unknown error")
            raise MediaInspectionError(f"Media inspection failed: {detail}")
        try:
            return _inspection_from_payload(payload)
        except (KeyError, TypeError, ValueError) as exc:
            raise MediaInspectionError("Media inspection result was incomplete") from exc


def _inspection_from_payload(payload: dict[str, Any]) -> MediaInspection:
    streams = tuple(
        MediaStreamInfo(
            index=int(stream["index"]),
            type=str(stream["type"]),
            codec_name=_optional_str(stream.get("codec_name")),
            codec_long_name=_optional_str(stream.get("codec_long_name")),
            duration_seconds=_optional_float(stream.get("duration_seconds")),
            start_time_seconds=_optional_float(stream.get("start_time_seconds")),
            frame_count=_optional_int(stream.get("frame_count")),
            time_base=_optional_str(stream.get("time_base")),
            width=_optional_int(stream.get("width")),
            height=_optional_int(stream.get("height")),
            pixel_format=_optional_str(stream.get("pixel_format")),
            average_frame_rate=_optional_float(stream.get("average_frame_rate")),
            sample_rate=_optional_int(stream.get("sample_rate")),
            channels=_optional_int(stream.get("channels")),
            metadata=_string_mapping(stream.get("metadata", {})),
        )
        for stream in payload["streams"]
    )
    if not streams:
        raise ValueError("Inspection requires at least one media stream")
    return MediaInspection(
        format_name=str(payload["format_name"]),
        format_long_name=str(payload["format_long_name"]),
        duration_seconds=_optional_float(payload.get("duration_seconds")),
        start_time_seconds=_optional_float(payload.get("start_time_seconds")),
        bit_rate=_optional_int(payload.get("bit_rate")),
        metadata=_string_mapping(payload.get("metadata", {})),
        streams=streams,
        warnings=tuple(str(value) for value in payload.get("warnings", [])),
        library=str(payload["library"]),
        library_version=str(payload["library_version"]),
    )


def inspection_to_payload(inspection: MediaInspection) -> dict[str, Any]:
    return {
        "format_name": inspection.format_name,
        "format_long_name": inspection.format_long_name,
        "duration_seconds": inspection.duration_seconds,
        "start_time_seconds": inspection.start_time_seconds,
        "bit_rate": inspection.bit_rate,
        "metadata": inspection.metadata,
        "streams": [
            {
                "index": stream.index,
                "type": stream.type,
                "codec_name": stream.codec_name,
                "codec_long_name": stream.codec_long_name,
                "duration_seconds": stream.duration_seconds,
                "start_time_seconds": stream.start_time_seconds,
                "frame_count": stream.frame_count,
                "time_base": stream.time_base,
                "width": stream.width,
                "height": stream.height,
                "pixel_format": stream.pixel_format,
                "average_frame_rate": stream.average_frame_rate,
                "sample_rate": stream.sample_rate,
                "channels": stream.channels,
                "metadata": stream.metadata,
            }
            for stream in inspection.streams
        ],
        "warnings": list(inspection.warnings),
        "library": inspection.library,
        "library_version": inspection.library_version,
    }


def _optional_str(value: object) -> str | None:
    return None if value is None else str(value)


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float, str)):
        return int(value)
    raise TypeError("Expected an integer-compatible value")


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float, str)):
        return float(value)
    raise TypeError("Expected a number-compatible value")


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TypeError("Metadata must be an object")
    return {str(key): str(item) for key, item in value.items()}
