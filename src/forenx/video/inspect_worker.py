from __future__ import annotations

import json
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any

import av


def _seconds(value: int | None, time_base: Fraction | None) -> float | None:
    if value is None or time_base is None:
        return None
    return float(value * time_base)


def _safe_metadata(metadata: dict[str, str]) -> dict[str, str]:
    return {
        str(key)[:128]: str(value)[:2048]
        for key, value in list(metadata.items())[:64]
    }


def inspect(path: Path) -> dict[str, Any]:
    av.logging.set_level(av.logging.PANIC)
    with av.open(str(path), mode="r", metadata_errors="ignore") as container:
        streams: list[dict[str, Any]] = []
        for stream in container.streams:
            codec = stream.codec_context
            item: dict[str, Any] = {
                "index": stream.index,
                "type": stream.type,
                "codec_name": codec.name,
                "codec_long_name": codec.codec.long_name if codec.codec is not None else None,
                "duration_seconds": _seconds(stream.duration, stream.time_base),
                "start_time_seconds": _seconds(stream.start_time, stream.time_base),
                "frame_count": stream.frames or None,
                "time_base": str(stream.time_base) if stream.time_base is not None else None,
                "metadata": _safe_metadata(dict(stream.metadata)),
            }
            if stream.type == "video":
                average_rate = getattr(stream, "average_rate", None)
                item.update(
                    {
                        "width": getattr(codec, "width", None),
                        "height": getattr(codec, "height", None),
                        "pixel_format": getattr(codec, "pix_fmt", None),
                        "average_frame_rate": (
                            float(average_rate) if average_rate is not None else None
                        ),
                        "sample_rate": None,
                        "channels": None,
                    }
                )
            elif stream.type == "audio":
                item.update(
                    {
                        "width": None,
                        "height": None,
                        "pixel_format": None,
                        "average_frame_rate": None,
                        "sample_rate": getattr(codec, "sample_rate", None),
                        "channels": getattr(codec, "channels", None),
                    }
                )
            else:
                item.update(
                    {
                        "width": None,
                        "height": None,
                        "pixel_format": None,
                        "average_frame_rate": None,
                        "sample_rate": None,
                        "channels": None,
                    }
                )
            streams.append(item)

        format_name = container.format.name or "unknown"
        format_long_name = container.format.long_name or format_name
        duration_seconds = (
            float(container.duration / av.time_base)
            if container.duration is not None
            else None
        )
        return {
            "format_name": format_name,
            "format_long_name": format_long_name,
            "duration_seconds": duration_seconds,
            "start_time_seconds": (
                float(container.start_time / av.time_base)
                if container.start_time is not None
                else None
            ),
            "bit_rate": container.bit_rate,
            "metadata": _safe_metadata(dict(container.metadata)),
            "streams": streams,
            "warnings": [],
            "library": "PyAV",
            "library_version": av.__version__,
        }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "worker requires one evidence path"}))
        return 2
    try:
        payload = inspect(Path(sys.argv[1]))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": "media inspection failed",
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
