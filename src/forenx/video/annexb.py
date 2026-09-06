from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class VideoCodec(StrEnum):
    H264 = "h264"
    H265 = "h265"


@dataclass(frozen=True, slots=True)
class NalObservation:
    start_code_offset: int
    header_offset: int
    header_byte: int
    h264_type: int
    h265_type: int


@dataclass(frozen=True, slots=True)
class AnnexBValidationResult:
    codec: VideoCodec | None
    confidence: float
    bytes_scanned: int
    observations: tuple[NalObservation, ...]
    evidence: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def is_valid(self) -> bool:
        return self.codec is not None


def validate_annex_b(data: bytes, *, source_offset: int = 0) -> AnnexBValidationResult:
    return validate_annex_b_chunks(((data, source_offset),))


def validate_annex_b_chunks(
    chunks: Iterable[tuple[bytes, int]],
) -> AnnexBValidationResult:
    observations: list[NalObservation] = []
    bytes_scanned = 0
    for data, source_offset in chunks:
        if source_offset < 0:
            raise ValueError("Annex-B source offset cannot be negative")
        bytes_scanned += len(data)
        observations.extend(_observe_chunk(data, source_offset))

    h264_types = {observation.h264_type for observation in observations}
    h265_types = {observation.h265_type for observation in observations}
    h264_parameters = {7, 8}.issubset(h264_types)
    h265_parameters = {32, 33, 34}.issubset(h265_types)

    if h264_parameters and h265_parameters:
        return AnnexBValidationResult(
            codec=None,
            confidence=0.0,
            bytes_scanned=bytes_scanned,
            observations=tuple(observations),
            evidence=(),
            warnings=("Annex-B stream contains conflicting H.264 and H.265 parameter sets",),
        )

    if h264_parameters:
        has_idr = 5 in h264_types
        evidence = [
            "Observed H.264 SPS NAL unit (type 7)",
            "Observed H.264 PPS NAL unit (type 8)",
        ]
        if has_idr:
            evidence.append("Observed H.264 IDR picture NAL unit (type 5)")
        return AnnexBValidationResult(
            codec=VideoCodec.H264,
            confidence=0.98 if has_idr else 0.9,
            bytes_scanned=bytes_scanned,
            observations=tuple(observations),
            evidence=tuple(evidence),
            warnings=(),
        )

    if h265_parameters:
        has_idr = bool({19, 20} & h265_types)
        evidence = [
            "Observed H.265 VPS NAL unit (type 32)",
            "Observed H.265 SPS NAL unit (type 33)",
            "Observed H.265 PPS NAL unit (type 34)",
        ]
        if has_idr:
            evidence.append("Observed H.265 IDR picture NAL unit (type 19 or 20)")
        return AnnexBValidationResult(
            codec=VideoCodec.H265,
            confidence=0.98 if has_idr else 0.92,
            bytes_scanned=bytes_scanned,
            observations=tuple(observations),
            evidence=tuple(evidence),
            warnings=(),
        )

    return AnnexBValidationResult(
        codec=None,
        confidence=0.0,
        bytes_scanned=bytes_scanned,
        observations=tuple(observations),
        evidence=(),
        warnings=("No complete H.264 or H.265 Annex-B parameter-set sequence was observed",),
    )


def _observe_chunk(data: bytes, source_offset: int) -> list[NalObservation]:
    observations: list[NalObservation] = []
    position = 0
    while position + 3 < len(data):
        start_code_length = 0
        if data[position : position + 4] == b"\x00\x00\x00\x01":
            start_code_length = 4
        elif data[position : position + 3] == b"\x00\x00\x01":
            start_code_length = 3

        if start_code_length == 0:
            position += 1
            continue

        header_offset = position + start_code_length
        if header_offset >= len(data):
            break
        header_byte = data[header_offset]
        observations.append(
            NalObservation(
                start_code_offset=source_offset + position,
                header_offset=source_offset + header_offset,
                header_byte=header_byte,
                h264_type=header_byte & 0x1F,
                h265_type=(header_byte >> 1) & 0x3F,
            )
        )
        position = header_offset + 1
    return observations
