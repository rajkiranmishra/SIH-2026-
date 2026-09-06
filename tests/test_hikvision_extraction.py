from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forenx.adapters import ExtractionError, PhysicalExtent, RecordingDescriptor
from forenx.adapters.base import RecordingState
from forenx.adapters.hikvision import HikvisionAdapter

H264_SPS = b"\x00\x00\x00\x01\x67\x64\x00\x1f"
H264_PPS_IDR = b"\x00\x00\x01\x68\xee\x00\x00\x01\x65\x88"


class MemoryEvidence:
    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise AssertionError("Extractor attempted an out-of-bounds read")
        return self._data[offset : offset + length]


def _recording(*extents: PhysicalExtent, recording_id: str = "hikvision-primary-0001"):
    return RecordingDescriptor(
        recording_id=recording_id,
        channel="1",
        start_time=datetime(2026, 9, 6, tzinfo=UTC),
        end_time=datetime(2026, 9, 6, 0, 1, tzinfo=UTC),
        timestamp_source="test",
        state=RecordingState.ACTIVE,
        extents=tuple(extents),
        confidence=0.9,
    )


def test_extraction_copies_extents_in_order_and_hashes_exact_output(tmp_path: Path):
    gap = b"do-not-copy"
    source_bytes = H264_SPS + gap + H264_PPS_IDR
    source = MemoryEvidence(source_bytes)
    recording = _recording(
        PhysicalExtent(offset=0, length=len(H264_SPS)),
        PhysicalExtent(offset=len(H264_SPS) + len(gap), length=len(H264_PPS_IDR)),
    )
    destination = tmp_path / "recording.h264"

    result = HikvisionAdapter().extract(source, recording, destination)

    expected = H264_SPS + H264_PPS_IDR
    assert destination.read_bytes() == expected
    assert result.output_path == destination.resolve()
    assert result.sha256 == hashlib.sha256(expected).hexdigest()
    assert result.bytes_written == len(expected)
    assert result.source_extents == recording.extents
    assert result.format_hint == "h264"
    assert any("SPS" in item for item in result.validation_evidence)
    assert any("source offset" in item for item in result.validation_evidence)
    assert destination.stat().st_mode & 0o777 == 0o600


def test_existing_destination_is_never_overwritten(tmp_path: Path):
    destination = tmp_path / "existing.bin"
    destination.write_bytes(b"original")
    source = MemoryEvidence(H264_SPS + H264_PPS_IDR)
    recording = _recording(PhysicalExtent(offset=0, length=source.size))

    with pytest.raises(ExtractionError, match="already exists"):
        HikvisionAdapter().extract(source, recording, destination)

    assert destination.read_bytes() == b"original"


def test_unvalidated_bitstream_is_rejected_without_creating_output(tmp_path: Path):
    source = MemoryEvidence(bytes(1024))
    recording = _recording(PhysicalExtent(offset=0, length=source.size))
    destination = tmp_path / "invalid.bin"

    with pytest.raises(ExtractionError, match="validation failed"):
        HikvisionAdapter().extract(source, recording, destination)

    assert not destination.exists()


def test_out_of_image_extent_is_rejected_before_output_creation(tmp_path: Path):
    source = MemoryEvidence(H264_SPS + H264_PPS_IDR)
    recording = _recording(PhysicalExtent(offset=source.size, length=1))
    destination = tmp_path / "invalid-extent.bin"

    with pytest.raises(ExtractionError, match="outside"):
        HikvisionAdapter().extract(source, recording, destination)

    assert not destination.exists()


def test_recording_from_another_adapter_is_rejected(tmp_path: Path):
    source = MemoryEvidence(H264_SPS + H264_PPS_IDR)
    recording = _recording(
        PhysicalExtent(offset=0, length=source.size),
        recording_id="dahua-0001",
    )

    with pytest.raises(ExtractionError, match="not produced"):
        HikvisionAdapter().extract(source, recording, tmp_path / "foreign.bin")


def test_missing_destination_directory_is_rejected(tmp_path: Path):
    source = MemoryEvidence(H264_SPS + H264_PPS_IDR)
    recording = _recording(PhysicalExtent(offset=0, length=source.size))

    with pytest.raises(ExtractionError, match="does not exist"):
        HikvisionAdapter().extract(source, recording, tmp_path / "missing" / "video.bin")


def test_failed_write_removes_only_the_new_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    source = MemoryEvidence(H264_SPS + H264_PPS_IDR)
    recording = _recording(PhysicalExtent(offset=0, length=source.size))
    destination = tmp_path / "failed.bin"

    def fail_write(descriptor: int, data: bytes | memoryview) -> int:
        del descriptor, data
        raise OSError("simulated write failure")

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises(OSError, match="simulated"):
        HikvisionAdapter().extract(source, recording, destination)

    assert not destination.exists()
