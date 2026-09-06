from __future__ import annotations

import struct

import pytest

from forenx.adapters.base import AdapterCapability
from forenx.adapters.hikvision import (
    HIKVISION_SIGNATURE,
    HikvisionAdapter,
    HikvisionFormatError,
    HikvisionMasterSector,
)


class MemoryEvidence:
    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise ValueError("Out-of-bounds test read")
        return self._data[offset : offset + length]


def _build_valid_image(*, signature_offset: int = 528, size: int = 0x20000) -> bytes:
    data = bytearray(size)
    data[signature_offset : signature_offset + len(HIKVISION_SIGNATURE)] = HIKVISION_SIGNATURE
    filesystem_size = size - signature_offset
    fields_u64 = {
        0x38: filesystem_size,
        0x50: 0x1000,
        0x58: 0x1000,
        0x68: 0x4000,
        0x78: 0x1000,
        0x80: 8,
        0x88: 0x2000,
        0x90: 0x1000,
        0x98: 0x3000,
        0xA0: 0x1000,
    }
    for field_offset, value in fields_u64.items():
        struct.pack_into("<Q", data, signature_offset + field_offset, value)
    struct.pack_into("<I", data, signature_offset + 0xE0, 1_725_523_200)
    return bytes(data)


def test_probe_recognizes_valid_master_sector_and_reports_observed_bytes():
    source = MemoryEvidence(_build_valid_image())

    result = HikvisionAdapter().probe(source)

    assert result.confidence == 0.95
    assert result.warnings == ()
    assert result.capabilities == frozenset(
        {
            AdapterCapability.DEVICE_METADATA,
            AdapterCapability.ENUMERATE_ACTIVE,
            AdapterCapability.EXTRACT,
        }
    )
    assert result.evidence[0].offset == 528
    assert result.evidence[0].observed_hex == HIKVISION_SIGNATURE.hex()
    assert result.evidence[1].offset == 528 + 0x78
    assert result.evidence[1].observed_hex == (0x1000).to_bytes(8, "little").hex()


def test_parse_master_sector_preserves_raw_vendor_fields():
    master = HikvisionAdapter().parse_master_sector(MemoryEvidence(_build_valid_image()))

    assert master.signature_offset == 528
    assert master.video_data_offset == 0x4000
    assert master.data_block_size == 0x1000
    assert master.total_data_blocks == 8
    assert master.primary_tree_offset == 0x2000
    assert master.secondary_tree_offset == 0x3000
    assert master.initialization_time_raw == 1_725_523_200


def test_signature_detection_handles_a_chunk_boundary():
    image = _build_valid_image(signature_offset=59)
    adapter = HikvisionAdapter(scan_chunk_size=64)

    result = adapter.probe(MemoryEvidence(image))

    assert result.confidence == 0.95
    assert result.evidence[0].offset == 59


def test_missing_signature_is_not_reported_as_vendor_support():
    result = HikvisionAdapter(scan_limit=1024).probe(MemoryEvidence(bytes(2048)))

    assert result.confidence == 0.0
    assert result.evidence == ()
    assert result.capabilities == frozenset()
    assert "first 1024 bytes" in result.warnings[0]


def test_signature_outside_scan_limit_is_not_followed():
    result = HikvisionAdapter(scan_limit=512).probe(
        MemoryEvidence(_build_valid_image(signature_offset=528))
    )

    assert result.confidence == 0.0


def test_truncated_master_sector_keeps_confidence_low_and_capabilities_empty():
    source = MemoryEvidence(HIKVISION_SIGNATURE + bytes(12))

    result = HikvisionAdapter().probe(source)

    assert result.confidence == 0.55
    assert result.capabilities == frozenset()
    assert "truncated" in result.warnings[0]


def test_parse_rejects_missing_or_truncated_master_sector():
    adapter = HikvisionAdapter()
    with pytest.raises(HikvisionFormatError, match="not found"):
        adapter.parse_master_sector(MemoryEvidence(bytes(512)))
    with pytest.raises(HikvisionFormatError, match="truncated"):
        adapter.parse_master_sector(MemoryEvidence(HIKVISION_SIGNATURE))


def test_untrusted_large_offsets_only_produce_warnings():
    data = bytearray(_build_valid_image())
    signature_offset = 528
    struct.pack_into("<Q", data, signature_offset + 0x68, 2**63)
    struct.pack_into("<Q", data, signature_offset + 0x78, 2**63)
    struct.pack_into("<Q", data, signature_offset + 0x88, 2**63)

    result = HikvisionAdapter().probe(MemoryEvidence(bytes(data)))

    assert result.confidence == 0.75
    assert any("Video-data offset" in warning for warning in result.warnings)
    assert any("one-GiB" in warning for warning in result.warnings)
    assert any("Primary HIKBTREE" in warning for warning in result.warnings)


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("scan_limit", 0),
        ("scan_limit", True),
        ("scan_chunk_size", len(HIKVISION_SIGNATURE) - 1),
    ],
)
def test_adapter_rejects_unsafe_scan_configuration(keyword: str, value: int):
    with pytest.raises(ValueError, match="Scan"):
        HikvisionAdapter(**{keyword: value})  # type: ignore[arg-type]


def test_structure_rejects_negative_signature_offset():
    image = _build_valid_image(signature_offset=0)
    with pytest.raises(HikvisionFormatError, match="negative"):
        HikvisionMasterSector.from_bytes(image[:0xE4], signature_offset=-1)
