from __future__ import annotations

import struct
from datetime import UTC, datetime

import pytest

from forenx.adapters.base import RecordingState
from forenx.adapters.hikvision import (
    HIKBTREE_SIGNATURE,
    HIKVISION_SIGNATURE,
    HikbtreeDataEntry,
    HikvisionAdapter,
    HikvisionEntryState,
    HikvisionFormatError,
    HikvisionHikbtreeParser,
)

IMAGE_SIZE = 0x40000
MASTER_RELATIVE = 528
TREE_RELATIVE = 0x5000
PAGE_LIST_RELATIVE = 0x6000
PAGE_ONE_RELATIVE = 0x7000
PAGE_TWO_RELATIVE = 0x8000
VIDEO_ONE_RELATIVE = 0x10000
VIDEO_TWO_RELATIVE = 0x12000
BLOCK_SIZE = 0x1000
START_TIME = 1_725_523_200
END_TIME = START_TIME + 300


class MemoryEvidence:
    def __init__(self, data: bytes) -> None:
        self._data = data

    @property
    def size(self) -> int:
        return len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.size or length > self.size - offset:
            raise AssertionError("Parser attempted an out-of-bounds read")
        return self._data[offset : offset + length]


def _write_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def _write_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def _write_video_entry(
    data: bytearray,
    *,
    absolute_offset: int,
    status: bytes,
    channel: int,
    start_time: int,
    end_time: int,
    data_offset: int,
) -> None:
    data[absolute_offset : absolute_offset + 8] = b"\xff" * 8
    data[absolute_offset + 8 : absolute_offset + 16] = status
    data[absolute_offset + 17] = channel
    _write_u32(data, absolute_offset + 24, start_time)
    _write_u32(data, absolute_offset + 28, end_time)
    _write_u64(data, absolute_offset + 32, data_offset)


def _build_tree_image(*, filesystem_base: int = 0, with_mbr: bool = False) -> bytearray:
    data = bytearray(IMAGE_SIZE)
    if with_mbr:
        start_sector = filesystem_base // 512
        sector_count = (IMAGE_SIZE - filesystem_base) // 512
        partition_entry = 0x1BE
        data[partition_entry + 4] = 0x83
        _write_u32(data, partition_entry + 8, start_sector)
        _write_u32(data, partition_entry + 12, sector_count)
        data[510:512] = b"\x55\xaa"

    master = filesystem_base + MASTER_RELATIVE
    data[master : master + len(HIKVISION_SIGNATURE)] = HIKVISION_SIGNATURE
    master_fields = {
        0x38: IMAGE_SIZE,
        0x50: 0x1000,
        0x58: 0x1000,
        0x68: VIDEO_ONE_RELATIVE,
        0x78: BLOCK_SIZE,
        0x80: 16,
        0x88: TREE_RELATIVE,
        0x90: 0x1000,
        0x98: 0x9000,
        0xA0: 0x1000,
    }
    for field_offset, value in master_fields.items():
        _write_u64(data, master + field_offset, value)
    _write_u32(data, master + 0xE0, START_TIME)

    tree = filesystem_base + TREE_RELATIVE + 16
    data[tree : tree + len(HIKBTREE_SIGNATURE)] = HIKBTREE_SIGNATURE
    data[tree + 0x10 : tree + 0x20] = b"HIK.2011.03.08\x00"
    _write_u32(data, tree + 0x2C, START_TIME)
    _write_u64(data, tree + 0x30, 0xA000)
    _write_u64(data, tree + 0x40, PAGE_LIST_RELATIVE)
    _write_u64(data, tree + 0x48, PAGE_ONE_RELATIVE)
    _write_u32(data, tree + 0x50, 0x60)
    _write_u64(data, tree + 0x58, 3)

    page_list = filesystem_base + PAGE_LIST_RELATIVE
    _write_u32(data, page_list, 2)
    _write_u64(data, page_list + 80, PAGE_ONE_RELATIVE)
    _write_u64(data, page_list + 80 + 48, PAGE_TWO_RELATIVE)

    page_one = filesystem_base + PAGE_ONE_RELATIVE
    _write_video_entry(
        data,
        absolute_offset=page_one + 80,
        status=bytes(8),
        channel=2,
        start_time=START_TIME,
        end_time=END_TIME,
        data_offset=VIDEO_ONE_RELATIVE,
    )
    _write_video_entry(
        data,
        absolute_offset=page_one + 80 + 48,
        status=b"\xff" * 8,
        channel=2,
        start_time=0,
        end_time=0,
        data_offset=0,
    )

    page_two = filesystem_base + PAGE_TWO_RELATIVE
    _write_video_entry(
        data,
        absolute_offset=page_two + 96,
        status=bytes(8),
        channel=4,
        start_time=0x7FFFFFFF,
        end_time=0x7FFFFFFF,
        data_offset=VIDEO_TWO_RELATIVE,
    )
    return data


def test_parser_supports_observed_80_and_96_byte_page_variants():
    result = HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(_build_tree_image())))

    assert result.header.signature_offset == TREE_RELATIVE + 16
    assert result.header.version == "HIK.2011.03.08"
    assert result.header.declared_block_count == 3
    assert result.page_list_entry_offset == 80
    assert result.page_offsets == (PAGE_ONE_RELATIVE, PAGE_TWO_RELATIVE)
    assert len(result.entries) == 3
    assert result.entries[0].state is HikvisionEntryState.VIDEO
    assert result.entries[1].state is HikvisionEntryState.EMPTY
    assert result.entries[2].is_partial
    assert result.warnings == ()


def test_parser_supports_96_byte_page_list_variant():
    data = _build_tree_image()
    page_list = PAGE_LIST_RELATIVE
    data[page_list + 80 : page_list + 192] = bytes(112)
    _write_u64(data, page_list + 96, PAGE_ONE_RELATIVE)
    _write_u64(data, page_list + 96 + 48, PAGE_TWO_RELATIVE)

    result = HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))

    assert result.page_list_entry_offset == 96
    assert result.page_offsets == (PAGE_ONE_RELATIVE, PAGE_TWO_RELATIVE)


def test_recording_enumeration_returns_only_video_entries_with_provenance():
    recordings = HikvisionAdapter().enumerate_recordings(
        MemoryEvidence(bytes(_build_tree_image()))
    )

    assert len(recordings) == 2
    complete, partial = recordings
    assert complete.channel == "2"
    assert complete.start_time == datetime.fromtimestamp(START_TIME, tz=UTC)
    assert complete.end_time == datetime.fromtimestamp(END_TIME, tz=UTC)
    assert complete.state is RecordingState.ACTIVE
    assert complete.extents[0].offset == VIDEO_ONE_RELATIVE
    assert complete.extents[0].length == BLOCK_SIZE
    assert complete.confidence == 0.85
    assert "timezone" in complete.warnings[0]

    assert partial.channel == "4"
    assert partial.start_time is None
    assert partial.end_time is None
    assert partial.state is RecordingState.UNCERTAIN
    assert partial.confidence == 0.55
    assert any("partial/incomplete" in warning for warning in partial.warnings)


def test_mbr_partition_base_is_applied_to_tree_pages_and_video_extents():
    filesystem_base = 0x1000
    source = MemoryEvidence(
        bytes(_build_tree_image(filesystem_base=filesystem_base, with_mbr=True))
    )
    adapter = HikvisionAdapter()

    master = adapter.parse_master_sector(source)
    recordings = adapter.enumerate_recordings(source)

    assert master.filesystem_base_offset == filesystem_base
    assert recordings[0].extents[0].offset == filesystem_base + VIDEO_ONE_RELATIVE


def test_excessive_declared_page_count_is_rejected_before_page_reads():
    data = _build_tree_image()
    _write_u32(data, PAGE_LIST_RELATIVE, HikvisionHikbtreeParser.MAX_PAGES + 1)

    with pytest.raises(HikvisionFormatError, match="exceeding"):
        HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))


def test_ambiguous_page_list_layout_is_rejected_instead_of_guessed():
    data = _build_tree_image()
    tree = TREE_RELATIVE + 16
    _write_u64(data, tree + 0x48, 0xA000)
    _write_u64(data, PAGE_LIST_RELATIVE + 96, PAGE_TWO_RELATIVE)

    with pytest.raises(HikvisionFormatError, match="ambiguous"):
        HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))


def test_missing_tree_signature_is_reported_explicitly():
    data = _build_tree_image()
    tree = TREE_RELATIVE + 16
    data[tree : tree + len(HIKBTREE_SIGNATURE)] = bytes(len(HIKBTREE_SIGNATURE))

    with pytest.raises(HikvisionFormatError, match="signature is absent"):
        HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))


def test_tree_signature_at_exact_declared_offset_is_supported():
    data = _build_tree_image()
    tree = TREE_RELATIVE
    header = bytes(data[tree + 16 : tree + 16 + 0x60])
    data[tree : tree + 16 + 0x60] = bytes(16 + 0x60)
    data[tree : tree + 0x60] = header

    result = HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))

    assert result.header.signature_offset == TREE_RELATIVE


def test_out_of_image_video_extent_is_not_enumerated():
    data = _build_tree_image()
    _write_u64(data, PAGE_ONE_RELATIVE + 80 + 32, IMAGE_SIZE + 1)

    recordings = HikvisionAdapter().enumerate_recordings(MemoryEvidence(bytes(data)))

    assert len(recordings) == 1
    assert recordings[0].channel == "4"


def test_zero_page_tree_returns_an_explicit_warning():
    data = _build_tree_image()
    _write_u32(data, PAGE_LIST_RELATIVE, 0)

    result = HikvisionAdapter().parse_primary_tree(MemoryEvidence(bytes(data)))

    assert result.entries == ()
    assert result.warnings == ("HIKBTREE page list declares zero pages",)


def test_reversed_timestamps_are_preserved_as_an_uncertain_recording():
    data = _build_tree_image()
    _write_u32(data, PAGE_ONE_RELATIVE + 80 + 28, START_TIME - 1)

    recording = HikvisionAdapter().enumerate_recordings(MemoryEvidence(bytes(data)))[0]

    assert recording.start_time == datetime.fromtimestamp(START_TIME, tz=UTC)
    assert recording.end_time is None
    assert recording.state is RecordingState.UNCERTAIN
    assert recording.confidence == 0.4
    assert any("precedes" in warning for warning in recording.warnings)


def test_entry_preserves_unknown_status_without_calling_it_video():
    entry = HikbtreeDataEntry(
        metadata_offset=1,
        page_offset=0,
        status_raw=b"unknown!",
        channel=1,
        start_time_raw=START_TIME,
        end_time_raw=END_TIME,
        data_offset=VIDEO_ONE_RELATIVE,
    )

    assert entry.state is HikvisionEntryState.UNKNOWN
    assert not entry.is_partial


@pytest.mark.parametrize(
    ("filesystem_base", "max_pages", "max_entries", "message"),
    [
        (-1, 1, 1, "Filesystem base"),
        (0, 0, 1, "page count"),
        (0, 1, 0, "entry count"),
    ],
)
def test_parser_rejects_unsafe_limits(
    filesystem_base: int,
    max_pages: int,
    max_entries: int,
    message: str,
):
    with pytest.raises((ValueError, HikvisionFormatError), match=message):
        HikvisionHikbtreeParser(
            MemoryEvidence(bytes(512)),
            filesystem_base_offset=filesystem_base,
            max_pages=max_pages,
            max_entries=max_entries,
        )
