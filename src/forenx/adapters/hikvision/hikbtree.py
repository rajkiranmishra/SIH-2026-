from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum

from forenx.adapters.base import ReadableEvidence
from forenx.adapters.hikvision.structures import HikvisionFormatError

HIKBTREE_SIGNATURE = b"HIKBTREE"
HIKBTREE_HEADER_SIZE = 0x60
HIKBTREE_PAGE_SIZE = 4096
HIKBTREE_ENTRY_SIZE = 48
HIKBTREE_ENTRY_MARKER = b"\xff" * 8
HIKBTREE_VIDEO_STATUS = bytes(8)
HIKBTREE_EMPTY_STATUS = b"\xff" * 8
HIKBTREE_SENTINEL_TIMESTAMP = 0x7FFFFFFF


class HikvisionEntryState(StrEnum):
    VIDEO = "video"
    EMPTY = "empty"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class HikbtreeHeader:
    signature_offset: int
    version_raw: bytes
    created_time_raw: int
    footer_offset: int
    page_list_offset: int
    first_page_offset: int
    header_size: int
    declared_block_count: int

    @property
    def version(self) -> str:
        return self.version_raw.rstrip(b"\x00").decode("ascii", errors="replace")


@dataclass(frozen=True, slots=True)
class HikbtreeDataEntry:
    metadata_offset: int
    page_offset: int
    status_raw: bytes
    channel: int
    start_time_raw: int
    end_time_raw: int
    data_offset: int

    def __post_init__(self) -> None:
        if self.metadata_offset < 0 or self.page_offset < 0 or self.data_offset < 0:
            raise ValueError("HIKBTREE offsets cannot be negative")
        if len(self.status_raw) != 8:
            raise ValueError("HIKBTREE status must preserve exactly eight bytes")
        if not 0 <= self.channel <= 255:
            raise ValueError("HIKBTREE channel must fit in one byte")

    @property
    def state(self) -> HikvisionEntryState:
        if self.status_raw == HIKBTREE_VIDEO_STATUS:
            return HikvisionEntryState.VIDEO
        if self.status_raw == HIKBTREE_EMPTY_STATUS:
            return HikvisionEntryState.EMPTY
        return HikvisionEntryState.UNKNOWN

    @property
    def is_partial(self) -> bool:
        return self.state is HikvisionEntryState.VIDEO and (
            self.start_time_raw == HIKBTREE_SENTINEL_TIMESTAMP
            or self.end_time_raw == HIKBTREE_SENTINEL_TIMESTAMP
        )


@dataclass(frozen=True, slots=True)
class HikbtreeParseResult:
    header: HikbtreeHeader
    page_list_entry_offset: int
    page_offsets: tuple[int, ...]
    entries: tuple[HikbtreeDataEntry, ...]
    warnings: tuple[str, ...]


class HikvisionHikbtreeParser:
    """Bounded parser for the observed 48-byte HIKBTREE firmware family."""

    PAGE_LIST_ENTRY_OFFSETS = (80, 96)
    PAGE_ENTRY_OFFSETS = (80, 96)
    MAX_PAGES = 4096
    MAX_ENTRIES = 250_000

    def __init__(
        self,
        source: ReadableEvidence,
        *,
        filesystem_base_offset: int,
        max_pages: int = MAX_PAGES,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        if filesystem_base_offset < 0 or filesystem_base_offset > source.size:
            raise HikvisionFormatError("Filesystem base is outside the evidence image")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages <= 0:
            raise ValueError("Maximum HIKBTREE page count must be a positive integer")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("Maximum HIKBTREE entry count must be a positive integer")
        self._source = source
        self._filesystem_base_offset = filesystem_base_offset
        self._max_pages = max_pages
        self._max_entries = max_entries

    def parse(self, tree_offset: int) -> HikbtreeParseResult:
        header = self._parse_header(tree_offset)
        page_list_absolute = self._absolute_offset(
            header.page_list_offset, 4, "HIKBTREE page list"
        )
        declared_pages = _read_u32(self._source.read_at(page_list_absolute, 4), 0)
        if declared_pages > self._max_pages:
            raise HikvisionFormatError(
                f"HIKBTREE declares {declared_pages} pages, exceeding the "
                f"configured limit of {self._max_pages}"
            )

        if declared_pages == 0:
            return HikbtreeParseResult(
                header=header,
                page_list_entry_offset=self.PAGE_LIST_ENTRY_OFFSETS[0],
                page_offsets=(),
                entries=(),
                warnings=("HIKBTREE page list declares zero pages",),
            )

        page_list_entry_offset = self._select_page_list_entry_offset(
            page_list_absolute,
            header.first_page_offset,
        )
        warnings: list[str] = []
        page_offsets = self._read_page_offsets(
            page_list_absolute,
            page_list_entry_offset,
            declared_pages,
            warnings,
        )

        entries: list[HikbtreeDataEntry] = []
        for page_offset in page_offsets:
            page_absolute = self._absolute_offset(
                page_offset, HIKBTREE_PAGE_SIZE, "HIKBTREE page"
            )
            page_data = self._source.read_at(page_absolute, HIKBTREE_PAGE_SIZE)
            entry_offset = self._select_page_entry_offset(page_data)
            if entry_offset is None:
                warnings.append(
                    f"Page at 0x{page_absolute:x} has no unambiguous 48-byte entry layout"
                )
                continue

            self._parse_page_entries(
                page_data,
                page_absolute,
                entry_offset,
                entries,
                warnings,
            )

        return HikbtreeParseResult(
            header=header,
            page_list_entry_offset=page_list_entry_offset,
            page_offsets=tuple(page_offsets),
            entries=tuple(entries),
            warnings=tuple(warnings),
        )

    def _parse_header(self, tree_offset: int) -> HikbtreeHeader:
        tree_base = self._absolute_offset(tree_offset, 0, "HIKBTREE base")
        signature_offset: int | None = None
        for adjustment in (0, 16):
            candidate = tree_base + adjustment
            if self._contains(candidate, len(HIKBTREE_SIGNATURE)) and (
                self._source.read_at(candidate, len(HIKBTREE_SIGNATURE))
                == HIKBTREE_SIGNATURE
            ):
                signature_offset = candidate
                break

        if signature_offset is None:
            raise HikvisionFormatError(
                f"HIKBTREE signature is absent at declared offset 0x{tree_base:x} "
                "and its observed +16-byte variant"
            )
        if not self._contains(signature_offset, HIKBTREE_HEADER_SIZE):
            raise HikvisionFormatError("HIKBTREE header is truncated")

        data = self._source.read_at(signature_offset, HIKBTREE_HEADER_SIZE)
        return HikbtreeHeader(
            signature_offset=signature_offset,
            version_raw=data[0x10:0x20],
            created_time_raw=_read_u32(data, 0x2C),
            footer_offset=_read_u64(data, 0x30),
            page_list_offset=_read_u64(data, 0x40),
            first_page_offset=_read_u64(data, 0x48),
            header_size=_read_u32(data, 0x50),
            declared_block_count=_read_u64(data, 0x58),
        )

    def _select_page_list_entry_offset(
        self,
        page_list_absolute: int,
        expected_first_page_offset: int,
    ) -> int:
        candidates: list[tuple[int, int]] = []
        for entry_offset in self.PAGE_LIST_ENTRY_OFFSETS:
            absolute = page_list_absolute + entry_offset
            if not self._contains(absolute, HIKBTREE_ENTRY_SIZE):
                continue
            relative_page = _read_u64(self._source.read_at(absolute, HIKBTREE_ENTRY_SIZE), 0)
            if relative_page in (0, 0xFFFFFFFFFFFFFFFF):
                continue
            page_absolute = self._filesystem_base_offset + relative_page
            if self._contains(page_absolute, HIKBTREE_PAGE_SIZE):
                candidates.append((entry_offset, relative_page))

        exact = [
            entry_offset
            for entry_offset, relative_page in candidates
            if relative_page == expected_first_page_offset
        ]
        if len(exact) == 1:
            return exact[0]
        if len(candidates) == 1:
            return candidates[0][0]
        raise HikvisionFormatError(
            "HIKBTREE page-list layout is missing or ambiguous; refusing to guess"
        )

    def _read_page_offsets(
        self,
        page_list_absolute: int,
        entry_offset: int,
        declared_pages: int,
        warnings: list[str],
    ) -> list[int]:
        page_offsets: list[int] = []
        seen: set[int] = set()
        for index in range(declared_pages):
            absolute = page_list_absolute + entry_offset + index * HIKBTREE_ENTRY_SIZE
            if not self._contains(absolute, HIKBTREE_ENTRY_SIZE):
                warnings.append(f"Page-list entry {index + 1} is truncated")
                break
            relative_page = _read_u64(self._source.read_at(absolute, HIKBTREE_ENTRY_SIZE), 0)
            if relative_page in (0, 0xFFFFFFFFFFFFFFFF):
                warnings.append(f"Page-list entry {index + 1} has an empty page pointer")
                continue
            page_absolute = self._filesystem_base_offset + relative_page
            if not self._contains(page_absolute, HIKBTREE_PAGE_SIZE):
                warnings.append(f"Page-list entry {index + 1} points outside the image")
                continue
            if relative_page in seen:
                warnings.append(f"Page-list entry {index + 1} repeats an earlier page pointer")
                continue
            seen.add(relative_page)
            page_offsets.append(relative_page)
        return page_offsets

    def _select_page_entry_offset(self, page_data: bytes) -> int | None:
        scored: list[tuple[int, int]] = []
        for entry_offset in self.PAGE_ENTRY_OFFSETS:
            recognized = 0
            position = entry_offset
            while position + HIKBTREE_ENTRY_SIZE <= len(page_data):
                entry = page_data[position : position + HIKBTREE_ENTRY_SIZE]
                if entry[:8] != HIKBTREE_ENTRY_MARKER:
                    break
                if entry[8:16] not in (HIKBTREE_VIDEO_STATUS, HIKBTREE_EMPTY_STATUS):
                    break
                recognized += 1
                position += HIKBTREE_ENTRY_SIZE
            scored.append((recognized, entry_offset))

        best_score = max(score for score, _ in scored)
        winners = [entry_offset for score, entry_offset in scored if score == best_score]
        if best_score == 0 or len(winners) != 1:
            return None
        return winners[0]

    def _parse_page_entries(
        self,
        page_data: bytes,
        page_absolute: int,
        entry_offset: int,
        entries: list[HikbtreeDataEntry],
        warnings: list[str],
    ) -> None:
        position = entry_offset
        while position + HIKBTREE_ENTRY_SIZE <= len(page_data):
            if len(entries) >= self._max_entries:
                raise HikvisionFormatError(
                    f"HIKBTREE entry count exceeds the configured limit of {self._max_entries}"
                )
            data = page_data[position : position + HIKBTREE_ENTRY_SIZE]
            if data[:8] != HIKBTREE_ENTRY_MARKER:
                break
            entry = HikbtreeDataEntry(
                metadata_offset=page_absolute + position,
                page_offset=page_absolute,
                status_raw=data[8:16],
                channel=data[17],
                start_time_raw=_read_u32(data, 24),
                end_time_raw=_read_u32(data, 28),
                data_offset=_read_u64(data, 32),
            )
            if entry.state is HikvisionEntryState.UNKNOWN:
                warnings.append(
                    f"Entry at 0x{entry.metadata_offset:x} has an unknown status value"
                )
            entries.append(entry)
            position += HIKBTREE_ENTRY_SIZE

    def _absolute_offset(self, relative_offset: int, length: int, label: str) -> int:
        absolute = self._filesystem_base_offset + relative_offset
        if not self._contains(absolute, length):
            raise HikvisionFormatError(f"{label} is outside the available evidence image")
        return absolute

    def _contains(self, offset: int, length: int) -> bool:
        return (
            offset >= 0
            and length >= 0
            and offset <= self._source.size
            and length <= self._source.size - offset
        )


def _read_u64(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", data, offset)[0])


def _read_u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])
