from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from forenx.adapters.base import (
    AdapterCapability,
    DvrFilesystemAdapter,
    ExtractionError,
    ExtractionResult,
    PhysicalExtent,
    ProbeEvidence,
    ProbeResult,
    ReadableEvidence,
    RecordingDescriptor,
    RecordingState,
)
from forenx.adapters.hikvision.hikbtree import (
    HikbtreeParseResult,
    HikvisionEntryState,
    HikvisionHikbtreeParser,
)
from forenx.adapters.hikvision.structures import (
    HIKVISION_SIGNATURE,
    MASTER_SECTOR_MIN_SIZE,
    HikvisionFormatError,
    HikvisionMasterSector,
)
from forenx.video.annexb import AnnexBValidationResult, validate_annex_b_chunks


class HikvisionAdapter(DvrFilesystemAdapter):
    """Read-only identification and metadata parsing for Hikvision disk images."""

    adapter_id = "hikvision"
    version = "0.1.0"
    vendor = "Hikvision"
    filesystem = "Hikvision proprietary DVR filesystem"

    DEFAULT_SCAN_LIMIT = 50 * 1024 * 1024
    DEFAULT_SCAN_CHUNK_SIZE = 1024 * 1024
    CODEC_SCAN_LIMIT = 4 * 1024 * 1024
    COPY_CHUNK_SIZE = 8 * 1024 * 1024

    def __init__(
        self,
        *,
        scan_limit: int = DEFAULT_SCAN_LIMIT,
        scan_chunk_size: int = DEFAULT_SCAN_CHUNK_SIZE,
    ) -> None:
        if isinstance(scan_limit, bool) or not isinstance(scan_limit, int) or scan_limit <= 0:
            raise ValueError("Scan limit must be a positive integer")
        if (
            isinstance(scan_chunk_size, bool)
            or not isinstance(scan_chunk_size, int)
            or scan_chunk_size < len(HIKVISION_SIGNATURE)
        ):
            raise ValueError(
                "Scan chunk size must be an integer at least as large as the signature"
            )
        self._scan_limit = scan_limit
        self._scan_chunk_size = scan_chunk_size

    def probe(self, source: ReadableEvidence) -> ProbeResult:
        signature_offset = self._find_signature(source)
        if signature_offset is None:
            return ProbeResult(
                adapter_id=self.adapter_id,
                vendor=self.vendor,
                filesystem=self.filesystem,
                confidence=0.0,
                evidence=(),
                capabilities=frozenset(),
                warnings=(
                    f"Hikvision signature was not observed in the first "
                    f"{min(source.size, self._scan_limit)} bytes",
                ),
            )

        evidence = [
            ProbeEvidence(
                description="Exact Hikvision filesystem signature",
                offset=signature_offset,
                observed_hex=HIKVISION_SIGNATURE.hex(),
            )
        ]

        try:
            filesystem_base_offset = self._filesystem_base_offset(source, signature_offset)
            master = self._read_master_sector(
                source,
                signature_offset,
                filesystem_base_offset,
            )
        except HikvisionFormatError as exc:
            return ProbeResult(
                adapter_id=self.adapter_id,
                vendor=self.vendor,
                filesystem=self.filesystem,
                confidence=0.55,
                evidence=tuple(evidence),
                capabilities=frozenset(),
                warnings=(str(exc),),
            )

        warnings = master.validate(source_size=source.size)
        evidence.append(
            ProbeEvidence(
                description="Observed little-endian video data-block size",
                offset=signature_offset + 0x78,
                observed_hex=master.data_block_size.to_bytes(8, "little").hex(),
            )
        )
        confidence = 0.95 if not warnings else 0.75

        return ProbeResult(
            adapter_id=self.adapter_id,
            vendor=self.vendor,
            filesystem=self.filesystem,
            confidence=confidence,
            evidence=tuple(evidence),
            capabilities=frozenset(
                {
                    AdapterCapability.DEVICE_METADATA,
                    AdapterCapability.ENUMERATE_ACTIVE,
                    AdapterCapability.EXTRACT,
                }
            ),
            warnings=warnings,
        )

    def parse_master_sector(self, source: ReadableEvidence) -> HikvisionMasterSector:
        """Locate and parse the master sector without reading referenced regions."""
        signature_offset = self._find_signature(source)
        if signature_offset is None:
            raise HikvisionFormatError("Hikvision filesystem signature was not found")
        filesystem_base_offset = self._filesystem_base_offset(source, signature_offset)
        return self._read_master_sector(source, signature_offset, filesystem_base_offset)

    def parse_primary_tree(self, source: ReadableEvidence) -> HikbtreeParseResult:
        master = self.parse_master_sector(source)
        parser = HikvisionHikbtreeParser(
            source,
            filesystem_base_offset=master.filesystem_base_offset,
        )
        return parser.parse(master.primary_tree_offset)

    def enumerate_recordings(self, source: ReadableEvidence) -> Sequence[RecordingDescriptor]:
        master = self.parse_master_sector(source)
        if master.data_block_size <= 0:
            raise HikvisionFormatError("Cannot enumerate recordings with a zero data-block size")

        parser = HikvisionHikbtreeParser(
            source,
            filesystem_base_offset=master.filesystem_base_offset,
        )
        tree = parser.parse(master.primary_tree_offset)
        recordings: list[RecordingDescriptor] = []
        for entry in tree.entries:
            if entry.state is not HikvisionEntryState.VIDEO:
                continue

            data_offset = master.filesystem_base_offset + entry.data_offset
            if (
                data_offset > source.size
                or master.data_block_size > source.size - data_offset
            ):
                continue

            warnings = [
                "DVR timezone is not established; Unix seconds are normalized as UTC"
            ]
            start_time = self._timestamp(entry.start_time_raw)
            end_time = self._timestamp(entry.end_time_raw)
            state = RecordingState.ACTIVE
            confidence = 0.85

            if entry.is_partial:
                warnings.append("HIKBTREE uses the partial/incomplete timestamp sentinel")
                state = RecordingState.UNCERTAIN
                confidence = 0.55
            elif start_time is None or end_time is None:
                warnings.append("One or both HIKBTREE timestamps are unset")
                state = RecordingState.UNCERTAIN
                confidence = 0.5
            elif end_time < start_time:
                warnings.append("HIKBTREE end time precedes its start time")
                end_time = None
                state = RecordingState.UNCERTAIN
                confidence = 0.4

            recordings.append(
                RecordingDescriptor(
                    recording_id=f"hikvision-primary-{entry.metadata_offset:016x}",
                    channel=str(entry.channel),
                    start_time=start_time,
                    end_time=end_time,
                    timestamp_source="hikbtree-unix-seconds-timezone-unverified",
                    state=state,
                    extents=(
                        PhysicalExtent(
                            offset=data_offset,
                            length=master.data_block_size,
                        ),
                    ),
                    confidence=confidence,
                    warnings=tuple(warnings),
                )
            )

        return tuple(recordings)

    def extract(
        self,
        source: ReadableEvidence,
        recording: RecordingDescriptor,
        destination: Path,
    ) -> ExtractionResult:
        if not recording.recording_id.startswith("hikvision-"):
            raise ExtractionError("Recording was not produced by the Hikvision adapter")
        self._validate_extents(source, recording)
        validation = self._validate_bitstream(source, recording)
        if not validation.is_valid or validation.codec is None:
            detail = validation.warnings[0] if validation.warnings else "Unknown bitstream"
            raise ExtractionError(f"Video block validation failed: {detail}")

        target = self._safe_destination(destination)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError as exc:
            raise ExtractionError("Extraction destination already exists") from exc
        except OSError as exc:
            raise ExtractionError(f"Cannot create extraction destination: {exc}") from exc

        digest = hashlib.sha256()
        bytes_written = 0
        try:
            for extent in recording.extents:
                position = extent.offset
                remaining = extent.length
                while remaining:
                    read_length = min(self.COPY_CHUNK_SIZE, remaining)
                    chunk = source.read_at(position, read_length)
                    self._write_all(descriptor, chunk)
                    digest.update(chunk)
                    position += read_length
                    remaining -= read_length
                    bytes_written += read_length
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            target.unlink(missing_ok=True)
            raise
        else:
            os.close(descriptor)

        observed_offsets = tuple(
            f"NAL header byte 0x{observation.header_byte:02x} at source offset "
            f"0x{observation.header_offset:x}"
            for observation in validation.observations[:16]
        )
        return ExtractionResult(
            output_path=target,
            sha256=digest.hexdigest(),
            bytes_written=bytes_written,
            source_extents=recording.extents,
            warnings=(
                *recording.warnings,
                "Exact source-block copy; no decoding or remuxing was performed",
            ),
            format_hint=validation.codec.value,
            validation_evidence=validation.evidence + observed_offsets,
        )

    def _validate_bitstream(
        self,
        source: ReadableEvidence,
        recording: RecordingDescriptor,
    ) -> AnnexBValidationResult:
        remaining_scan = self.CODEC_SCAN_LIMIT
        chunks: list[tuple[bytes, int]] = []
        for extent in recording.extents:
            if remaining_scan == 0:
                break
            read_length = min(extent.length, remaining_scan)
            chunks.append((source.read_at(extent.offset, read_length), extent.offset))
            remaining_scan -= read_length
        return validate_annex_b_chunks(chunks)

    @staticmethod
    def _validate_extents(
        source: ReadableEvidence,
        recording: RecordingDescriptor,
    ) -> None:
        for extent in recording.extents:
            if extent.offset > source.size or extent.length > source.size - extent.offset:
                raise ExtractionError("Recording extent is outside the evidence image")

    @staticmethod
    def _safe_destination(destination: Path) -> Path:
        path = Path(destination).expanduser()
        if not path.name:
            raise ExtractionError("Extraction destination must include a file name")
        try:
            parent = path.parent.resolve(strict=True)
        except OSError as exc:
            raise ExtractionError("Extraction destination directory does not exist") from exc
        if not parent.is_dir():
            raise ExtractionError("Extraction destination parent is not a directory")
        return parent / path.name

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise ExtractionError("Extraction destination returned a short write")
            remaining = remaining[written:]

    def _find_signature(self, source: ReadableEvidence) -> int | None:
        scan_length = min(source.size, self._scan_limit)
        overlap = b""
        position = 0

        while position < scan_length:
            read_length = min(self._scan_chunk_size, scan_length - position)
            chunk = source.read_at(position, read_length)
            searchable = overlap + chunk
            match_index = searchable.find(HIKVISION_SIGNATURE)
            if match_index >= 0:
                return position - len(overlap) + match_index

            overlap_size = min(len(HIKVISION_SIGNATURE) - 1, len(searchable))
            overlap = searchable[-overlap_size:]
            position += read_length

        return None

    @staticmethod
    def _read_master_sector(
        source: ReadableEvidence,
        signature_offset: int,
        filesystem_base_offset: int,
    ) -> HikvisionMasterSector:
        available = min(MASTER_SECTOR_MIN_SIZE, source.size - signature_offset)
        data = source.read_at(signature_offset, available)
        return HikvisionMasterSector.from_bytes(
            data,
            signature_offset=signature_offset,
            filesystem_base_offset=filesystem_base_offset,
        )

    @staticmethod
    def _filesystem_base_offset(source: ReadableEvidence, signature_offset: int) -> int:
        """Return the containing MBR partition start, or zero for a partition image."""
        if source.size < 512:
            return 0
        mbr = source.read_at(0, 512)
        if mbr[510:512] != b"\x55\xaa":
            return 0

        for index in range(4):
            entry_offset = 0x1BE + index * 16
            start_sector = int.from_bytes(mbr[entry_offset + 8 : entry_offset + 12], "little")
            sector_count = int.from_bytes(mbr[entry_offset + 12 : entry_offset + 16], "little")
            if start_sector == 0 or sector_count == 0:
                continue
            partition_start = start_sector * 512
            partition_end = partition_start + sector_count * 512
            if partition_start <= signature_offset < partition_end:
                return partition_start
        return 0

    @staticmethod
    def _timestamp(raw_timestamp: int) -> datetime | None:
        if raw_timestamp in (0, 0x7FFFFFFF, 0xFFFFFFFF):
            return None
        return datetime.fromtimestamp(raw_timestamp, tz=UTC)
