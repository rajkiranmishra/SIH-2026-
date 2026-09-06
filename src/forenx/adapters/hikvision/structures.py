from __future__ import annotations

import struct
from dataclasses import dataclass

HIKVISION_SIGNATURE = b"HIKVISION@HANGZHOU"
MASTER_SECTOR_MIN_SIZE = 0xE4


class HikvisionFormatError(ValueError):
    """Raised when observable bytes do not form a supported Hikvision structure."""


@dataclass(frozen=True, slots=True)
class HikvisionMasterSector:
    """Empirically documented fields from a Hikvision DVR master sector.

    Referenced offsets stored in the structure are relative to the containing
    partition, not necessarily to the master-sector signature. Raw values are
    preserved so reports can distinguish observed bytes from interpretation.
    """

    signature_offset: int
    filesystem_base_offset: int
    hdd_capacity: int
    system_log_offset: int
    system_log_size: int
    video_data_offset: int
    data_block_size: int
    total_data_blocks: int
    primary_tree_offset: int
    primary_tree_size: int
    secondary_tree_offset: int
    secondary_tree_size: int
    initialization_time_raw: int

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        signature_offset: int,
        filesystem_base_offset: int = 0,
    ) -> HikvisionMasterSector:
        if signature_offset < 0:
            raise HikvisionFormatError("Signature offset cannot be negative")
        if filesystem_base_offset < 0 or filesystem_base_offset > signature_offset:
            raise HikvisionFormatError(
                "Filesystem base offset must be non-negative and precede the signature"
            )
        if len(data) < MASTER_SECTOR_MIN_SIZE:
            raise HikvisionFormatError(
                f"Master sector is truncated: need {MASTER_SECTOR_MIN_SIZE} bytes, "
                f"observed {len(data)}"
            )
        if data[: len(HIKVISION_SIGNATURE)] != HIKVISION_SIGNATURE:
            raise HikvisionFormatError("Hikvision master-sector signature is missing")

        return cls(
            signature_offset=signature_offset,
            filesystem_base_offset=filesystem_base_offset,
            hdd_capacity=_read_u64(data, 0x38),
            system_log_offset=_read_u64(data, 0x50),
            system_log_size=_read_u64(data, 0x58),
            video_data_offset=_read_u64(data, 0x68),
            data_block_size=_read_u64(data, 0x78),
            total_data_blocks=_read_u64(data, 0x80),
            primary_tree_offset=_read_u64(data, 0x88),
            primary_tree_size=_read_u64(data, 0x90),
            secondary_tree_offset=_read_u64(data, 0x98),
            secondary_tree_size=_read_u64(data, 0xA0),
            initialization_time_raw=_read_u32(data, 0xE0),
        )

    def validate(self, *, source_size: int) -> tuple[str, ...]:
        """Return bounded-layout warnings without following any vendor offsets."""
        if source_size < 0:
            raise ValueError("Source size cannot be negative")

        warnings: list[str] = []
        if self.filesystem_base_offset > source_size:
            return ("Filesystem base offset is outside the available evidence image",)
        filesystem_bytes = source_size - self.filesystem_base_offset

        if self.hdd_capacity == 0:
            warnings.append("Declared HDD capacity is zero")
        elif self.hdd_capacity > source_size:
            warnings.append("Declared HDD capacity exceeds the available evidence image")

        if self.video_data_offset >= filesystem_bytes:
            warnings.append("Video-data offset is outside the available evidence image")

        if self.data_block_size == 0:
            warnings.append("Video data-block size is zero")
        else:
            if self.data_block_size % 512 != 0:
                warnings.append("Video data-block size is not sector aligned")
            if self.data_block_size > 1024 * 1024 * 1024:
                warnings.append("Video data-block size exceeds the one-GiB safety threshold")

        if self.total_data_blocks == 0:
            warnings.append("Declared video data-block count is zero")
        elif self.data_block_size > 0 and self.video_data_offset < filesystem_bytes:
            declared_span = self.data_block_size * self.total_data_blocks
            available_span = filesystem_bytes - self.video_data_offset
            if declared_span > available_span:
                warnings.append("Declared video block span exceeds the available evidence image")

        self._validate_region(
            "System-log",
            self.system_log_offset,
            self.system_log_size,
            filesystem_bytes,
            warnings,
        )
        self._validate_region(
            "Primary HIKBTREE",
            self.primary_tree_offset,
            self.primary_tree_size,
            filesystem_bytes,
            warnings,
        )
        self._validate_region(
            "Secondary HIKBTREE",
            self.secondary_tree_offset,
            self.secondary_tree_size,
            filesystem_bytes,
            warnings,
        )

        return tuple(warnings)

    @staticmethod
    def _validate_region(
        label: str,
        offset: int,
        size: int,
        filesystem_bytes: int,
        warnings: list[str],
    ) -> None:
        if size == 0:
            warnings.append(f"{label} region has zero length")
            return
        if offset >= filesystem_bytes or size > filesystem_bytes - offset:
            warnings.append(f"{label} region is outside the available evidence image")


def _read_u64(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<Q", data, offset)[0])


def _read_u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("<I", data, offset)[0])
