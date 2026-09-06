from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class ReadableEvidence(Protocol):
    @property
    def size(self) -> int: ...

    def read_at(self, offset: int, length: int) -> bytes: ...


class AdapterCapability(StrEnum):
    ENUMERATE_ACTIVE = "enumerate-active"
    ENUMERATE_ORPHANED = "enumerate-orphaned"
    EXTRACT = "extract"
    RECONSTRUCT = "reconstruct"
    DEVICE_METADATA = "device-metadata"


class RecordingState(StrEnum):
    ACTIVE = "active"
    ORPHANED = "orphaned"
    OVERWRITTEN = "overwritten"
    CARVED_CANDIDATE = "carved-candidate"
    UNCERTAIN = "uncertain"


class ExtractionError(RuntimeError):
    """Raised when a derivative cannot be created safely and reproducibly."""


@dataclass(frozen=True, slots=True)
class ProbeEvidence:
    description: str
    offset: int
    observed_hex: str

    def __post_init__(self) -> None:
        if self.offset < 0:
            raise ValueError("Probe evidence offset cannot be negative")
        if not self.description.strip():
            raise ValueError("Probe evidence requires a description")


@dataclass(frozen=True, slots=True)
class ProbeResult:
    adapter_id: str
    vendor: str
    filesystem: str
    confidence: float
    evidence: tuple[ProbeEvidence, ...]
    capabilities: frozenset[AdapterCapability]
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Probe confidence must be between 0 and 1")
        if self.confidence > 0 and not self.evidence:
            raise ValueError("A positive probe result requires observable evidence")


@dataclass(frozen=True, slots=True)
class PhysicalExtent:
    offset: int
    length: int

    def __post_init__(self) -> None:
        if self.offset < 0 or self.length <= 0:
            raise ValueError("Physical extent requires a non-negative offset and positive length")


@dataclass(frozen=True, slots=True)
class RecordingDescriptor:
    recording_id: str
    channel: str | None
    start_time: datetime | None
    end_time: datetime | None
    timestamp_source: str | None
    state: RecordingState
    extents: tuple[PhysicalExtent, ...]
    codec_hint: str | None = None
    confidence: float = 0.0
    warnings: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.recording_id.strip():
            raise ValueError("Recording identifier cannot be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Recording confidence must be between 0 and 1")
        if self.end_time and self.start_time and self.end_time < self.start_time:
            raise ValueError("Recording end time cannot precede start time")
        if not self.extents:
            raise ValueError("A recording descriptor requires source provenance extents")


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    output_path: Path
    sha256: str
    bytes_written: int
    source_extents: tuple[PhysicalExtent, ...]
    warnings: tuple[str, ...] = ()
    format_hint: str | None = None
    validation_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.bytes_written < 0:
            raise ValueError("Extracted byte count cannot be negative")
        if len(self.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.sha256.lower()
        ):
            raise ValueError("Extraction result requires a hexadecimal SHA-256 digest")
        if not self.source_extents:
            raise ValueError("Extraction result requires source extents")


class DvrFilesystemAdapter(ABC):
    """A side-effect-limited adapter for one DVR filesystem family."""

    adapter_id: str
    version: str

    @abstractmethod
    def probe(self, source: ReadableEvidence) -> ProbeResult:
        """Identify observable format evidence without writing to disk."""

    @abstractmethod
    def enumerate_recordings(self, source: ReadableEvidence) -> Sequence[RecordingDescriptor]:
        """Return typed recording descriptors with source-byte provenance."""

    @abstractmethod
    def extract(
        self,
        source: ReadableEvidence,
        recording: RecordingDescriptor,
        destination: Path,
    ) -> ExtractionResult:
        """Extract exact source extents into a new derivative artifact."""
