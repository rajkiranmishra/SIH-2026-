"""DVR/NVR filesystem adapter contracts and implementations."""

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
from forenx.adapters.registry import (
    AdapterMaturity,
    AdapterProbeFailure,
    AdapterRegistration,
    AdapterRegistry,
    AmbiguousAdapterError,
    MultiVendorProbeReport,
    UnsupportedEvidenceError,
    default_adapter_registry,
)

__all__ = [
    "AdapterCapability",
    "AdapterMaturity",
    "AdapterProbeFailure",
    "AdapterRegistration",
    "AdapterRegistry",
    "AmbiguousAdapterError",
    "DvrFilesystemAdapter",
    "ExtractionError",
    "ExtractionResult",
    "MultiVendorProbeReport",
    "PhysicalExtent",
    "ProbeEvidence",
    "ProbeResult",
    "ReadableEvidence",
    "RecordingDescriptor",
    "RecordingState",
    "UnsupportedEvidenceError",
    "default_adapter_registry",
]
