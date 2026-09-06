"""DVR/NVR filesystem adapter contracts and implementations."""

from forenx.adapters.base import (
    AdapterCapability,
    DvrFilesystemAdapter,
    ExtractionError,
    ExtractionResult,
    PhysicalExtent,
    ProbeEvidence,
    ProbeResult,
    RecordingDescriptor,
)
from forenx.adapters.registry import (
    AdapterMaturity,
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
    "RecordingDescriptor",
    "UnsupportedEvidenceError",
    "default_adapter_registry",
]
