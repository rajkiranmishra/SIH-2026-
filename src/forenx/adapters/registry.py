from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from forenx.adapters.base import (
    AdapterCapability,
    DvrFilesystemAdapter,
    ProbeResult,
    ReadableEvidence,
)
from forenx.adapters.hikvision import HikvisionAdapter


class AdapterMaturity(StrEnum):
    EXPERIMENTAL = "experimental"
    PILOT = "pilot"
    VALIDATED = "validated"


class UnsupportedEvidenceError(LookupError):
    """Raised when no registered adapter identifies the evidence."""


class AmbiguousAdapterError(LookupError):
    """Raised when multiple adapters produce materially equal confidence."""


@dataclass(frozen=True, slots=True)
class AdapterRegistration:
    adapter: DvrFilesystemAdapter
    vendor: str
    family: str
    maturity: AdapterMaturity
    available_capabilities: frozenset[AdapterCapability]
    validated_models: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.adapter.adapter_id.strip() or not self.adapter.version.strip():
            raise ValueError("Registered adapter identifiers cannot be empty")
        if not self.vendor.strip() or not self.family.strip():
            raise ValueError("Registered vendor and family cannot be empty")
        if self.maturity is AdapterMaturity.VALIDATED and not self.validated_models:
            raise ValueError("A validated adapter requires at least one validated model")

    def summary(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter.adapter_id,
            "version": self.adapter.version,
            "vendor": self.vendor,
            "family": self.family,
            "maturity": self.maturity.value,
            "capabilities": sorted(capability.value for capability in self.available_capabilities),
            "validated_models": list(self.validated_models),
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class AdapterProbeFailure:
    adapter_id: str
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class MultiVendorProbeReport:
    results: tuple[ProbeResult, ...]
    failures: tuple[AdapterProbeFailure, ...]

    @property
    def matches(self) -> tuple[ProbeResult, ...]:
        return tuple(result for result in self.results if result.confidence > 0)

    def best_match(
        self,
        *,
        minimum_confidence: float = 0.5,
        ambiguity_margin: float = 0.05,
    ) -> ProbeResult:
        if not 0 <= minimum_confidence <= 1:
            raise ValueError("Minimum confidence must be between zero and one")
        if not 0 <= ambiguity_margin <= 1:
            raise ValueError("Ambiguity margin must be between zero and one")

        candidates = [
            result for result in self.results if result.confidence >= minimum_confidence
        ]
        if not candidates:
            raise UnsupportedEvidenceError("No adapter met the required confidence threshold")
        best = candidates[0]
        if (
            len(candidates) > 1
            and best.confidence - candidates[1].confidence <= ambiguity_margin
        ):
            raise AmbiguousAdapterError(
                f"Evidence matches both {best.adapter_id} and {candidates[1].adapter_id}"
            )
        return best


class AdapterRegistry:
    def __init__(self, registrations: tuple[AdapterRegistration, ...]) -> None:
        identifiers = [registration.adapter.adapter_id for registration in registrations]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Adapter identifiers must be unique")
        self._registrations = registrations

    @property
    def registrations(self) -> tuple[AdapterRegistration, ...]:
        return self._registrations

    def probe_all(self, source: ReadableEvidence) -> MultiVendorProbeReport:
        results: list[ProbeResult] = []
        failures: list[AdapterProbeFailure] = []
        for registration in self._registrations:
            try:
                result = registration.adapter.probe(source)
                if result.adapter_id != registration.adapter.adapter_id:
                    raise ValueError("Adapter returned a mismatched identifier")
                results.append(result)
            except Exception as exc:
                failures.append(
                    AdapterProbeFailure(
                        adapter_id=registration.adapter.adapter_id,
                        error_type=type(exc).__name__,
                        message=str(exc),
                    )
                )
        results.sort(key=lambda result: (-result.confidence, result.adapter_id))
        return MultiVendorProbeReport(tuple(results), tuple(failures))


def default_adapter_registry() -> AdapterRegistry:
    hikvision = HikvisionAdapter()
    return AdapterRegistry(
        (
            AdapterRegistration(
                adapter=hikvision,
                vendor="Hikvision",
                family="Proprietary DVR disk (observed 48-byte HIKBTREE family)",
                maturity=AdapterMaturity.EXPERIMENTAL,
                available_capabilities=frozenset(
                    {
                        AdapterCapability.DEVICE_METADATA,
                        AdapterCapability.ENUMERATE_ACTIVE,
                        AdapterCapability.EXTRACT,
                    }
                ),
                notes=(
                    "Synthetic fixtures pass; authorized real-device validation is pending",
                ),
            ),
        )
    )
