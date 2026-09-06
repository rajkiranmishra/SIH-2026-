from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from forenx.adapters.base import (
    AdapterCapability,
    DvrFilesystemAdapter,
    ExtractionResult,
    ProbeEvidence,
    ProbeResult,
    ReadableEvidence,
    RecordingDescriptor,
)
from forenx.adapters.registry import (
    AdapterMaturity,
    AdapterRegistration,
    AdapterRegistry,
    AmbiguousAdapterError,
    UnsupportedEvidenceError,
    default_adapter_registry,
)


class EmptyEvidence:
    size = 0

    def read_at(self, offset: int, length: int) -> bytes:
        assert offset == 0 and length == 0
        return b""


class FakeAdapter(DvrFilesystemAdapter):
    version = "1.0"

    def __init__(
        self,
        adapter_id: str,
        confidence: float,
        *,
        failure: bool = False,
        returned_id: str | None = None,
    ) -> None:
        self.adapter_id = adapter_id
        self._confidence = confidence
        self._failure = failure
        self._returned_id = returned_id or adapter_id

    def probe(self, source: ReadableEvidence) -> ProbeResult:
        del source
        if self._failure:
            raise RuntimeError("isolated parser failure")
        evidence = (
            ProbeEvidence("test signature", 0, "aa"),
        ) if self._confidence else ()
        return ProbeResult(
            adapter_id=self._returned_id,
            vendor=self.adapter_id,
            filesystem="test",
            confidence=self._confidence,
            evidence=evidence,
            capabilities=frozenset(),
        )

    def enumerate_recordings(self, source: ReadableEvidence) -> Sequence[RecordingDescriptor]:
        del source
        return ()

    def extract(
        self,
        source: ReadableEvidence,
        recording: RecordingDescriptor,
        destination: Path,
    ) -> ExtractionResult:
        del source, recording, destination
        raise NotImplementedError


def _registration(adapter: FakeAdapter) -> AdapterRegistration:
    return AdapterRegistration(
        adapter=adapter,
        vendor=adapter.adapter_id,
        family="test family",
        maturity=AdapterMaturity.EXPERIMENTAL,
        available_capabilities=frozenset(),
    )


def test_registry_probes_every_vendor_sorts_matches_and_isolates_failure():
    registry = AdapterRegistry(
        (
            _registration(FakeAdapter("low", 0.6)),
            _registration(FakeAdapter("broken", 0, failure=True)),
            _registration(FakeAdapter("high", 0.9)),
        )
    )

    report = registry.probe_all(EmptyEvidence())

    assert [result.adapter_id for result in report.results] == ["high", "low"]
    assert [result.adapter_id for result in report.matches] == ["high", "low"]
    assert report.failures[0].adapter_id == "broken"
    assert report.failures[0].error_type == "RuntimeError"
    assert report.best_match().adapter_id == "high"


def test_registry_rejects_ambiguous_and_unsupported_evidence():
    ambiguous = AdapterRegistry(
        (
            _registration(FakeAdapter("one", 0.91)),
            _registration(FakeAdapter("two", 0.88)),
        )
    ).probe_all(EmptyEvidence())
    unsupported = AdapterRegistry(
        (_registration(FakeAdapter("none", 0.2)),)
    ).probe_all(EmptyEvidence())

    with pytest.raises(AmbiguousAdapterError, match="both"):
        ambiguous.best_match()
    with pytest.raises(UnsupportedEvidenceError, match="threshold"):
        unsupported.best_match()


def test_registry_rejects_duplicate_or_mismatched_adapter_identifiers():
    duplicate = _registration(FakeAdapter("same", 0.5))
    with pytest.raises(ValueError, match="unique"):
        AdapterRegistry((duplicate, duplicate))

    report = AdapterRegistry(
        (_registration(FakeAdapter("declared", 0.9, returned_id="different")),)
    ).probe_all(EmptyEvidence())
    assert report.results == ()
    assert report.failures[0].error_type == "ValueError"


def test_validated_registration_requires_named_real_models():
    with pytest.raises(ValueError, match="validated model"):
        AdapterRegistration(
            adapter=FakeAdapter("adapter", 0.9),
            vendor="Vendor",
            family="Family",
            maturity=AdapterMaturity.VALIDATED,
            available_capabilities=frozenset({AdapterCapability.EXTRACT}),
        )


def test_default_registry_reports_hikvision_as_experimental():
    registration = default_adapter_registry().registrations[0]
    summary = registration.summary()

    assert summary["adapter_id"] == "hikvision"
    assert summary["maturity"] == "experimental"
    assert summary["validated_models"] == []
    assert summary["capabilities"] == [
        "device-metadata",
        "enumerate-active",
        "extract",
    ]


@pytest.mark.parametrize(
    ("minimum", "margin"),
    [(-0.1, 0.1), (0.1, 1.1)],
)
def test_best_match_rejects_invalid_thresholds(minimum: float, margin: float):
    report = AdapterRegistry(
        (_registration(FakeAdapter("test", 0.8)),)
    ).probe_all(EmptyEvidence())
    with pytest.raises(ValueError, match="between"):
        report.best_match(minimum_confidence=minimum, ambiguity_margin=margin)
