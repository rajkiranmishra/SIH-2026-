from datetime import UTC, datetime

import pytest

from forenx.adapters.base import (
    AdapterCapability,
    PhysicalExtent,
    ProbeEvidence,
    ProbeResult,
    RecordingDescriptor,
    RecordingState,
)


def test_recording_descriptor_requires_physical_provenance():
    with pytest.raises(ValueError, match="source provenance"):
        RecordingDescriptor(
            recording_id="recording-1",
            channel="1",
            start_time=None,
            end_time=None,
            timestamp_source=None,
            state=RecordingState.UNCERTAIN,
            extents=(),
        )


def test_recording_descriptor_rejects_impossible_time_range():
    with pytest.raises(ValueError, match="end time"):
        RecordingDescriptor(
            recording_id="recording-1",
            channel="1",
            start_time=datetime(2026, 9, 5, 11, tzinfo=UTC),
            end_time=datetime(2026, 9, 5, 10, tzinfo=UTC),
            timestamp_source="hikbtree",
            state=RecordingState.ACTIVE,
            extents=(PhysicalExtent(offset=4096, length=1024),),
        )


def test_probe_result_requires_observable_evidence():
    with pytest.raises(ValueError, match="observable evidence"):
        ProbeResult(
            adapter_id="hikvision",
            vendor="Hikvision",
            filesystem="HIKVISION",
            confidence=0.5,
            evidence=(),
            capabilities=frozenset({AdapterCapability.ENUMERATE_ACTIVE}),
        )


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_probe_result_rejects_invalid_confidence(confidence):
    evidence = ProbeEvidence(description="signature", offset=0, observed_hex="00")
    with pytest.raises(ValueError, match="between 0 and 1"):
        ProbeResult(
            adapter_id="hikvision",
            vendor="Hikvision",
            filesystem="HIKVISION",
            confidence=confidence,
            evidence=(evidence,),
            capabilities=frozenset(),
        )


@pytest.mark.parametrize(("offset", "length"), [(-1, 1), (0, 0)])
def test_physical_extent_rejects_invalid_ranges(offset, length):
    with pytest.raises(ValueError, match="Physical extent"):
        PhysicalExtent(offset=offset, length=length)


def test_probe_evidence_requires_description_and_valid_offset():
    with pytest.raises(ValueError, match="offset"):
        ProbeEvidence(description="signature", offset=-1, observed_hex="00")
    with pytest.raises(ValueError, match="description"):
        ProbeEvidence(description=" ", offset=0, observed_hex="00")
