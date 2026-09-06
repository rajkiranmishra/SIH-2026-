from dataclasses import replace
from datetime import UTC, datetime

import pytest

from forenx.custody.ledger import CustodyLedger


def test_custody_ledger_builds_and_verifies_hash_chain():
    ledger = CustodyLedger()
    first = ledger.append(
        case_id="CASE-001",
        actor_id="intake-1",
        actor_role="evidence-intake-officer",
        action="EVIDENCE_RECEIVED",
        details={"exhibit": "EX-01", "seal": "intact"},
        occurred_at=datetime(2026, 9, 5, 10, 0, tzinfo=UTC),
    )
    second = ledger.append(
        case_id="CASE-001",
        actor_id="examiner-1",
        actor_role="forensic-examiner",
        action="SOURCE_HASHED",
        evidence_hashes={"sha256": "a" * 64},
        occurred_at=datetime(2026, 9, 5, 10, 5, tzinfo=UTC),
    )

    assert first.sequence == 1
    assert second.sequence == 2
    assert second.previous_hash == first.event_hash
    assert ledger.verify().valid
    assert ledger.verify().checked_events == 2


def test_custody_ledger_detects_modified_event():
    ledger = CustodyLedger()
    original = ledger.append(
        case_id="CASE-001",
        actor_id="examiner-1",
        actor_role="forensic-examiner",
        action="SOURCE_HASHED",
        evidence_hashes={"sha256": "a" * 64},
    )
    tampered = replace(original, action="SOURCE_REPLACED")

    result = CustodyLedger([tampered]).verify()

    assert not result.valid
    assert result.failure_sequence == 1
    assert result.message == "Custody event hash does not match"


def test_custody_ledger_copies_mutable_input():
    details = {"seal": "intact"}
    ledger = CustodyLedger()
    event = ledger.append(
        case_id="CASE-001",
        actor_id="intake-1",
        actor_role="evidence-intake-officer",
        action="EVIDENCE_RECEIVED",
        details=details,
    )
    details["seal"] = "changed outside ledger"

    assert event.details["seal"] == "intact"
    assert event.to_dict()["details"] == {"seal": "intact"}
    assert ledger.verify().valid


def test_custody_ledger_rejects_naive_time_and_empty_fields():
    ledger = CustodyLedger()
    with pytest.raises(ValueError, match="timezone-aware"):
        ledger.append(
            case_id="CASE-001",
            actor_id="intake-1",
            actor_role="officer",
            action="RECEIVED",
            occurred_at=datetime(2026, 9, 5),
        )
    with pytest.raises(ValueError, match="cannot be empty"):
        ledger.append(case_id=" ", actor_id="a", actor_role="officer", action="RECEIVED")


def test_custody_ledger_detects_sequence_and_previous_hash_changes():
    ledger = CustodyLedger()
    original = ledger.append(
        case_id="CASE-001",
        actor_id="intake-1",
        actor_role="officer",
        action="RECEIVED",
    )

    sequence_result = CustodyLedger([replace(original, sequence=2)]).verify()
    previous_result = CustodyLedger([replace(original, previous_hash="f" * 64)]).verify()

    assert sequence_result.message == "Custody sequence is not contiguous"
    assert previous_result.message == "Previous custody hash does not match"
