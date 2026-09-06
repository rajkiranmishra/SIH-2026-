from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from forenx.cases import (
    CaseAssignmentAlreadyExistsError,
    CaseAssignmentNotFoundError,
    CaseNotFoundError,
    CaseStatus,
    CaseStore,
    CaseStoreError,
    ConcurrentCaseUpdateError,
    DuplicateCaseReferenceError,
    DuplicateExhibitNumberError,
    InvalidCaseTransitionError,
)

CASE_TIME = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)


def _create_case(store: CaseStore, *, reference: str = "FIR-2026-001"):
    return store.create_case(
        case_reference=reference,
        agency="State Forensic Science Laboratory",
        police_station="Central Police Station",
        investigating_officer="Inspector A. Kumar",
        classification="Restricted",
        actor_id="intake-operator-1",
        occurred_at=CASE_TIME,
    )


def _add_exhibit(store: CaseStore, case_id: str, *, number: str = "EX-01"):
    return store.add_exhibit(
        case_id,
        exhibit_number=number,
        device_type="DVR",
        manufacturer="Hikvision",
        model="DS-7208",
        serial_number="SERIAL-001",
        channel_count=8,
        working_channels_observed=6,
        recorder_time_observed=datetime(2026, 9, 6, 15, 30, tzinfo=UTC),
        clock_offset_seconds=120,
        seal_number="SEAL-100",
        seal_condition="Intact",
        packaging="Anti-static bag inside sealed evidence box",
        collector="Officer B. Singh",
        collection_location="Control room rack 2",
        collected_at=datetime(2026, 9, 6, 9, 0, tzinfo=UTC),
        authorization_reference="WARRANT-001",
        actor_id="intake-operator-1",
    )


def test_case_and_exhibit_persist_with_complete_intake_fields(tmp_path: Path):
    database = tmp_path / "forenx.db"
    store = CaseStore(database)
    case = _create_case(store)
    exhibit = _add_exhibit(store, case.case_id)
    store.close()

    reopened = CaseStore(database)
    loaded_case = reopened.get_case(case.case_id)
    loaded_exhibit = reopened.get_exhibit(exhibit.exhibit_id)

    assert loaded_case.case_reference == "FIR-2026-001"
    assert loaded_case.status is CaseStatus.INTAKE
    assert loaded_case.version == 1
    assert loaded_exhibit.seal_condition == "Intact"
    assert loaded_exhibit.channel_count == 8
    assert loaded_exhibit.working_channels_observed == 6
    assert loaded_exhibit.authorization_reference == "WARRANT-001"
    assert reopened.list_exhibits(case.case_id) == (loaded_exhibit,)
    assert database.stat().st_mode & 0o777 == 0o600
    reopened.close()


def test_case_reference_and_exhibit_number_are_unique(tmp_path: Path):
    store = CaseStore(tmp_path / "forenx.db")
    case = _create_case(store)
    with pytest.raises(DuplicateCaseReferenceError, match="already exists"):
        _create_case(store, reference="fir-2026-001")

    _add_exhibit(store, case.case_id)
    with pytest.raises(DuplicateExhibitNumberError, match="already exists"):
        _add_exhibit(store, case.case_id)


def test_status_transitions_are_explicit_versioned_and_audited():
    store = CaseStore()
    case = _create_case(store)

    acquisition = store.transition_case(
        case.case_id,
        CaseStatus.ACQUISITION,
        expected_version=1,
        actor_id="examiner-1",
        reason="Seal and intake checklist verified",
        occurred_at=datetime(2026, 9, 6, 10, 5, tzinfo=UTC),
    )

    assert acquisition.status is CaseStatus.ACQUISITION
    assert acquisition.version == 2
    activity = store.list_activity(case.case_id)
    assert [event.action for event in activity] == [
        "CASE_CREATED",
        "CASE_ACCESS_GRANTED",
        "CASE_STATUS_CHANGED",
    ]
    assert activity[2].details["from"] == "intake"
    assert activity[2].details["to"] == "acquisition"
    assert store.verify_activity(case.case_id).valid


def test_internal_product_activity_can_be_recorded_and_verified():
    store = CaseStore()
    case = _create_case(store)

    event = store.record_activity(
        case.case_id,
        actor_id="examiner-1",
        action="EVIDENCE_INTEGRITY_VERIFIED",
        details={"source_id": "source-1", "valid": True},
        occurred_at=datetime(2026, 9, 6, 10, 10, tzinfo=UTC),
    )

    assert event.sequence == 3
    assert event.details["source_id"] == "source-1"
    assert store.verify_activity(case.case_id).valid


def test_invalid_or_stale_status_transition_changes_nothing():
    store = CaseStore()
    case = _create_case(store)

    with pytest.raises(InvalidCaseTransitionError, match="cannot move"):
        store.transition_case(
            case.case_id,
            CaseStatus.APPROVED,
            expected_version=1,
            actor_id="supervisor-1",
            reason="invalid shortcut",
        )
    with pytest.raises(ConcurrentCaseUpdateError, match="another operation"):
        store.transition_case(
            case.case_id,
            CaseStatus.ACQUISITION,
            expected_version=99,
            actor_id="examiner-1",
            reason="stale form",
        )

    assert store.get_case(case.case_id).status is CaseStatus.INTAKE
    assert len(store.list_activity(case.case_id)) == 2


def test_activity_rows_are_database_immutable(tmp_path: Path):
    database = tmp_path / "forenx.db"
    store = CaseStore(database)
    case = _create_case(store)

    external = sqlite3.connect(database)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        external.execute(
            "UPDATE activity_events SET action = 'ALTERED' WHERE case_id = ?",
            (case.case_id,),
        )
    external.close()
    assert store.verify_activity(case.case_id).valid


def test_hash_chain_detects_tampering_even_if_database_trigger_is_removed(tmp_path: Path):
    database = tmp_path / "forenx.db"
    store = CaseStore(database)
    case = _create_case(store)

    external = sqlite3.connect(database)
    external.execute("DROP TRIGGER activity_events_no_update")
    external.execute(
        "UPDATE activity_events SET action = 'ALTERED' WHERE case_id = ?",
        (case.case_id,),
    )
    external.commit()
    external.close()

    verification = store.verify_activity(case.case_id)
    assert not verification.valid
    assert verification.message == "Activity event hash does not match"


def test_intake_rejects_impossible_channel_counts_and_naive_times():
    store = CaseStore()
    case = _create_case(store)
    with pytest.raises(ValueError, match="cannot exceed"):
        store.add_exhibit(
            case.case_id,
            exhibit_number="EX-01",
            device_type="DVR",
            channel_count=4,
            working_channels_observed=5,
            seal_condition="Intact",
            packaging="Box",
            collector="Officer",
            collection_location="Scene",
            collected_at=CASE_TIME,
            authorization_reference="AUTH-1",
            actor_id="intake-1",
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        store.add_exhibit(
            case.case_id,
            exhibit_number="EX-02",
            device_type="DVR",
            seal_condition="Intact",
            packaging="Box",
            collector="Officer",
            collection_location="Scene",
            collected_at=datetime(2026, 9, 6),
            authorization_reference="AUTH-1",
            actor_id="intake-1",
        )


def test_unknown_case_and_database_symlink_are_rejected(tmp_path: Path):
    store = CaseStore(tmp_path / "forenx.db")
    with pytest.raises(CaseNotFoundError, match="not found"):
        store.get_case("missing")
    with pytest.raises(CaseNotFoundError, match="not found"):
        store.list_exhibits("missing")
    store.close()

    link = tmp_path / "linked.db"
    link.symlink_to(tmp_path / "forenx.db")
    with pytest.raises(CaseStoreError, match="symbolic link"):
        CaseStore(link)


def test_list_cases_can_filter_by_workflow_status():
    store = CaseStore()
    first = _create_case(store, reference="CASE-A")
    second = _create_case(store, reference="CASE-B")
    store.transition_case(
        first.case_id,
        CaseStatus.ACQUISITION,
        expected_version=1,
        actor_id="examiner",
        reason="ready",
    )

    assert [case.case_id for case in store.list_cases(status=CaseStatus.INTAKE)] == [
        second.case_id
    ]
    assert [case.case_id for case in store.list_cases(status=CaseStatus.ACQUISITION)] == [
        first.case_id
    ]


def test_case_assignments_are_scoped_revocable_and_audited():
    store = CaseStore()
    first = _create_case(store, reference="CASE-ACCESS-A")
    second = _create_case(store, reference="CASE-ACCESS-B")

    assert store.has_access(first.case_id, "intake-operator-1")
    assert {
        case.case_id for case in store.list_cases_for_user("intake-operator-1")
    } == {first.case_id, second.case_id}

    assignment = store.assign_user(
        first.case_id,
        "examiner-1",
        assigned_by="supervisor-1",
        occurred_at=datetime(2026, 9, 6, 10, 10, tzinfo=UTC),
    )
    assert assignment.active
    assert store.has_access(first.case_id, "examiner-1")
    assert store.list_cases_for_user("examiner-1") == (first,)
    with pytest.raises(CaseAssignmentAlreadyExistsError, match="already has access"):
        store.assign_user(first.case_id, "examiner-1", assigned_by="supervisor-1")

    revoked = store.revoke_user(
        first.case_id,
        "examiner-1",
        revoked_by="supervisor-1",
        occurred_at=datetime(2026, 9, 6, 10, 20, tzinfo=UTC),
    )
    assert not revoked.active
    assert revoked.revoked_by == "supervisor-1"
    assert not store.has_access(first.case_id, "examiner-1")
    assert store.list_cases_for_user("examiner-1") == ()
    assert store.list_assignments(first.case_id) == (
        store.list_assignments(first.case_id, include_revoked=True)[0],
    )
    with pytest.raises(CaseAssignmentNotFoundError, match="not found"):
        store.revoke_user(first.case_id, "examiner-1", revoked_by="supervisor-1")

    actions = [event.action for event in store.list_activity(first.case_id)]
    assert actions == [
        "CASE_CREATED",
        "CASE_ACCESS_GRANTED",
        "CASE_ACCESS_GRANTED",
        "CASE_ACCESS_REVOKED",
    ]
    assert store.verify_activity(first.case_id).valid


def test_case_assignment_rows_cannot_be_rewritten_or_deleted(tmp_path: Path):
    database = tmp_path / "forenx.db"
    store = CaseStore(database)
    case = _create_case(store)

    external = sqlite3.connect(database)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        external.execute(
            "UPDATE case_assignments SET user_id = 'attacker' WHERE case_id = ?",
            (case.case_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        external.execute("DELETE FROM case_assignments WHERE case_id = ?", (case.case_id,))
    external.close()
    assert store.has_access(case.case_id, "intake-operator-1")


def test_schema_version_one_is_migrated_fail_closed(tmp_path: Path):
    database = tmp_path / "legacy.db"
    legacy = sqlite3.connect(database)
    legacy.execute("CREATE TABLE schema_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    legacy.execute("INSERT INTO schema_metadata VALUES('schema_version', '1')")
    legacy.commit()
    legacy.close()

    store = CaseStore(database)
    assert store.list_cases_for_user("legacy-user") == ()
    store.close()
    migrated = sqlite3.connect(database)
    version = migrated.execute(
        "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
    ).fetchone()
    migrated.close()
    assert version == ("2",)


def test_close_is_idempotent_and_file_stays_private(tmp_path: Path):
    database = tmp_path / "forenx.db"
    store = CaseStore(database)
    store.close()
    store.close()
    assert os.stat(database).st_mode & 0o777 == 0o600
