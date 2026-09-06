from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any


class CaseStatus(StrEnum):
    INTAKE = "intake"
    ACQUISITION = "acquisition"
    PROCESSING = "processing"
    EXAMINER_REVIEW = "examiner-review"
    SUPERVISOR_REVIEW = "supervisor-review"
    APPROVED = "approved"
    CLOSED = "closed"


ALLOWED_CASE_TRANSITIONS: Mapping[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.INTAKE: frozenset({CaseStatus.ACQUISITION}),
    CaseStatus.ACQUISITION: frozenset({CaseStatus.PROCESSING, CaseStatus.INTAKE}),
    CaseStatus.PROCESSING: frozenset(
        {CaseStatus.EXAMINER_REVIEW, CaseStatus.ACQUISITION}
    ),
    CaseStatus.EXAMINER_REVIEW: frozenset(
        {CaseStatus.SUPERVISOR_REVIEW, CaseStatus.PROCESSING}
    ),
    CaseStatus.SUPERVISOR_REVIEW: frozenset(
        {CaseStatus.APPROVED, CaseStatus.EXAMINER_REVIEW}
    ),
    CaseStatus.APPROVED: frozenset({CaseStatus.CLOSED, CaseStatus.EXAMINER_REVIEW}),
    CaseStatus.CLOSED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class CaseRecord:
    case_id: str
    case_reference: str
    agency: str
    police_station: str | None
    investigating_officer: str
    classification: str
    status: CaseStatus
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ExhibitRecord:
    exhibit_id: str
    case_id: str
    exhibit_number: str
    device_type: str
    manufacturer: str | None
    model: str | None
    serial_number: str | None
    channel_count: int | None
    working_channels_observed: int | None
    recorder_time_observed: datetime | None
    clock_offset_seconds: int | None
    seal_number: str | None
    seal_condition: str
    packaging: str
    collector: str
    collection_location: str
    collected_at: datetime
    authorization_reference: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    event_id: str
    case_id: str
    sequence: int
    actor_id: str
    action: str
    occurred_at: datetime
    details: Mapping[str, Any]
    previous_hash: str
    event_hash: str


@dataclass(frozen=True, slots=True)
class ActivityVerification:
    valid: bool
    checked_events: int
    message: str = "Activity chain verified"
    failure_sequence: int | None = None
