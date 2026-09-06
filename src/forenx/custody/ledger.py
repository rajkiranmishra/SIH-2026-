from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any
from uuid import uuid4

GENESIS_HASH = "0" * 64


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _normalized_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Custody timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CustodyEvent:
    event_id: str
    sequence: int
    case_id: str
    actor_id: str
    actor_role: str
    action: str
    occurred_at: str
    details: Mapping[str, Any]
    evidence_hashes: Mapping[str, str]
    previous_hash: str
    event_hash: str

    def hash_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "case_id": self.case_id,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "occurred_at": self.occurred_at,
            "details": dict(self.details),
            "evidence_hashes": dict(self.evidence_hashes),
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.hash_payload(), "event_hash": self.event_hash}


@dataclass(frozen=True, slots=True)
class CustodyVerification:
    valid: bool
    checked_events: int
    failure_sequence: int | None = None
    message: str = "Custody chain verified"


class CustodyLedger:
    def __init__(self, events: Iterable[CustodyEvent] = ()) -> None:
        self._events = list(events)

    @property
    def events(self) -> tuple[CustodyEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        *,
        case_id: str,
        actor_id: str,
        actor_role: str,
        action: str,
        details: Mapping[str, Any] | None = None,
        evidence_hashes: Mapping[str, str] | None = None,
        occurred_at: datetime | None = None,
    ) -> CustodyEvent:
        required = {
            "case_id": case_id,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "action": action,
        }
        empty_fields = [name for name, value in required.items() if not value.strip()]
        if empty_fields:
            raise ValueError(f"Custody event fields cannot be empty: {', '.join(empty_fields)}")

        sequence = len(self._events) + 1
        previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        event_id = str(uuid4())
        event_time = _normalized_time(occurred_at or datetime.now(UTC))
        safe_details = json.loads(_canonical_json(dict(details or {})).decode("utf-8"))
        safe_hashes = dict(evidence_hashes or {})

        for algorithm, digest in safe_hashes.items():
            if not algorithm.strip() or not digest.strip():
                raise ValueError("Evidence hash names and values cannot be empty")

        payload = {
            "event_id": event_id,
            "sequence": sequence,
            "case_id": case_id,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "action": action,
            "occurred_at": event_time,
            "details": safe_details,
            "evidence_hashes": safe_hashes,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()
        event = CustodyEvent(
            **{
                **payload,
                "details": MappingProxyType(safe_details),
                "evidence_hashes": MappingProxyType(safe_hashes),
                "event_hash": event_hash,
            }
        )
        self._events.append(event)
        return event

    def verify(self) -> CustodyVerification:
        previous_hash = GENESIS_HASH
        for expected_sequence, event in enumerate(self._events, start=1):
            if event.sequence != expected_sequence:
                return CustodyVerification(
                    False,
                    expected_sequence - 1,
                    event.sequence,
                    "Custody sequence is not contiguous",
                )
            if event.previous_hash != previous_hash:
                return CustodyVerification(
                    False,
                    expected_sequence - 1,
                    event.sequence,
                    "Previous custody hash does not match",
                )
            calculated = hashlib.sha256(_canonical_json(event.hash_payload())).hexdigest()
            if calculated != event.event_hash:
                return CustodyVerification(
                    False,
                    expected_sequence - 1,
                    event.sequence,
                    "Custody event hash does not match",
                )
            previous_hash = event.event_hash
        return CustodyVerification(True, len(self._events))
