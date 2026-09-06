from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class BiometricComparisonMode(StrEnum):
    ONE_TO_ONE = "one-to-one"


@dataclass(frozen=True, slots=True)
class BiometricAuthorizationRecord:
    authorization_id: str
    case_id: str
    source_id: str
    mode: BiometricComparisonMode
    purpose: str
    legal_authority_reference: str
    reference_provenance: str
    retention_until: datetime
    threshold_policy: str
    authorized_by: str
    authorized_at: datetime
