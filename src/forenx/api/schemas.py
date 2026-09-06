from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field

from forenx.auth import Role
from forenx.biometrics import BiometricComparisonMode
from forenx.cases import CaseStatus
from forenx.evidence import EvidenceMediaKind

ShortText = Annotated[str, Field(min_length=1, max_length=256)]


class SetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: ShortText
    password: str = Field(min_length=12, max_length=1024)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: ShortText
    password: str = Field(min_length=12, max_length=1024)
    role: Role


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    username: str
    display_name: str
    role: Role
    active: bool
    created_at: datetime


class SessionResponse(BaseModel):
    token: str
    expires_at: datetime
    user: UserResponse


class CreateCaseRequest(BaseModel):
    case_reference: ShortText
    agency: ShortText
    police_station: str | None = Field(default=None, max_length=256)
    investigating_officer: ShortText
    classification: ShortText


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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


class CreateCaseAssignmentRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)


class CaseAssignmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    assignment_id: str
    case_id: str
    user_id: str
    assigned_by: str
    assigned_at: datetime
    revoked_by: str | None
    revoked_at: datetime | None
    active: bool


class TransitionCaseRequest(BaseModel):
    target_status: CaseStatus
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1000)


class CreateExhibitRequest(BaseModel):
    exhibit_number: ShortText
    device_type: ShortText
    manufacturer: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=256)
    serial_number: str | None = Field(default=None, max_length=256)
    channel_count: int | None = Field(default=None, ge=1, le=4096)
    working_channels_observed: int | None = Field(default=None, ge=0, le=4096)
    recorder_time_observed: datetime | None = None
    clock_offset_seconds: int | None = Field(default=None, ge=-604800, le=604800)
    seal_number: str | None = Field(default=None, max_length=256)
    seal_condition: ShortText
    packaging: str = Field(min_length=1, max_length=2000)
    collector: ShortText
    collection_location: str = Field(min_length=1, max_length=1000)
    collected_at: datetime
    authorization_reference: str = Field(min_length=1, max_length=1000)


class ExhibitResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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


class ActivityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    case_id: str
    sequence: int
    actor_id: str
    action: str
    occurred_at: datetime
    details: dict[str, Any]
    previous_hash: str
    event_hash: str


class ActivityVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    valid: bool
    checked_events: int
    message: str
    failure_sequence: int | None


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_id: str
    case_id: str
    exhibit_id: str
    original_filename: str
    media_kind: EvidenceMediaKind
    byte_size: int
    sha256: str
    created_by: str
    created_at: datetime


class EvidenceVerificationResponse(BaseModel):
    source_id: str
    valid: bool
    expected_sha256: str
    observed_sha256: str


class MediaStreamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    index: int
    type: str
    codec_name: str | None
    codec_long_name: str | None
    duration_seconds: float | None
    start_time_seconds: float | None
    frame_count: int | None
    time_base: str | None
    width: int | None
    height: int | None
    pixel_format: str | None
    average_frame_rate: float | None
    sample_rate: int | None
    channels: int | None
    metadata: dict[str, str]


class MediaInspectionResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    format_name: str
    format_long_name: str
    duration_seconds: float | None
    start_time_seconds: float | None
    bit_rate: int | None
    metadata: dict[str, str]
    streams: tuple[MediaStreamResponse, ...]
    warnings: tuple[str, ...]
    library: str
    library_version: str


class StoredMediaInspectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    inspection_id: str
    source_id: str
    result: MediaInspectionResultResponse
    inspected_by: str
    inspected_at: datetime


class CreateBookmarkRequest(BaseModel):
    timestamp_ms: int = Field(ge=0)
    title: str = Field(min_length=1, max_length=256)
    note: str | None = Field(default=None, max_length=4000)


class BookmarkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bookmark_id: str
    case_id: str
    source_id: str
    timestamp_ms: int
    title: str
    note: str | None
    created_by: str
    created_at: datetime


class CreateBiometricAuthorizationRequest(BaseModel):
    mode: BiometricComparisonMode = BiometricComparisonMode.ONE_TO_ONE
    purpose: str = Field(min_length=1, max_length=2000)
    legal_authority_reference: str = Field(min_length=1, max_length=1000)
    reference_provenance: str = Field(min_length=1, max_length=2000)
    retention_until: datetime
    threshold_policy: str = Field(min_length=1, max_length=2000)


class BiometricAuthorizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

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


class CreateFaceDetectionRequest(BaseModel):
    timestamp_ms: int = Field(ge=0)


class FacePointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    x: float
    y: float


class FaceDetectionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    detection_id: str
    sequence: int
    x: float
    y: float
    width: float
    height: float
    landmarks: tuple[FacePointResponse, ...]
    confidence: float
    quality_flags: tuple[str, ...]


class FaceDetectionRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    case_id: str
    source_id: str
    authorization_id: str
    requested_timestamp_ms: int
    observed_timestamp_ms: int
    source_frame_sha256: str
    frame_width: int
    frame_height: int
    analysis_width: int
    analysis_height: int
    model_id: str
    model_name: str
    model_version: str
    model_sha256: str
    model_license: str
    model_source_uri: str
    runtime: str
    runtime_version: str
    score_threshold: float
    nms_threshold: float
    max_dimension: int
    preview_sha256: str
    created_by: str
    created_at: datetime
    faces: tuple[FaceDetectionResponse, ...]


class CreateReportPackageRequest(BaseModel):
    signing_password: str = Field(min_length=12, max_length=1024, repr=False)
    report_title: str = Field(min_length=1, max_length=256)
    purpose: str = Field(min_length=1, max_length=5000)
    examiner_conclusion: str = Field(min_length=1, max_length=10_000)
    limitations: list[str] = Field(default_factory=list, max_length=50)


class ReportPackageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    package_id: str
    case_id: str
    exhibit_id: str
    source_id: str
    report_title: str
    created_by: str
    created_at: datetime
    manifest_sha256: str
    archive_sha256: str
    public_key_fingerprint: str
