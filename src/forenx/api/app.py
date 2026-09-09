import hmac
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi import status as http_status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from forenx import __version__
from forenx.adapters import (
    AmbiguousAdapterError,
    ExtractionError,
    UnsupportedEvidenceError,
)
from forenx.adapters.registry import AdapterRegistry, default_adapter_registry
from forenx.api.schemas import (
    ActivityResponse,
    ActivityVerificationResponse,
    AuthAuditVerificationResponse,
    AuthEventResponse,
    BiometricAuthorizationResponse,
    BookmarkResponse,
    CaseAssignmentResponse,
    CaseResponse,
    ChangePasswordRequest,
    ConfirmAccountActionRequest,
    CreateBiometricAuthorizationRequest,
    CreateBookmarkRequest,
    CreateCaseAssignmentRequest,
    CreateCaseRequest,
    CreateExhibitRequest,
    CreateFaceDetectionRequest,
    CreateFaceTrackingRequest,
    CreateReportPackageRequest,
    CreateUserRequest,
    EvidenceResponse,
    EvidenceVerificationResponse,
    ExhibitResponse,
    FaceDetectionRunResponse,
    FaceTrackingRunResponse,
    LoginRequest,
    RecoveryArtifactResponse,
    RecoveryScanResponse,
    ReportPackageResponse,
    ResetPasswordRequest,
    SessionResponse,
    SetupRequest,
    SetUserStatusRequest,
    StoredMediaInspectionResponse,
    TransitionCaseRequest,
    UserResponse,
)
from forenx.auth import (
    AuthAuditVerification,
    AuthenticationError,
    AuthenticationThrottled,
    AuthEvent,
    AuthorizationError,
    AuthStore,
    AuthStoreError,
    Permission,
    Role,
    UserNotFoundError,
    UserRecord,
    require_permission,
)
from forenx.biometrics import (
    BiometricAuthorizationError,
    BiometricAuthorizationNotFoundError,
    BiometricAuthorizationRecord,
    BiometricAuthorizationStore,
    FaceDetectionError,
    FaceDetectionRun,
    FaceDetectionRunNotFoundError,
    FaceDetectionStore,
    FaceDetectionStoreError,
    FaceDetector,
    FaceTrackingError,
    FaceTrackingRun,
    FaceTrackingStore,
    FaceTrackingStoreError,
    associate_face_detections,
)
from forenx.cases import (
    ActivityEvent,
    CaseAssignmentAlreadyExistsError,
    CaseAssignmentNotFoundError,
    CaseAssignmentRecord,
    CaseNotFoundError,
    CaseRecord,
    CaseStatus,
    CaseStore,
    ConcurrentCaseUpdateError,
    DuplicateCaseReferenceError,
    DuplicateExhibitNumberError,
    ExhibitRecord,
    InvalidCaseTransitionError,
)
from forenx.evidence import (
    EvidenceCatalog,
    EvidenceCatalogError,
    EvidenceMediaKind,
    EvidenceNotFoundError,
    EvidenceRecord,
    EvidenceSourceError,
    RawEvidenceSource,
)
from forenx.recovery import (
    RecoveryArtifact,
    RecoveryArtifactExistsError,
    RecoveryArtifactNotFoundError,
    RecoveryScan,
    RecoveryScanNotFoundError,
    RecoveryStore,
    RecoveryStoreError,
)
from forenx.reporting import (
    ReportPackageError,
    ReportPackageNotFoundError,
    ReportPackageRecord,
    ReportPackageService,
)
from forenx.video import (
    BookmarkRecord,
    MediaInspectionError,
    MediaInspectionNotFoundError,
    MediaInspector,
    MediaStore,
    MediaStoreError,
    StoredMediaInspection,
)

PLAYBACK_COOKIE = "forenx_playback_session"


def create_app(
    *,
    adapter_registry: AdapterRegistry | None = None,
    case_store: CaseStore | None = None,
    auth_store: AuthStore | None = None,
    evidence_catalog: EvidenceCatalog | None = None,
    media_store: MediaStore | None = None,
    media_inspector: MediaInspector | None = None,
    report_service: ReportPackageService | None = None,
    biometric_authorization_store: BiometricAuthorizationStore | None = None,
    face_detection_store: FaceDetectionStore | None = None,
    face_detector: FaceDetector | None = None,
    face_tracking_store: FaceTrackingStore | None = None,
    recovery_store: RecoveryStore | None = None,
    setup_code: str | None = None,
) -> FastAPI:
    """Create the local API without performing evidence I/O at import time."""
    application = FastAPI(
        title="ForenX",
        description="Offline-first DVR/NVR forensic recovery service",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
    )
    registry = adapter_registry or default_adapter_registry()
    cases = case_store or CaseStore()
    auth = auth_store or AuthStore()
    evidence = evidence_catalog
    media = media_store
    inspector = media_inspector
    reports = report_service
    biometric_authorizations = biometric_authorization_store
    face_detections = face_detection_store
    detector = face_detector
    face_tracks = face_tracking_store
    recovery = recovery_store
    bearer = HTTPBearer(auto_error=False)

    def session_user(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer),
        ],
    ) -> UserRecord:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise _unauthorized()
        try:
            return auth.resolve_session(credentials.credentials, allow_password_change=True)
        except AuthenticationError as exc:
            raise _unauthorized() from exc

    def authorize(user: UserRecord, permission: Permission) -> None:
        try:
            require_permission(user, permission)
        except AuthorizationError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail="Your role does not permit this operation",
            ) from exc

    def authorize_case(
        user: UserRecord,
        case_id: str,
        permission: Permission,
    ) -> CaseRecord:
        authorize(user, permission)
        try:
            case = cases.get_case(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc
        if user.role is not Role.ADMINISTRATOR and not cases.has_access(
            case_id, user.user_id
        ):
            raise _not_found(CaseNotFoundError("Case was not found"))
        return case

    SessionUser = Annotated[UserRecord, Depends(session_user)]

    def current_user(user: SessionUser) -> UserRecord:
        if user.must_change_password:
            raise HTTPException(status_code=403, detail="Password change required")
        return user

    CurrentUser = Annotated[UserRecord, Depends(current_user)]

    def account_error(exc: Exception) -> HTTPException:
        if isinstance(exc, AuthenticationThrottled):
            return HTTPException(
                status_code=429,
                detail="Too many attempts. Try again later.",
                headers={"Retry-After": str(exc.retry_after)},
            )
        if isinstance(exc, AuthenticationError):
            return HTTPException(status_code=400, detail="Password confirmation failed")
        if isinstance(exc, AuthorizationError):
            return HTTPException(status_code=403, detail="Your role does not permit this operation")
        if isinstance(exc, UserNotFoundError):
            return HTTPException(status_code=404, detail=str(exc))
        if isinstance(exc, AuthStoreError):
            return HTTPException(status_code=409, detail=str(exc))
        return HTTPException(status_code=422, detail=str(exc))

    def clear_playback_cookie(response: Response) -> None:
        response.delete_cookie(
            PLAYBACK_COOKIE, path="/api/v1/evidence", httponly=True, samesite="strict",
        )

    @application.middleware("http")
    async def secure_local_responses(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path == "/" or request.url.path.startswith("/app"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                "script-src 'self'; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response
    @application.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def ready() -> dict[str, str]:
        return {
            "status": "ready",
            "service": "forenx-api",
            "version": __version__,
        }

    @application.get("/api/v1/vendors", tags=["adapters"])
    def vendors() -> dict[str, object]:
        return {
            "vendors": [
                registration.summary() for registration in registry.registrations
            ],
            "support_rule": (
                "A vendor is validated only after named real-device models pass "
                "repeatable recovery tests"
            ),
        }

    @application.post(
        "/api/v1/setup",
        response_model=UserResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["authentication"],
    )
    def setup(request: SetupRequest) -> UserRecord:
        if auth.count_users() > 0:
            raise HTTPException(status_code=409, detail="Administrator setup is already complete")
        if setup_code is None or not hmac.compare_digest(
            request.setup_code.encode(), setup_code.encode(),
        ):
            raise HTTPException(status_code=403, detail="A valid installation code is required")
        try:
            return auth.bootstrap_administrator(**request.model_dump(exclude={"setup_code"}))
        except AuthStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    @application.get("/api/v1/setup/status", tags=["authentication"])
    def setup_status() -> dict[str, bool]:
        return {"initialized": auth.count_users() > 0}

    @application.post(
        "/api/v1/auth/login",
        response_model=SessionResponse,
        tags=["authentication"],
    )
    def login(request: LoginRequest, response: Response, connection: Request) -> object:
        try:
            session = auth.authenticate(**request.model_dump())
        except AuthenticationThrottled as exc:
            raise account_error(exc) from exc
        except AuthenticationError as exc:
            raise _unauthorized("Invalid username or password") from exc
        except ValueError as exc:
            raise _unauthorized("Invalid username or password") from exc
        response.set_cookie(
            key=PLAYBACK_COOKIE,
            value=session.token,
            max_age=max(1, int((session.expires_at - datetime.now(UTC)).total_seconds())),
            httponly=True,
            secure=connection.url.scheme == "https",
            samesite="strict",
            path="/api/v1/evidence",
        )
        return session

    @application.get(
        "/api/v1/auth/me",
        response_model=UserResponse,
        tags=["authentication"],
    )
    def authenticated_user(user: SessionUser) -> UserRecord:
        return user

    @application.post(
        "/api/v1/auth/logout",
        status_code=http_status.HTTP_204_NO_CONTENT,
        tags=["authentication"],
    )
    def logout(
        response: Response,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer),
        ],
        _user: SessionUser,
    ) -> None:
        if credentials is None:
            raise _unauthorized()
        try:
            auth.revoke_session(credentials.credentials)
        except AuthenticationError as exc:
            raise _unauthorized() from exc
        clear_playback_cookie(response)

    @application.post("/api/v1/auth/logout-all", status_code=204, tags=["authentication"])
    def logout_all(response: Response, user: SessionUser) -> None:
        auth.revoke_all_sessions(user.user_id)
        clear_playback_cookie(response)

    @application.post("/api/v1/auth/password", status_code=204, tags=["authentication"])
    def change_password(
        request: ChangePasswordRequest, response: Response, user: SessionUser,
    ) -> None:
        try:
            auth.change_password(user.user_id, **request.model_dump())
        except (AuthenticationError, AuthorizationError, AuthStoreError, ValueError) as exc:
            raise account_error(exc) from exc
        clear_playback_cookie(response)

    @application.get(
        "/api/v1/auth/events", response_model=list[AuthEventResponse], tags=["administration"],
    )
    def auth_events(
        user: CurrentUser,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        before: Annotated[int | None, Query(ge=1)] = None,
    ) -> tuple[AuthEvent, ...]:
        authorize(user, Permission.USER_MANAGE)
        return auth.list_auth_events(limit=limit, before=before)

    @application.get(
        "/api/v1/auth/events/verify",
        response_model=AuthAuditVerificationResponse,
        tags=["administration"],
    )
    def verify_auth_events(user: CurrentUser) -> AuthAuditVerification:
        authorize(user, Permission.USER_MANAGE)
        return auth.verify_auth_events()

    @application.post(
        "/api/v1/users",
        response_model=UserResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["administration"],
    )
    def create_user(request: CreateUserRequest, user: CurrentUser) -> UserRecord:
        authorize(user, Permission.USER_MANAGE)
        try:
            return auth.create_user(
                **request.model_dump(), actor_id=user.user_id, must_change_password=True,
            )
        except AuthStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    @application.patch(
        "/api/v1/users/{user_id}/status", response_model=UserResponse, tags=["administration"],
    )
    def set_user_status(
        user_id: str, request: SetUserStatusRequest, user: CurrentUser,
    ) -> UserRecord:
        authorize(user, Permission.USER_MANAGE)
        try:
            return auth.set_user_active(
                actor_id=user.user_id, user_id=user_id, **request.model_dump(),
            )
        except (AuthenticationError, AuthorizationError, AuthStoreError, ValueError) as exc:
            raise account_error(exc) from exc

    @application.post(
        "/api/v1/users/{user_id}/reset-password",
        response_model=UserResponse,
        tags=["administration"],
    )
    def reset_user_password(
        user_id: str, request: ResetPasswordRequest, user: CurrentUser,
    ) -> UserRecord:
        authorize(user, Permission.USER_MANAGE)
        try:
            return auth.reset_password(
                actor_id=user.user_id, user_id=user_id, **request.model_dump(),
            )
        except (AuthenticationError, AuthorizationError, AuthStoreError, ValueError) as exc:
            raise account_error(exc) from exc

    @application.post(
        "/api/v1/users/{user_id}/revoke-sessions", status_code=204, tags=["administration"],
    )
    def revoke_user_sessions(
        user_id: str, request: ConfirmAccountActionRequest, user: CurrentUser,
    ) -> None:
        authorize(user, Permission.USER_MANAGE)
        try:
            auth.revoke_user_sessions(
                actor_id=user.user_id, user_id=user_id, **request.model_dump(),
            )
        except (AuthenticationError, AuthorizationError, AuthStoreError, ValueError) as exc:
            raise account_error(exc) from exc

    @application.get(
        "/api/v1/users",
        response_model=list[UserResponse],
        tags=["administration"],
    )
    def list_users(user: CurrentUser) -> tuple[UserRecord, ...]:
        authorize(user, Permission.CASE_ASSIGN)
        return auth.list_users()

    @application.get(
        "/api/v1/cases",
        response_model=list[CaseResponse],
        tags=["cases"],
    )
    def list_cases(
        user: CurrentUser,
        status: CaseStatus | None = None,
    ) -> tuple[CaseRecord, ...]:
        authorize(user, Permission.CASE_READ)
        if user.role is Role.ADMINISTRATOR:
            return cases.list_cases(status=status)
        return cases.list_cases_for_user(user.user_id, status=status)

    @application.post(
        "/api/v1/cases",
        response_model=CaseResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["cases"],
    )
    def create_case(request: CreateCaseRequest, user: CurrentUser) -> CaseRecord:
        authorize(user, Permission.CASE_CREATE)
        try:
            return cases.create_case(actor_id=user.user_id, **request.model_dump())
        except DuplicateCaseReferenceError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/v1/cases/{case_id}",
        response_model=CaseResponse,
        tags=["cases"],
    )
    def get_case(case_id: str, user: CurrentUser) -> CaseRecord:
        return authorize_case(user, case_id, Permission.CASE_READ)

    @application.get(
        "/api/v1/cases/{case_id}/assignments",
        response_model=list[CaseAssignmentResponse],
        tags=["cases"],
    )
    def list_case_assignments(
        case_id: str,
        user: CurrentUser,
        include_revoked: bool = False,
    ) -> tuple[CaseAssignmentRecord, ...]:
        authorize_case(user, case_id, Permission.CASE_ASSIGN)
        return cases.list_assignments(case_id, include_revoked=include_revoked)

    @application.post(
        "/api/v1/cases/{case_id}/assignments",
        response_model=CaseAssignmentResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["cases"],
    )
    def assign_case_user(
        case_id: str,
        request: CreateCaseAssignmentRequest,
        user: CurrentUser,
    ) -> CaseAssignmentRecord:
        authorize_case(user, case_id, Permission.CASE_ASSIGN)
        try:
            target = auth.get_user(request.user_id)
            if not target.active:
                raise ValueError("Inactive users cannot be assigned to cases")
            return cases.assign_user(
                case_id,
                target.user_id,
                assigned_by=user.user_id,
            )
        except UserNotFoundError as exc:
            raise _not_found(exc) from exc
        except CaseAssignmentAlreadyExistsError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    @application.post(
        "/api/v1/cases/{case_id}/assignments/{user_id}/revoke",
        response_model=CaseAssignmentResponse,
        tags=["cases"],
    )
    def revoke_case_user(
        case_id: str,
        user_id: str,
        user: CurrentUser,
    ) -> CaseAssignmentRecord:
        authorize_case(user, case_id, Permission.CASE_ASSIGN)
        if user.role is not Role.ADMINISTRATOR and user.user_id == user_id:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="A supervisor cannot revoke their own case access",
            )
        try:
            auth.get_user(user_id)
            return cases.revoke_user(
                case_id,
                user_id,
                revoked_by=user.user_id,
            )
        except UserNotFoundError as exc:
            raise _not_found(exc) from exc
        except CaseAssignmentNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @application.post(
        "/api/v1/cases/{case_id}/transition",
        response_model=CaseResponse,
        tags=["cases"],
    )
    def transition_case(
        case_id: str,
        request: TransitionCaseRequest,
        user: CurrentUser,
    ) -> CaseRecord:
        permission = (
            Permission.CASE_APPROVE
            if request.target_status in {CaseStatus.APPROVED, CaseStatus.CLOSED}
            else Permission.CASE_PROCESS
        )
        authorize_case(user, case_id, permission)
        try:
            return cases.transition_case(
                case_id,
                request.target_status,
                expected_version=request.expected_version,
                actor_id=user.user_id,
                reason=request.reason,
            )
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc
        except (ConcurrentCaseUpdateError, InvalidCaseTransitionError) as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/v1/cases/{case_id}/exhibits",
        response_model=list[ExhibitResponse],
        tags=["exhibits"],
    )
    def list_exhibits(case_id: str, user: CurrentUser) -> tuple[ExhibitRecord, ...]:
        authorize_case(user, case_id, Permission.CASE_READ)
        try:
            return cases.list_exhibits(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

    @application.post(
        "/api/v1/cases/{case_id}/exhibits",
        response_model=ExhibitResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["exhibits"],
    )
    def create_exhibit(
        case_id: str,
        request: CreateExhibitRequest,
        user: CurrentUser,
    ) -> ExhibitRecord:
        authorize_case(user, case_id, Permission.EXHIBIT_CREATE)
        try:
            return cases.add_exhibit(
                case_id,
                actor_id=user.user_id,
                **request.model_dump(),
            )
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc
        except DuplicateExhibitNumberError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/v1/cases/{case_id}/activity",
        response_model=list[ActivityResponse],
        tags=["cases"],
    )
    def list_activity(case_id: str, user: CurrentUser) -> tuple[ActivityEvent, ...]:
        authorize_case(user, case_id, Permission.CASE_READ)
        try:
            return cases.list_activity(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get(
        "/api/v1/cases/{case_id}/activity/verify",
        response_model=ActivityVerificationResponse,
        tags=["cases"],
    )
    def verify_activity(case_id: str, user: CurrentUser) -> object:
        authorize_case(user, case_id, Permission.CASE_READ)
        try:
            return cases.verify_activity(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get(
        "/api/v1/cases/{case_id}/evidence",
        response_model=list[EvidenceResponse],
        response_model_exclude_none=True,
        tags=["evidence"],
    )
    def list_evidence(case_id: str, user: CurrentUser) -> tuple[EvidenceRecord, ...]:
        authorize_case(user, case_id, Permission.CASE_READ)
        return _required_evidence_catalog(evidence).list_for_case(case_id)

    @application.post(
        "/api/v1/cases/{case_id}/exhibits/{exhibit_id}/evidence",
        response_model=EvidenceResponse,
        response_model_exclude_none=True,
        status_code=http_status.HTTP_201_CREATED,
        tags=["evidence"],
    )
    async def ingest_evidence(
        case_id: str,
        exhibit_id: str,
        request: Request,
        user: CurrentUser,
        filename: Annotated[
            str,
            Header(alias="X-ForenX-Filename", min_length=1, max_length=768),
        ],
        media_kind: Annotated[
            EvidenceMediaKind,
            Header(alias="X-ForenX-Media-Kind"),
        ],
    ) -> EvidenceRecord:
        authorize_case(user, case_id, Permission.EVIDENCE_INGEST)
        try:
            exhibit = cases.get_exhibit(exhibit_id)
            if exhibit.case_id != case_id:
                raise CaseNotFoundError("Exhibit was not found in this case")
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

        content_length = _content_length(request.headers.get("content-length"))
        cases.record_activity(
            case_id,
            actor_id=user.user_id,
            action="EVIDENCE_INGEST_STARTED",
            details={
                "exhibit_id": exhibit_id,
                "filename": filename,
                "media_kind": media_kind.value,
                "declared_size": content_length,
            },
        )
        try:
            record = await _required_evidence_catalog(evidence).ingest(
                request.stream(),
                case_id=case_id,
                exhibit_id=exhibit_id,
                original_filename=filename,
                media_kind=media_kind,
                created_by=user.user_id,
                declared_size=content_length,
            )
        except EvidenceCatalogError as exc:
            cases.record_activity(
                case_id,
                actor_id=user.user_id,
                action="EVIDENCE_INGEST_FAILED",
                details={"exhibit_id": exhibit_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            case_id,
            actor_id=user.user_id,
            action="EVIDENCE_INGEST_COMPLETED",
            details={
                "source_id": record.source_id,
                "exhibit_id": exhibit_id,
                "byte_size": record.byte_size,
                "sha256": record.sha256,
            },
        )
        return record

    @application.post(
        "/api/v1/evidence/{source_id}/verify",
        response_model=EvidenceVerificationResponse,
        tags=["evidence"],
    )
    def verify_evidence(source_id: str, user: CurrentUser) -> dict[str, object]:
        authorize(user, Permission.CASE_PROCESS)
        catalog = _required_evidence_catalog(evidence)
        try:
            record = catalog.get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_PROCESS)
            valid, observed = catalog.verify(source_id)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        except EvidenceCatalogError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            record.case_id,
            actor_id=user.user_id,
            action="EVIDENCE_INTEGRITY_VERIFIED" if valid else "EVIDENCE_INTEGRITY_FAILED",
            details={
                "source_id": source_id,
                "expected_sha256": record.sha256,
                "observed_sha256": observed,
            },
        )
        return {
            "source_id": source_id,
            "valid": valid,
            "expected_sha256": record.sha256,
            "observed_sha256": observed,
        }

    @application.get(
        "/api/v1/evidence/{source_id}/recovery-scans",
        response_model=list[RecoveryScanResponse],
        tags=["recovery"],
    )
    def list_recovery_scans(
        source_id: str,
        user: CurrentUser,
    ) -> tuple[RecoveryScan, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            source = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, source.case_id, Permission.CASE_READ)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_recovery_store(recovery).list_for_source(source_id)

    @application.post(
        "/api/v1/evidence/{source_id}/recovery-scans",
        response_model=RecoveryScanResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["recovery"],
    )
    def create_recovery_scan(source_id: str, user: CurrentUser) -> RecoveryScan:
        authorize(user, Permission.CASE_PROCESS)
        catalog = _required_evidence_catalog(evidence)
        try:
            source = catalog.get(source_id)
            case = authorize_case(user, source.case_id, Permission.CASE_PROCESS)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if source.media_kind is not EvidenceMediaKind.RAW_DISK_IMAGE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Recovery probing requires raw-disk-image evidence",
            )
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Recovery probing cannot run on a closed case",
            )
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="RECOVERY_SCAN_STARTED",
            details={"source_id": source_id},
        )
        try:
            source_valid, observed_source_sha256 = catalog.verify(source_id)
            if not source_valid:
                raise RecoveryStoreError("Evidence integrity verification failed")
            with RawEvidenceSource(source.stored_path) as readable:
                probe_report = registry.probe_all(readable)
                best_match = probe_report.best_match()
                registration = registry.registration(best_match.adapter_id)
                recordings = tuple(registration.adapter.enumerate_recordings(readable))
            scan = _required_recovery_store(recovery).save_scan(
                case_id=source.case_id,
                source_id=source_id,
                source_sha256=observed_source_sha256,
                adapter=registration.adapter,
                best_match=best_match,
                probe_report=probe_report,
                recordings=recordings,
                created_by=user.user_id,
            )
        except (
            AmbiguousAdapterError,
            EvidenceCatalogError,
            EvidenceSourceError,
            LookupError,
            RecoveryStoreError,
            UnsupportedEvidenceError,
            ValueError,
        ) as exc:
            cases.record_activity(
                source.case_id,
                actor_id=user.user_id,
                action="RECOVERY_SCAN_FAILED",
                details={"source_id": source_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="RECOVERY_SCAN_COMPLETED",
            details={
                "scan_id": scan.scan_id,
                "source_id": source_id,
                "source_sha256": observed_source_sha256,
                "adapter_id": scan.adapter_id,
                "adapter_version": scan.adapter_version,
                "confidence": scan.confidence,
                "recording_count": len(scan.recordings),
            },
        )
        return scan

    @application.get(
        "/api/v1/recovery-scans/{scan_id}/artifacts",
        response_model=list[RecoveryArtifactResponse],
        tags=["recovery"],
    )
    def list_recovery_artifacts(
        scan_id: str,
        user: CurrentUser,
    ) -> tuple[RecoveryArtifact, ...]:
        authorize(user, Permission.CASE_READ)
        store = _required_recovery_store(recovery)
        try:
            scan = store.get_scan(scan_id)
            authorize_case(user, scan.case_id, Permission.CASE_READ)
        except RecoveryScanNotFoundError as exc:
            raise _not_found(exc) from exc
        return store.list_artifacts(scan_id)

    @application.post(
        "/api/v1/recovery-scans/{scan_id}/recordings/{recording_id}/extract",
        response_model=RecoveryArtifactResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["recovery"],
    )
    def extract_recovered_recording(
        scan_id: str,
        recording_id: str,
        user: CurrentUser,
    ) -> RecoveryArtifact:
        authorize(user, Permission.CASE_PROCESS)
        store = _required_recovery_store(recovery)
        catalog = _required_evidence_catalog(evidence)
        try:
            scan = store.get_scan(scan_id)
            case = authorize_case(user, scan.case_id, Permission.CASE_PROCESS)
        except RecoveryScanNotFoundError as exc:
            raise _not_found(exc) from exc
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Recovery extraction cannot run on a closed case",
            )
        recording = next(
            (item for item in scan.recordings if item.recording_id == recording_id),
            None,
        )
        if recording is None:
            raise _not_found(LookupError("Recovered recording was not found in this scan"))
        cases.record_activity(
            scan.case_id,
            actor_id=user.user_id,
            action="RECOVERY_EXTRACTION_STARTED",
            details={
                "scan_id": scan_id,
                "source_id": scan.source_id,
                "recording_id": recording_id,
            },
        )
        try:
            source = catalog.get(scan.source_id)
            source_valid, observed_source_sha256 = catalog.verify(scan.source_id)
            if not source_valid or not hmac.compare_digest(
                observed_source_sha256, scan.source_sha256
            ):
                raise RecoveryStoreError("Evidence integrity verification failed")
            registration = registry.registration(scan.adapter_id)
            with RawEvidenceSource(source.stored_path) as readable:
                artifact = store.extract(
                    scan=scan,
                    recording=recording,
                    source=readable,
                    adapter=registration.adapter,
                    created_by=user.user_id,
                )
        except RecoveryArtifactExistsError as exc:
            cases.record_activity(
                scan.case_id,
                actor_id=user.user_id,
                action="RECOVERY_EXTRACTION_FAILED",
                details={
                    "scan_id": scan_id,
                    "source_id": scan.source_id,
                    "recording_id": recording_id,
                    "reason": str(exc),
                },
            )
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except (
            EvidenceCatalogError,
            EvidenceNotFoundError,
            EvidenceSourceError,
            ExtractionError,
            LookupError,
            OSError,
            RecoveryStoreError,
            ValueError,
        ) as exc:
            cases.record_activity(
                scan.case_id,
                actor_id=user.user_id,
                action="RECOVERY_EXTRACTION_FAILED",
                details={
                    "scan_id": scan_id,
                    "source_id": scan.source_id,
                    "recording_id": recording_id,
                    "reason": str(exc),
                },
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            scan.case_id,
            actor_id=user.user_id,
            action="RECOVERY_EXTRACTION_COMPLETED",
            details={
                "artifact_id": artifact.artifact_id,
                "scan_id": scan_id,
                "source_id": scan.source_id,
                "recording_id": recording_id,
                "source_sha256": scan.source_sha256,
                "artifact_sha256": artifact.sha256,
                "byte_size": artifact.byte_size,
                "source_extents": [
                    {"offset": extent.offset, "length": extent.length}
                    for extent in artifact.source_extents
                ],
            },
        )
        return artifact

    @application.post(
        "/api/v1/recovery-artifacts/{artifact_id}/register-evidence",
        response_model=EvidenceResponse,
        response_model_exclude_none=True,
        status_code=http_status.HTTP_201_CREATED,
        tags=["recovery"],
    )
    def register_recovered_artifact_for_examination(
        artifact_id: str,
        user: CurrentUser,
    ) -> EvidenceRecord:
        authorize(user, Permission.CASE_PROCESS)
        store = _required_recovery_store(recovery)
        catalog = _required_evidence_catalog(evidence)
        try:
            artifact = store.get_artifact(artifact_id)
            case = authorize_case(user, artifact.case_id, Permission.CASE_PROCESS)
        except RecoveryArtifactNotFoundError as exc:
            raise _not_found(exc) from exc
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Recovered evidence cannot be registered on a closed case",
            )
        if artifact.examination_source_id is not None:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Recovered artifact is already registered for examination",
            )
        cases.record_activity(
            artifact.case_id,
            actor_id=user.user_id,
            action="RECOVERY_ARTIFACT_REGISTRATION_STARTED",
            details={
                "artifact_id": artifact_id,
                "scan_id": artifact.scan_id,
                "parent_source_id": artifact.source_id,
            },
        )
        try:
            artifact, valid, observed_sha256 = store.verify_artifact(artifact_id)
            if not valid:
                raise RecoveryStoreError("Recovered artifact integrity verification failed")
            parent = catalog.get(artifact.source_id)
            derived = catalog.register_derived_file(
                artifact.stored_path,
                case_id=artifact.case_id,
                exhibit_id=parent.exhibit_id,
                parent_source_id=parent.source_id,
                derived_artifact_id=artifact.artifact_id,
                original_filename=artifact.filename,
                media_kind=EvidenceMediaKind.VIDEO_FILE,
                expected_sha256=observed_sha256,
                derivation={
                    "kind": "exact-source-extent-recovery",
                    "scan_id": artifact.scan_id,
                    "artifact_id": artifact.artifact_id,
                    "recording_id": artifact.recording_id,
                    "parent_source_id": parent.source_id,
                    "parent_source_sha256": parent.sha256,
                    "artifact_sha256": artifact.sha256,
                    "source_extents": [
                        {"offset": extent.offset, "length": extent.length}
                        for extent in artifact.source_extents
                    ],
                    "format_hint": artifact.format_hint,
                    "validation_evidence": list(artifact.validation_evidence),
                    "warnings": list(artifact.warnings),
                },
                created_by=user.user_id,
            )
        except (EvidenceCatalogError, RecoveryStoreError, OSError, ValueError) as exc:
            cases.record_activity(
                artifact.case_id,
                actor_id=user.user_id,
                action="RECOVERY_ARTIFACT_REGISTRATION_FAILED",
                details={
                    "artifact_id": artifact_id,
                    "scan_id": artifact.scan_id,
                    "parent_source_id": artifact.source_id,
                    "reason": str(exc),
                },
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            artifact.case_id,
            actor_id=user.user_id,
            action="RECOVERY_ARTIFACT_REGISTERED",
            details={
                "artifact_id": artifact_id,
                "scan_id": artifact.scan_id,
                "parent_source_id": artifact.source_id,
                "parent_source_sha256": parent.sha256,
                "examination_source_id": derived.source_id,
                "examination_source_sha256": derived.sha256,
                "source_extents": [
                    {"offset": extent.offset, "length": extent.length}
                    for extent in artifact.source_extents
                ],
            },
        )
        return derived

    @application.get(
        "/api/v1/recovery-artifacts/{artifact_id}/download",
        response_class=FileResponse,
        tags=["recovery"],
    )
    def download_recovered_artifact(
        artifact_id: str,
        user: CurrentUser,
    ) -> FileResponse:
        authorize(user, Permission.CASE_READ)
        store = _required_recovery_store(recovery)
        try:
            artifact = store.get_artifact(artifact_id)
            authorize_case(user, artifact.case_id, Permission.CASE_READ)
            artifact, valid, observed_sha256 = store.verify_artifact(artifact_id)
        except RecoveryArtifactNotFoundError as exc:
            raise _not_found(exc) from exc
        except RecoveryStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        if not valid:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Recovered artifact integrity verification failed; download refused",
            )
        return FileResponse(
            path=artifact.stored_path,
            filename=artifact.filename,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "X-ForenX-Artifact-SHA256": observed_sha256,
            },
        )

    @application.get(
        "/api/v1/evidence/{source_id}/content",
        response_class=FileResponse,
        tags=["media"],
    )
    def evidence_content(
        source_id: str,
        session_token: Annotated[
            str | None,
            Cookie(alias=PLAYBACK_COOKIE),
        ] = None,
    ) -> FileResponse:
        if session_token is None:
            raise _unauthorized()
        try:
            user = auth.resolve_session(session_token)
            authorize(user, Permission.CASE_READ)
            record = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_READ)
        except AuthenticationError as exc:
            raise _unauthorized() from exc
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if record.media_kind is not EvidenceMediaKind.VIDEO_FILE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Only video-file evidence can be played",
            )
        return FileResponse(
            path=record.stored_path,
            filename=record.original_filename,
            content_disposition_type="inline",
            headers={"Cache-Control": "no-store"},
        )

    @application.post(
        "/api/v1/evidence/{source_id}/inspect",
        response_model=StoredMediaInspectionResponse,
        tags=["media"],
    )
    def inspect_media(source_id: str, user: CurrentUser) -> StoredMediaInspection:
        authorize(user, Permission.CASE_PROCESS)
        catalog = _required_evidence_catalog(evidence)
        try:
            record = catalog.get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_PROCESS)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if record.media_kind is not EvidenceMediaKind.VIDEO_FILE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Only video-file evidence can be inspected as media",
            )
        try:
            result = _required_media_inspector(inspector).inspect(record.stored_path)
            stored = _required_media_store(media).save_inspection(
                source_id,
                result,
                inspected_by=user.user_id,
            )
        except (MediaInspectionError, MediaStoreError) as exc:
            cases.record_activity(
                record.case_id,
                actor_id=user.user_id,
                action="MEDIA_INSPECTION_FAILED",
                details={"source_id": source_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            record.case_id,
            actor_id=user.user_id,
            action="MEDIA_INSPECTED",
            details={
                "source_id": source_id,
                "inspection_id": stored.inspection_id,
                "format": stored.result.format_name,
                "duration_seconds": stored.result.duration_seconds,
                "library": stored.result.library,
                "library_version": stored.result.library_version,
            },
        )
        return stored

    @application.get(
        "/api/v1/evidence/{source_id}/inspection",
        response_model=StoredMediaInspectionResponse,
        tags=["media"],
    )
    def latest_media_inspection(
        source_id: str,
        user: CurrentUser,
    ) -> StoredMediaInspection:
        authorize(user, Permission.CASE_READ)
        try:
            record = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_READ)
            return _required_media_store(media).latest_inspection(source_id)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        except MediaInspectionNotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get(
        "/api/v1/evidence/{source_id}/bookmarks",
        response_model=list[BookmarkResponse],
        tags=["media"],
    )
    def list_bookmarks(
        source_id: str,
        user: CurrentUser,
    ) -> tuple[BookmarkRecord, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            record = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_READ)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_media_store(media).list_bookmarks(source_id)

    @application.post(
        "/api/v1/evidence/{source_id}/bookmarks",
        response_model=BookmarkResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["media"],
    )
    def create_bookmark(
        source_id: str,
        request: CreateBookmarkRequest,
        user: CurrentUser,
    ) -> BookmarkRecord:
        authorize(user, Permission.CASE_PROCESS)
        try:
            record = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_PROCESS)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        store = _required_media_store(media)
        try:
            latest = store.latest_inspection(source_id)
            duration = latest.result.duration_seconds
            if duration is not None and request.timestamp_ms > round(duration * 1000):
                raise ValueError("Bookmark timestamp exceeds the inspected media duration")
            bookmark = store.add_bookmark(
                case_id=record.case_id,
                source_id=source_id,
                created_by=user.user_id,
                **request.model_dump(),
            )
        except (MediaInspectionNotFoundError, MediaStoreError, ValueError) as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            record.case_id,
            actor_id=user.user_id,
            action="MEDIA_BOOKMARK_CREATED",
            details={
                "source_id": source_id,
                "bookmark_id": bookmark.bookmark_id,
                "timestamp_ms": bookmark.timestamp_ms,
                "title": bookmark.title,
            },
        )
        return bookmark

    @application.get(
        "/api/v1/evidence/{source_id}/biometric-authorizations",
        response_model=list[BiometricAuthorizationResponse],
        tags=["biometrics"],
    )
    def list_biometric_authorizations(
        source_id: str,
        user: CurrentUser,
    ) -> tuple[BiometricAuthorizationRecord, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            record = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, record.case_id, Permission.CASE_READ)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_biometric_authorization_store(
            biometric_authorizations
        ).list_for_source(source_id)

    @application.post(
        "/api/v1/evidence/{source_id}/biometric-authorizations",
        response_model=BiometricAuthorizationResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["biometrics"],
    )
    def create_biometric_authorization(
        source_id: str,
        request: CreateBiometricAuthorizationRequest,
        user: CurrentUser,
    ) -> BiometricAuthorizationRecord:
        authorize(user, Permission.BIOMETRIC_AUTHORIZE)
        try:
            source = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, source.case_id, Permission.BIOMETRIC_AUTHORIZE)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if source.media_kind is not EvidenceMediaKind.VIDEO_FILE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Biometric analysis can only be authorized for video-file evidence",
            )
        case = cases.get_case(source.case_id)
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Biometric analysis cannot be authorized for a closed case",
            )
        try:
            _required_media_store(media).latest_inspection(source_id)
        except MediaInspectionNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Inspect the video before authorizing biometric analysis",
            ) from exc
        try:
            authorization = _required_biometric_authorization_store(
                biometric_authorizations
            ).authorize(
                case_id=source.case_id,
                source_id=source_id,
                authorized_by=user.user_id,
                **request.model_dump(),
            )
        except (BiometricAuthorizationError, ValueError) as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="BIOMETRIC_ANALYSIS_AUTHORIZED",
            details={
                "authorization_id": authorization.authorization_id,
                "source_id": source_id,
                "mode": authorization.mode.value,
                "legal_authority_reference": authorization.legal_authority_reference,
                "retention_until": authorization.retention_until.isoformat(),
                "threshold_policy": authorization.threshold_policy,
            },
        )
        return authorization

    @application.get(
        "/api/v1/evidence/{source_id}/face-detections",
        response_model=list[FaceDetectionRunResponse],
        tags=["biometrics"],
    )
    def list_face_detections(
        source_id: str,
        user: CurrentUser,
    ) -> tuple[FaceDetectionRun, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            source = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, source.case_id, Permission.CASE_READ)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_face_detection_store(face_detections).list_for_source(source_id)

    @application.post(
        "/api/v1/evidence/{source_id}/face-detections",
        response_model=FaceDetectionRunResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["biometrics"],
    )
    def create_face_detection(
        source_id: str,
        request: CreateFaceDetectionRequest,
        user: CurrentUser,
    ) -> FaceDetectionRun:
        authorize(user, Permission.CASE_PROCESS)
        catalog = _required_evidence_catalog(evidence)
        try:
            source = catalog.get(source_id)
            authorize_case(user, source.case_id, Permission.CASE_PROCESS)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if source.media_kind is not EvidenceMediaKind.VIDEO_FILE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Face detection can only run on video-file evidence",
            )
        case = cases.get_case(source.case_id)
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Face detection cannot run on a closed case",
            )
        try:
            inspection = _required_media_store(media).latest_inspection(source_id)
        except MediaInspectionNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Inspect the video before running face detection",
            ) from exc
        if (
            inspection.result.duration_seconds is not None
            and request.timestamp_ms > round(inspection.result.duration_seconds * 1000)
        ):
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Face-detection timestamp exceeds the inspected media duration",
            )
        try:
            authorization = _required_biometric_authorization_store(
                biometric_authorizations
            ).latest_active(source_id)
        except BiometricAuthorizationNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="An active supervisor authorization is required for face detection",
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="FACE_DETECTION_STARTED",
            details={
                "source_id": source_id,
                "authorization_id": authorization.authorization_id,
                "requested_timestamp_ms": request.timestamp_ms,
            },
        )
        try:
            source_valid, observed_source_sha256 = catalog.verify(source_id)
            if not source_valid:
                raise FaceDetectionError("Evidence integrity verification failed")
            result = _required_face_detector(detector).detect(
                source.stored_path,
                timestamp_ms=request.timestamp_ms,
            )
            run = _required_face_detection_store(face_detections).save(
                case_id=source.case_id,
                source_id=source_id,
                authorization_id=authorization.authorization_id,
                result=result,
                created_by=user.user_id,
            )
        except (EvidenceCatalogError, FaceDetectionError, FaceDetectionStoreError) as exc:
            cases.record_activity(
                source.case_id,
                actor_id=user.user_id,
                action="FACE_DETECTION_FAILED",
                details={"source_id": source_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="FACE_DETECTION_COMPLETED",
            details={
                "run_id": run.run_id,
                "source_id": source_id,
                "authorization_id": authorization.authorization_id,
                "source_sha256": observed_source_sha256,
                "source_frame_sha256": run.source_frame_sha256,
                "observed_timestamp_ms": run.observed_timestamp_ms,
                "model_id": run.model_id,
                "model_sha256": run.model_sha256,
                "preview_sha256": run.preview_sha256,
                "face_count": len(run.faces),
            },
        )
        return run

    @application.get(
        "/api/v1/evidence/{source_id}/face-detections/{run_id}/preview",
        response_class=FileResponse,
        tags=["biometrics"],
    )
    def face_detection_preview(
        source_id: str,
        run_id: str,
        session_token: Annotated[
            str | None,
            Cookie(alias=PLAYBACK_COOKIE),
        ] = None,
    ) -> FileResponse:
        if session_token is None:
            raise _unauthorized()
        try:
            user = auth.resolve_session(session_token)
            authorize(user, Permission.CASE_READ)
            run = _required_face_detection_store(face_detections).get(run_id)
        except AuthenticationError as exc:
            raise _unauthorized() from exc
        except FaceDetectionRunNotFoundError as exc:
            raise _not_found(exc) from exc
        if run.source_id != source_id:
            raise _not_found(FaceDetectionRunNotFoundError("Face-detection run was not found"))
        authorize_case(user, run.case_id, Permission.CASE_READ)
        try:
            preview_path, preview_sha256 = _required_face_detection_store(
                face_detections
            ).preview(run_id)
        except FaceDetectionStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        return FileResponse(
            path=preview_path,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store",
                "X-ForenX-Preview-SHA256": preview_sha256,
            },
        )

    @application.get(
        "/api/v1/evidence/{source_id}/face-tracks",
        response_model=list[FaceTrackingRunResponse],
        tags=["biometrics"],
    )
    def list_face_tracking_runs(
        source_id: str,
        user: CurrentUser,
    ) -> tuple[FaceTrackingRun, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            source = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, source.case_id, Permission.CASE_READ)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_face_tracking_store(face_tracks).list_for_source(source_id)

    @application.post(
        "/api/v1/evidence/{source_id}/face-tracks",
        response_model=FaceTrackingRunResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["biometrics"],
    )
    def create_face_tracking_run(
        source_id: str,
        request: CreateFaceTrackingRequest,
        user: CurrentUser,
    ) -> FaceTrackingRun:
        authorize(user, Permission.CASE_PROCESS)
        catalog = _required_evidence_catalog(evidence)
        try:
            source = catalog.get(source_id)
            case = authorize_case(user, source.case_id, Permission.CASE_PROCESS)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        if source.media_kind is not EvidenceMediaKind.VIDEO_FILE:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Face tracking can only run on video-file evidence",
            )
        if case.status is CaseStatus.CLOSED:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Face tracking cannot run on a closed case",
            )
        try:
            inspection = _required_media_store(media).latest_inspection(source_id)
        except MediaInspectionNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="Inspect the video before creating face tracks",
            ) from exc
        if (
            inspection.result.duration_seconds is not None
            and request.end_timestamp_ms
            > round(inspection.result.duration_seconds * 1000)
        ):
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Face-tracking range exceeds the inspected media duration",
            )
        try:
            authorization = _required_biometric_authorization_store(
                biometric_authorizations
            ).latest_active(source_id)
        except BiometricAuthorizationNotFoundError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail="An active supervisor authorization is required for face tracking",
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="FACE_TRACKING_STARTED",
            details={
                "source_id": source_id,
                "authorization_id": authorization.authorization_id,
                **request.model_dump(),
            },
        )
        try:
            source_valid, observed_source_sha256 = catalog.verify(source_id)
            if not source_valid:
                raise FaceTrackingError("Evidence integrity verification failed")
            result = associate_face_detections(
                _required_face_detection_store(face_detections).list_for_source(source_id),
                **request.model_dump(),
            )
            tracking = _required_face_tracking_store(face_tracks).save(
                case_id=source.case_id,
                source_id=source_id,
                authorization_id=authorization.authorization_id,
                result=result,
                created_by=user.user_id,
            )
        except (
            EvidenceCatalogError,
            FaceTrackingError,
            FaceTrackingStoreError,
            ValueError,
        ) as exc:
            cases.record_activity(
                source.case_id,
                actor_id=user.user_id,
                action="FACE_TRACKING_FAILED",
                details={"source_id": source_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="FACE_TRACKING_COMPLETED",
            details={
                "tracking_run_id": tracking.tracking_run_id,
                "source_id": source_id,
                "source_sha256": observed_source_sha256,
                "authorization_id": authorization.authorization_id,
                "included_detection_run_ids": list(tracking.included_run_ids),
                "distinct_frame_count": tracking.distinct_frame_count,
                "track_count": len(tracking.tracks),
                "algorithm": tracking.algorithm,
                "algorithm_version": tracking.algorithm_version,
            },
        )
        return tracking

    @application.get(
        "/api/v1/cases/{case_id}/reports",
        response_model=list[ReportPackageResponse],
        tags=["reports"],
    )
    def list_report_packages(
        case_id: str,
        user: CurrentUser,
    ) -> tuple[ReportPackageRecord, ...]:
        authorize_case(user, case_id, Permission.CASE_READ)
        try:
            return _required_report_service(reports).list_for_case(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc
        except ReportPackageError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc

    @application.post(
        "/api/v1/evidence/{source_id}/reports",
        response_model=ReportPackageResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["reports"],
    )
    def create_report_package(
        source_id: str,
        request: CreateReportPackageRequest,
        user: CurrentUser,
    ) -> ReportPackageRecord:
        authorize(user, Permission.CASE_APPROVE)
        try:
            source = _required_evidence_catalog(evidence).get(source_id)
            authorize_case(user, source.case_id, Permission.CASE_APPROVE)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="REPORT_EXPORT_STARTED",
            details={"source_id": source_id, "report_title": request.report_title},
        )
        try:
            package = _required_report_service(reports).create(
                source_id,
                user=user,
                signing_password=request.signing_password,
                report_title=request.report_title,
                purpose=request.purpose,
                examiner_conclusion=request.examiner_conclusion,
                limitations=tuple(request.limitations),
            )
        except ReportPackageError as exc:
            cases.record_activity(
                source.case_id,
                actor_id=user.user_id,
                action="REPORT_EXPORT_FAILED",
                details={"source_id": source_id, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        cases.record_activity(
            source.case_id,
            actor_id=user.user_id,
            action="REPORT_PACKAGE_CREATED",
            details={
                "source_id": source_id,
                "package_id": package.package_id,
                "manifest_sha256": package.manifest_sha256,
                "archive_sha256": package.archive_sha256,
                "public_key_fingerprint": package.public_key_fingerprint,
            },
        )
        return package

    @application.get(
        "/api/v1/reports/{package_id}/download",
        response_class=FileResponse,
        tags=["reports"],
    )
    def download_report_package(
        package_id: str,
        user: CurrentUser,
    ) -> FileResponse:
        authorize(user, Permission.CASE_READ)
        try:
            package = _required_report_service(reports).get(package_id)
            authorize_case(user, package.case_id, Permission.CASE_READ)
        except ReportPackageNotFoundError as exc:
            raise _not_found(exc) from exc
        except ReportPackageError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        return FileResponse(
            path=package.archive_path,
            filename=f"forenx-{package.package_id}.zip",
            media_type="application/zip",
            headers={
                "Cache-Control": "no-store",
                "X-ForenX-Archive-SHA256": package.archive_sha256,
            },
        )

    ui_directory = Path(__file__).resolve().parents[1] / "ui"
    if ui_directory.is_dir():

        @application.get("/", include_in_schema=False)
        def product_home() -> RedirectResponse:
            return RedirectResponse(
                url="/app/",
                status_code=http_status.HTTP_307_TEMPORARY_REDIRECT,
            )

        application.mount(
            "/app",
            StaticFiles(directory=ui_directory, html=True),
            name="product-ui",
        )

    return application


def _unauthorized(detail: str = "Authentication is required") -> HTTPException:
    return HTTPException(
        status_code=http_status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _not_found(exc: Exception) -> HTTPException:
    return HTTPException(
        status_code=http_status.HTTP_404_NOT_FOUND,
        detail=str(exc),
    )


def _required_evidence_catalog(catalog: EvidenceCatalog | None) -> EvidenceCatalog:
    if catalog is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent evidence storage is unavailable in this runtime",
        )
    return catalog


def _required_media_store(store: MediaStore | None) -> MediaStore:
    if store is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent media records are unavailable in this runtime",
        )
    return store


def _required_media_inspector(inspector: MediaInspector | None) -> MediaInspector:
    if inspector is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Media inspection is unavailable in this runtime",
        )
    return inspector


def _required_report_service(service: ReportPackageService | None) -> ReportPackageService:
    if service is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signed report packaging is unavailable in this runtime",
        )
    return service


def _required_biometric_authorization_store(
    store: BiometricAuthorizationStore | None,
) -> BiometricAuthorizationStore:
    if store is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Biometric authorization records are unavailable in this runtime",
        )
    return store


def _required_face_detection_store(
    store: FaceDetectionStore | None,
) -> FaceDetectionStore:
    if store is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Face-detection records are unavailable in this runtime",
        )
    return store


def _required_face_detector(detector: FaceDetector | None) -> FaceDetector:
    if detector is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Offline face detection is unavailable in this runtime",
        )
    return detector


def _required_face_tracking_store(
    store: FaceTrackingStore | None,
) -> FaceTrackingStore:
    if store is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Face-tracking records are unavailable in this runtime",
        )
    return store


def _required_recovery_store(store: RecoveryStore | None) -> RecoveryStore:
    if store is None:
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent recovery records are unavailable in this runtime",
        )
    return store


def _content_length(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Content-Length must be an integer",
        ) from exc
    if value <= 0:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Content-Length must be positive",
        )
    return value


app = create_app()
