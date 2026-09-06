from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi import status as http_status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from forenx import __version__
from forenx.adapters.registry import AdapterRegistry, default_adapter_registry
from forenx.api.schemas import (
    ActivityResponse,
    ActivityVerificationResponse,
    CaseResponse,
    CreateCaseRequest,
    CreateExhibitRequest,
    CreateUserRequest,
    EvidenceResponse,
    EvidenceVerificationResponse,
    ExhibitResponse,
    LoginRequest,
    SessionResponse,
    SetupRequest,
    TransitionCaseRequest,
    UserResponse,
)
from forenx.auth import (
    AuthenticationError,
    AuthorizationError,
    AuthStore,
    AuthStoreError,
    Permission,
    UserRecord,
    require_permission,
)
from forenx.cases import (
    ActivityEvent,
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
)


def create_app(
    *,
    adapter_registry: AdapterRegistry | None = None,
    case_store: CaseStore | None = None,
    auth_store: AuthStore | None = None,
    evidence_catalog: EvidenceCatalog | None = None,
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
    bearer = HTTPBearer(auto_error=False)

    def current_user(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer),
        ],
    ) -> UserRecord:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise _unauthorized()
        try:
            return auth.resolve_session(credentials.credentials)
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

    CurrentUser = Annotated[UserRecord, Depends(current_user)]

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
        try:
            return auth.bootstrap_administrator(**request.model_dump())
        except AuthStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
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
    def login(request: LoginRequest) -> object:
        try:
            return auth.authenticate(**request.model_dump())
        except AuthenticationError as exc:
            raise _unauthorized("Invalid username or password") from exc

    @application.get(
        "/api/v1/auth/me",
        response_model=UserResponse,
        tags=["authentication"],
    )
    def authenticated_user(user: CurrentUser) -> UserRecord:
        return user

    @application.post(
        "/api/v1/auth/logout",
        status_code=http_status.HTTP_204_NO_CONTENT,
        tags=["authentication"],
    )
    def logout(
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(bearer),
        ],
        _user: CurrentUser,
    ) -> None:
        if credentials is None:
            raise _unauthorized()
        try:
            auth.revoke_session(credentials.credentials)
        except AuthenticationError as exc:
            raise _unauthorized() from exc

    @application.post(
        "/api/v1/users",
        response_model=UserResponse,
        status_code=http_status.HTTP_201_CREATED,
        tags=["administration"],
    )
    def create_user(request: CreateUserRequest, user: CurrentUser) -> UserRecord:
        authorize(user, Permission.USER_MANAGE)
        try:
            return auth.create_user(**request.model_dump())
        except AuthStoreError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

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
        return cases.list_cases(status=status)

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
        authorize(user, Permission.CASE_READ)
        try:
            return cases.get_case(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

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
        authorize(user, permission)
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
        authorize(user, Permission.CASE_READ)
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
        authorize(user, Permission.EXHIBIT_CREATE)
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
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

    @application.get(
        "/api/v1/cases/{case_id}/activity",
        response_model=list[ActivityResponse],
        tags=["cases"],
    )
    def list_activity(case_id: str, user: CurrentUser) -> tuple[ActivityEvent, ...]:
        authorize(user, Permission.CASE_READ)
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
        authorize(user, Permission.CASE_READ)
        try:
            return cases.verify_activity(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc

    @application.get(
        "/api/v1/cases/{case_id}/evidence",
        response_model=list[EvidenceResponse],
        tags=["evidence"],
    )
    def list_evidence(case_id: str, user: CurrentUser) -> tuple[EvidenceRecord, ...]:
        authorize(user, Permission.CASE_READ)
        try:
            cases.get_case(case_id)
        except CaseNotFoundError as exc:
            raise _not_found(exc) from exc
        return _required_evidence_catalog(evidence).list_for_case(case_id)

    @application.post(
        "/api/v1/cases/{case_id}/exhibits/{exhibit_id}/evidence",
        response_model=EvidenceResponse,
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
        authorize(user, Permission.EVIDENCE_INGEST)
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
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
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
            valid, observed = catalog.verify(source_id)
        except EvidenceNotFoundError as exc:
            raise _not_found(exc) from exc
        except EvidenceCatalogError as exc:
            raise HTTPException(
                status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
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
