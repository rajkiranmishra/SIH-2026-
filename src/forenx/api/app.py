from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
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


def create_app(
    *,
    adapter_registry: AdapterRegistry | None = None,
    case_store: CaseStore | None = None,
    auth_store: AuthStore | None = None,
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


app = create_app()
