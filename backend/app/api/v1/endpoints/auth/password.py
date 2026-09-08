from typing import Awaitable, Callable, TypeVar

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import Settings, get_settings
from app.core.email import email_equals
from app.core.identity_policy import can_authenticate_user
from app.core.local_session import native_identity_selected
from app.core.logging import get_logger
from app.core.security import verify_password_or_dummy
from app.core.user_query_options import user_selectinload_options
from app.db.session import get_db
from app.models import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.local_auth import LocalAuthChallenge
from app.services._auth_session_workflow import commit_failed_password_login, commit_successful_password_login
from app.services._auth_session_workflow.authority import lock_session_user
from app.services._local_auth.factors import begin_password_login
from app.services.account_lockout_service import AccountLockoutBackendError

from ._local_transport import SafeAuthRoute, establish_browser, native_context
from ._request_protection import validate_request_origin
from ._shared import _build_token_response, _issue_refresh_session

router = APIRouter(route_class=SafeAuthRoute)
logger = get_logger("auth.password")
_T = TypeVar("_T")


def _raise_lockout_backend_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail="Authentication backend temporarily unavailable. Please retry.",
        headers={"Retry-After": "5"},
    )


async def _run_lockout_operation(
    *,
    settings: Settings,
    operation_name: str,
    operation: Callable[[], Awaitable[_T]],
    fallback: _T,
) -> _T:
    try:
        return await operation()
    except AccountLockoutBackendError as exc:
        logger.warning("auth_lockout_backend_error", operation=operation_name, error=str(exc))
        if settings.redis.lockout_fail_closed_on_backend_error:
            _raise_lockout_backend_unavailable()
        return fallback


@router.post(
    "/login", response_model=TokenResponse | LocalAuthChallenge, responses={202: {"model": LocalAuthChallenge}}
)
async def login(
    credentials: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """
    Authenticate user and return JWT token.

    Args:
        credentials: Email and password
        db: Database session

    Returns:
        JWT access token and user information

    Raises:
        HTTPException: If credentials are invalid or user is inactive
    """
    if settings.auth_mode == "microsoft_sso":
        raise HTTPException(status_code=403, detail="Password login is disabled. Use single sign-on (SSO).")
    if forbidden_response := validate_request_origin(request, settings):
        return forbidden_response

    if native_identity_selected(settings):
        ctx = await native_context(request, db=db, settings=settings)
        browser = establish_browser(request, response, settings)
        challenge_result = await begin_password_login(
            db, ctx, email=credentials.email, password=credentials.password, browser=browser
        )
        response.status_code = 202
        return challenge_result

    # Check if account is locked due to too many failed attempts
    account_lockout = request.app.state.account_lockout
    is_locked, lockout_remaining = await _run_lockout_operation(
        settings=settings,
        operation_name="is_locked",
        operation=lambda: account_lockout.is_locked(credentials.email),
        fallback=(False, 0),
    )
    if is_locked:
        raise HTTPException(
            status_code=429,
            detail=(
                "Account temporarily locked due to too many failed attempts. "
                f"Try again in {lockout_remaining} seconds."
            ),
            headers={"Retry-After": str(lockout_remaining)},
        )

    result = await db.execute(
        select(User)
        .options(*user_selectinload_options(include_permissions=True))
        .where(email_equals(User.email, credentials.email))
    )
    user = result.scalar_one_or_none()
    verified_version = user.token_version if user else None
    verified_hash = user.hashed_password if user else None
    password_valid = verify_password_or_dummy(credentials.password, user.hashed_password if user else None)

    if not user or not password_valid:
        # Track failed attempt
        is_now_locked = (
            await _run_lockout_operation(
                settings=settings,
                operation_name="record_failed_attempt_invalid_credentials",
                operation=lambda: account_lockout.record_failed_attempt(credentials.email),
                fallback=(False, 0),
            )
        )[0]

        from app.core.activity_logger import log_activity
        from app.models.activity_log import ActivityAction, ActivityEntityType

        await log_activity(
            db=db,
            actor=None,
            action=ActivityAction.FAILED_LOGIN,
            entity_type=ActivityEntityType.USER,
            entity_id=0,
            entity_name=credentials.email,
            safe_description=f"Failed login attempt{' (account now locked)' if is_now_locked else ''}",
            safe_description_siem=f"Failed login attempt{' (account now locked)' if is_now_locked else ''}",
            description=f"Failed login attempt: invalid credentials{' (account now locked)' if is_now_locked else ''}",
        )
        await commit_failed_password_login(db)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not can_authenticate_user(user, settings=settings):
        raise HTTPException(status_code=403, detail="User account is inactive")

    # Clear lockout tracking on successful login before issuing tokens.
    await _run_lockout_operation(
        settings=settings,
        operation_name="record_successful_login",
        operation=lambda: account_lockout.record_successful_login(credentials.email),
        fallback=None,
    )

    user = await lock_session_user(db, user_id=user.id)
    if (
        user is None
        or not can_authenticate_user(user, settings=settings)
        or user.token_version != verified_version
        or user.hashed_password != verified_hash
        or (not settings.debug and user.external_id is not None)
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token_response = _build_token_response(user, settings=settings)
    await _issue_refresh_session(db=db, request=request, response=response, user=user, settings=settings)

    from app.core.activity_logger import log_activity
    from app.models.activity_log import ActivityAction, ActivityEntityType

    # Log successful login
    await log_activity(
        db=db,
        actor=user,
        action=ActivityAction.LOGIN,
        entity_type=ActivityEntityType.USER,
        entity_id=user.id,
        entity_name=user.name,
        safe_description="User logged in",
        safe_description_siem="User logged in",
        description=f"User logged in: {user.email}",
    )

    await commit_successful_password_login(db)

    return token_response
