from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from app.api import deps
from app.core.activity_logger import log_activity
from app.core.config import Settings, get_settings
from app.core.tokens import clear_refresh_cookie, get_refresh_cookie, token_decode_or_none
from app.db.session import get_db
from app.models import RefreshToken, User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.services._auth_session_workflow import commit_logout, commit_logout_all
from app.services._auth_session_workflow.authority import invalidate_user_sessions, lock_session_user

from ._request_protection import validate_csrf, validate_request_origin

router = APIRouter()


async def _resolve_refresh_cookie_user(
    *,
    db: AsyncSession,
    request: Request,
    settings: Settings,
) -> User | None:
    raw_token = get_refresh_cookie(request, settings)
    payload = token_decode_or_none(raw_token, settings)
    if not payload:
        return None

    user_id = payload.get("user_id")
    jti = payload.get("jti")
    token_version = payload.get("token_version")
    if type(user_id) is not int or not isinstance(jti, str) or type(token_version) is not int:
        return None

    refresh_row = (
        await db.execute(
            select(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .where(RefreshToken.jti == jti)
            .where(RefreshToken.revoked_at.is_(None))
        )
    ).scalar_one_or_none()
    if refresh_row is None:
        return None

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        return None
    if token_version != user.token_version or refresh_row.token_version != user.token_version:
        return None
    return user


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
    current_user: User | None = Depends(deps.get_current_user_optional),
):
    """
    Logout endpoint (server-side refresh token revocation + cookie clear).

    Returns:
        Success message
    """
    resolved_user = current_user
    require_csrf = False

    if resolved_user is None:
        resolved_user = await _resolve_refresh_cookie_user(db=db, request=request, settings=settings)
        require_csrf = resolved_user is not None

    if resolved_user is not None:
        if forbidden_response := validate_request_origin(request, settings):
            return forbidden_response
        if require_csrf and (forbidden_response := validate_csrf(request)):
            return forbidden_response

        expected_version = resolved_user.token_version
        resolved_user = await lock_session_user(db, user_id=resolved_user.id)
        if resolved_user is None or resolved_user.token_version != expected_version:
            clear_refresh_cookie(response, settings)
            return {"message": "Logged out successfully"}
        revoked = await invalidate_user_sessions(db=db, user=resolved_user, reason="logout")
        await log_activity(
            db=db,
            actor=resolved_user,
            action=ActivityAction.LOGOUT,
            entity_type=ActivityEntityType.USER,
            entity_id=resolved_user.id,
            entity_name=resolved_user.name,
            safe_description="User logged out",
            safe_description_siem="User logged out",
            changes={
                "logout_scope": "all_devices",
                "revoke_count": revoked,
                "result": "revoked",
            },
        )
        clear_refresh_cookie(response, settings)
        await commit_logout(db)
        return {"message": "Logged out successfully", "revoked_sessions": revoked}

    clear_refresh_cookie(response, settings)
    return {"message": "Logged out successfully"}


@router.post("/logout-all")
async def logout_all_devices(
    response: Response,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    expected_version = current_user.token_version
    locked_user = await lock_session_user(db, user_id=current_user.id)
    if locked_user is None or locked_user.token_version != expected_version:
        raise HTTPException(status_code=401, detail="Session revoked")
    revoked = await invalidate_user_sessions(db=db, user=locked_user, reason="logout_all")
    await log_activity(
        db=db,
        actor=current_user,
        action=ActivityAction.LOGOUT_ALL,
        entity_type=ActivityEntityType.USER,
        entity_id=current_user.id,
        entity_name=current_user.name,
        safe_description="User logged out from all devices",
        safe_description_siem="User logged out from all devices",
        changes={
            "logout_scope": "all_devices",
            "revoke_count": revoked,
            "result": "revoked",
        },
    )
    clear_refresh_cookie(response, settings)
    await commit_logout_all(db)

    return {"message": "Logged out from all devices", "revoked_sessions": revoked}
