from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from app.core.activity_logger import audit_logger, log_activity
from app.core.config import Settings, get_settings
from app.core.local_session import native_identity_selected
from app.core.logging import get_logger
from app.core.tokens import (
    create_refresh_token,
    get_refresh_cookie,
    get_request_client_ip,
    get_request_user_agent,
    new_token_jti,
    token_decode_or_none,
)
from app.db.session import get_db
from app.models import RefreshToken
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.schemas.auth import TokenResponse
from app.services._auth_session import (
    SessionCookiePlan,
    apply_session_cookie_plan,
    lock_refresh_rotation_user,
    resolve_refresh_session,
)
from app.services._auth_session_workflow import commit_refresh_session

from ._request_protection import validate_csrf, validate_request_origin
from ._shared import _build_token_response, _issue_refresh_session

router = APIRouter()
logger = get_logger("auth.refresh")


def _telemetry_fingerprint(value: str | None) -> str | None:
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _refresh_unauthorized_response(detail: str, settings: Settings) -> JSONResponse:
    response = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
    )
    apply_session_cookie_plan(
        response=response,
        settings=settings,
        plan=SessionCookiePlan(action="clear_refresh"),
    )
    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    if forbidden_response := validate_request_origin(request, settings):
        return forbidden_response
    if forbidden_response := validate_csrf(request):
        return forbidden_response

    raw_token = get_refresh_cookie(request, settings)
    current_ip = get_request_client_ip(request, settings.trusted_proxies)
    current_user_agent = get_request_user_agent(request)
    resolution = await resolve_refresh_session(
        db=db,
        raw_token=raw_token,
        settings=settings,
        current_ip=current_ip,
        current_user_agent=current_user_agent,
    )
    if not resolution.is_authorized:
        return _refresh_unauthorized_response(resolution.detail, settings)

    user = resolution.user
    refresh_row = resolution.refresh_row
    now = resolution.now
    expires_at = resolution.expires_at
    jti = resolution.jti
    user_id = resolution.user_id
    context_outcome = resolution.context_outcome or resolution.outcome
    assert user is not None
    assert refresh_row is not None
    assert now is not None
    assert jti is not None
    assert user_id is not None
    locked_user = await lock_refresh_rotation_user(
        db=db,
        user_id=user_id,
        expected_token_version=refresh_row.token_version,
    )
    if locked_user is None:
        return _refresh_unauthorized_response("Session revoked", settings)
    user = locked_user
    local_context = None
    if native_identity_selected(settings):
        from app.services._local_auth.sessions import validate_native_session

        try:
            local_context = await validate_native_session(
                db,
                settings=settings,
                user=user,
                payload=token_decode_or_none(raw_token, settings) or {},
                refresh_row=refresh_row,
            )
        except ValueError:
            return _refresh_unauthorized_response("Native session invalid", settings)
    if context_outcome.audit_plan.context_changed:
        logger.warning(
            "refresh_session_context_changed",
            user_id=user.id,
            refresh_token_id=refresh_row.id,
            ip_changed=context_outcome.ip_changed,
            old_ip_sha256=_telemetry_fingerprint(refresh_row.created_ip),
            new_ip_sha256=_telemetry_fingerprint(current_ip),
            user_agent_changed=context_outcome.user_agent_changed,
            old_user_agent_sha256=_telemetry_fingerprint(refresh_row.user_agent),
            new_user_agent_sha256=_telemetry_fingerprint(current_user_agent),
        )
        audit_logger.warning(
            "refresh_session_context_changed",
            feature="audit",
            event_type="refresh_session_context_changed",
            entity_type=ActivityEntityType.USER.value,
            entity_id=user.id,
            actor_id=user.id,
            description="Refresh session context changed",
            ip_changed=context_outcome.ip_changed,
            old_ip_sha256=_telemetry_fingerprint(refresh_row.created_ip),
            new_ip_sha256=_telemetry_fingerprint(current_ip),
            user_agent_changed=context_outcome.user_agent_changed,
            old_user_agent_sha256=_telemetry_fingerprint(refresh_row.user_agent),
            new_user_agent_sha256=_telemetry_fingerprint(current_user_agent),
        )

    child_jti = new_token_jti()
    if expires_at is None:
        return _refresh_unauthorized_response("Refresh token expired", settings)
    child_refresh_token, child_expires_at = create_refresh_token(
        user_id=user.id,
        token_version=user.token_version,
        jti=child_jti,
        settings=settings,
        expires_at=expires_at,
        local_context=local_context,
    )
    rotate_result = await db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == refresh_row.id)
        .where(RefreshToken.user_id == user_id)
        .where(RefreshToken.jti == jti)
        .where(RefreshToken.revoked_at.is_(None))
        .values(
            revoked_at=now,
            revoked_reason="rotated",
            replaced_by_jti=child_jti,
            last_used_at=now,
        )
    )
    if int(getattr(rotate_result, "rowcount", 0) or 0) != 1:
        return _refresh_unauthorized_response("Refresh session not found", settings)

    await _issue_refresh_session(
        db=db,
        request=request,
        response=response,
        user=user,
        settings=settings,
        refresh_jti=child_jti,
        refresh_token_and_expiry=(child_refresh_token, child_expires_at),
        issued_at=now,
        local_context=local_context,
    )

    await log_activity(
        db=db,
        actor=user,
        action=ActivityAction.REFRESH,
        entity_type=ActivityEntityType.USER,
        entity_id=user.id,
        entity_name=user.name,
        safe_description="User refreshed session",
        safe_description_siem="User refreshed session",
        changes={
            "result": "rotated",
            "revoke_count": 1,
            "context_changed": context_outcome.audit_plan.context_changed,
        },
    )
    token_response = _build_token_response(
        user, settings=settings, session_expires_at=expires_at, local_context=local_context
    )
    await commit_refresh_session(db)
    return token_response
