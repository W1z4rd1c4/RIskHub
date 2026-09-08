from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import Settings
from app.core.datetime_utils import coerce_utc, utc_now
from app.core.local_session import LocalSessionContext, native_identity_selected
from app.core.permissions import get_effective_permissions, get_scope_label, is_platform_admin
from app.core.security import create_access_token
from app.core.tokens import (
    create_refresh_token,
    get_request_client_ip,
    get_request_user_agent,
    new_token_jti,
    set_csrf_cookie,
    set_refresh_cookie,
)
from app.models import RefreshToken, User
from app.schemas.auth import TokenResponse
from app.schemas.user import AccessScopeEnum, UserBrief
from app.services._directory_identity import resolve_safe_default_role as resolve_directory_safe_default_role

if TYPE_CHECKING:
    from app.models import Role

SESSION_RENEWAL_MINIMUM_SECONDS = 60


def _sha256_trunc(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _resolve_access_expires_delta(
    *,
    user: User,
    settings: Settings,
    session_expires_at: datetime | None = None,
) -> timedelta:
    configured_minutes = (
        settings.platform_admin_access_token_expire_minutes
        if is_platform_admin(user)
        else settings.access_token_expire_minutes
    )
    configured_lifetime = timedelta(minutes=configured_minutes)
    if session_expires_at is None:
        return configured_lifetime

    coerced_session_expires_at = coerce_utc(session_expires_at)
    if coerced_session_expires_at is None:
        return configured_lifetime
    remaining = coerced_session_expires_at - utc_now()
    if remaining.total_seconds() <= SESSION_RENEWAL_MINIMUM_SECONDS:
        raise ValueError("session_expiring")
    return min(configured_lifetime, remaining)


def _build_token_response(
    user: User,
    *,
    settings: Settings,
    session_expires_at: datetime | None = None,
    post_login_redirect_to: str | None = None,
    local_context: LocalSessionContext | None = None,
) -> TokenResponse:
    if native_identity_selected(settings) and local_context is None:
        raise ValueError("Completed native MFA context is required")
    if local_context is not None:
        session_expires_at = local_context.expires_at
    effective_permissions = get_effective_permissions(user)
    scope_label = get_scope_label(user)
    user_data = UserBrief(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role.name,
        role_display_name=user.role.display_name,
        entra_business_role=user.entra_business_role,
        department_id=user.department_id,
        department_name=user.department.name if user.department else None,
        permissions=effective_permissions,
        effective_permissions=effective_permissions,
        access_scope=AccessScopeEnum(user.access_scope.value),
        scope_label=scope_label,
    )
    access_token = create_access_token(
        data={
            "sub": user.email,
            "user_id": user.id,
            "token_version": user.token_version,
            **(local_context.claims() if local_context else {}),
        },
        expires_delta=_resolve_access_expires_delta(
            user=user,
            settings=settings,
            session_expires_at=session_expires_at,
        ),
        settings=settings,
    )
    return TokenResponse(
        access_token=access_token,
        user=user_data,
        post_login_redirect_to=post_login_redirect_to,
    )


async def _issue_refresh_session(
    *,
    db: AsyncSession,
    request: Request,
    response: Response,
    user: User,
    settings: Settings,
    rotated_from: RefreshToken | None = None,
    refresh_jti: str | None = None,
    refresh_token_and_expiry: tuple[str, datetime] | None = None,
    issued_at: datetime | None = None,
    local_context: LocalSessionContext | None = None,
) -> RefreshToken:
    if native_identity_selected(settings) and local_context is None:
        raise ValueError("Completed native MFA context is required")
    jti = refresh_jti or new_token_jti()
    if refresh_token_and_expiry is None:
        refresh_token, expires_at = create_refresh_token(
            user_id=user.id,
            token_version=user.token_version,
            jti=jti,
            settings=settings,
            local_context=local_context,
            expires_at=local_context.expires_at if local_context else None,
        )
    else:
        refresh_token, expires_at = refresh_token_and_expiry

    now = issued_at or utc_now()
    coerced_expires_at = coerce_utc(expires_at)
    cookie_max_age = max(int(((coerced_expires_at or now) - now).total_seconds()), 0)
    refresh_row = RefreshToken(
        user_id=user.id,
        jti=jti,
        token_version=user.token_version,
        expires_at=expires_at,
        issued_at=now,
        last_used_at=now,
        created_ip=get_request_client_ip(request, settings.trusted_proxies),
        user_agent=get_request_user_agent(request),
    )
    if local_context is not None:
        refresh_row.auth_method = "local_mfa"
        refresh_row.authenticated_at = local_context.authenticated_at
        refresh_row.factor_generation = local_context.factor_generation
        refresh_row.installation_id = local_context.installation_id
    db.add(refresh_row)
    if rotated_from is not None:
        rotated_from.revoked_at = now
        rotated_from.revoked_reason = "rotated"
        rotated_from.replaced_by_jti = jti
        db.add(rotated_from)

    set_refresh_cookie(response, refresh_token, settings, max_age=cookie_max_age)
    set_csrf_cookie(response, settings, max_age=cookie_max_age)
    return refresh_row


async def _resolve_safe_default_role(db: AsyncSession) -> Role:
    return await resolve_directory_safe_default_role(
        db,
        exception_factory=lambda message: HTTPException(status_code=500, detail=message),
    )
