from __future__ import annotations

import secrets
from datetime import timedelta
from http import HTTPStatus

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from app.core.config import Settings
from app.core.datetime_utils import utc_now
from app.core.identity_policy import can_authenticate_user
from app.core.tokens import get_sso_challenge_cookie
from app.schemas.auth import SsoExchangeRequest, SsoStartRequest, SsoStartResponse
from app.services._auth_session_workflow.authority import lock_session_user
from app.services.sso_challenge_store import SsoChallenge
from app.services.sso_token_service import VerifiedIdentity

from .contracts import (
    SESSION_RENEWAL_MINIMUM_SECONDS,
    SessionCookiePlan,
    SsoExchangeResolution,
    SsoFailure,
    SsoSessionOutcome,
    SsoStartResolution,
    sso_session_outcome,
)
from .jit import resolve_jit_user, sync_sso_user_profile
from .sso_identity import log_failed_sso, verify_sso_identity


def _sanitize_return_to(value: str | None) -> str:
    if not value:
        return "/"
    normalized = value.replace("\\", "/").strip()
    if not normalized or "\r" in normalized or "\n" in normalized:
        return "/"
    if normalized.startswith("/") and not normalized.startswith("//"):
        return normalized
    return "/"


def _challenge_failure(
    *,
    status_code: int,
    code: str,
    detail: str,
) -> SsoFailure:
    return SsoFailure(status_code=status_code, detail=detail, code=code, clear_challenge_cookie=True)


async def _verify_sso_identity(
    *,
    payload: SsoExchangeRequest,
    settings: Settings,
    db: AsyncSession,
    token_verifier=None,
):
    if token_verifier is not None:
        return await verify_sso_identity(
            payload=payload,
            settings=settings,
            db=db,
            identity_verifier=token_verifier,
        )
    return await verify_sso_identity(payload=payload, settings=settings, db=db)


async def _consume_sso_challenge(
    *,
    request: Request,
    payload: SsoExchangeRequest,
    identity: VerifiedIdentity,
    db: AsyncSession,
):
    challenge_id = get_sso_challenge_cookie(request)
    if not challenge_id:
        await log_failed_sso(
            db, entity_name=identity.email or "unknown", description="Failed SSO login: challenge missing"
        )
        return None, _challenge_failure(
            status_code=HTTPStatus.UNAUTHORIZED,
            code="SSO_CHALLENGE_MISSING",
            detail="SSO login challenge missing or expired.",
        )

    challenge_store = getattr(request.app.state, "sso_challenge_store", None)
    if challenge_store is None:
        return None, SsoFailure(
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            detail="SSO challenge store unavailable.",
            code="SSO_CHALLENGE_UNAVAILABLE",
        )

    challenge = await challenge_store.consume(challenge_id)
    if challenge is None:
        await log_failed_sso(
            db, entity_name=identity.email or "unknown", description="Failed SSO login: challenge expired"
        )
        return None, _challenge_failure(
            status_code=HTTPStatus.UNAUTHORIZED,
            code="SSO_CHALLENGE_EXPIRED",
            detail="SSO login challenge expired or was already used.",
        )

    if payload.state != challenge.state:
        await log_failed_sso(
            db, entity_name=identity.email or "unknown", description="Failed SSO login: state mismatch"
        )
        return None, _challenge_failure(
            status_code=HTTPStatus.UNAUTHORIZED,
            code="SSO_STATE_MISMATCH",
            detail="SSO state mismatch.",
        )

    if not identity.nonce:
        await log_failed_sso(db, entity_name=identity.email or "unknown", description="Failed SSO login: nonce missing")
        return None, _challenge_failure(
            status_code=HTTPStatus.UNAUTHORIZED,
            code="SSO_NONCE_MISSING",
            detail="SSO token missing nonce claim.",
        )

    if identity.nonce != challenge.nonce:
        await log_failed_sso(
            db, entity_name=identity.email or "unknown", description="Failed SSO login: nonce mismatch"
        )
        return None, _challenge_failure(
            status_code=HTTPStatus.UNAUTHORIZED,
            code="SSO_NONCE_MISMATCH",
            detail="SSO nonce mismatch.",
        )

    return challenge.return_to, None


async def resolve_sso_start(
    *,
    payload: SsoStartRequest,
    request: Request,
    settings: Settings,
) -> SsoStartResolution:
    if settings.auth_mode not in ("microsoft_sso", "hybrid_dev"):
        return SsoStartResolution(
            failure=SsoFailure(status_code=HTTPStatus.FORBIDDEN, detail="SSO is not enabled.", code="SSO_DISABLED")
        )

    challenge_store = getattr(request.app.state, "sso_challenge_store", None)
    if challenge_store is None:
        return SsoStartResolution(
            failure=SsoFailure(
                status_code=HTTPStatus.SERVICE_UNAVAILABLE,
                detail="SSO challenge store unavailable.",
                code="SSO_CHALLENGE_UNAVAILABLE",
            )
        )

    ttl_seconds = max(int(settings.auth_sso_challenge_ttl_seconds), SESSION_RENEWAL_MINIMUM_SECONDS)
    existing_challenge_id = get_sso_challenge_cookie(request)
    if existing_challenge_id:
        await challenge_store.delete(existing_challenge_id)

    issued_at = utc_now()
    challenge = SsoChallenge(
        challenge_id=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        state=secrets.token_urlsafe(32),
        return_to=_sanitize_return_to(payload.return_to),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
    )
    await challenge_store.store(challenge)
    return SsoStartResolution(
        response=SsoStartResponse(nonce=challenge.nonce, state=challenge.state, expires_in=ttl_seconds),
        challenge_id=challenge.challenge_id,
        max_age=ttl_seconds,
    )


async def resolve_sso_exchange(
    *,
    payload: SsoExchangeRequest,
    request: Request,
    db: AsyncSession,
    settings: Settings,
    token_verifier=None,
) -> SsoExchangeResolution:
    if settings.auth_mode not in ("microsoft_sso", "hybrid_dev"):
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            failure=SsoFailure(status_code=HTTPStatus.FORBIDDEN, detail="SSO is not enabled.", code="SSO_DISABLED"),
        )

    identity, error_response = await _verify_sso_identity(
        payload=payload,
        settings=settings,
        db=db,
        token_verifier=token_verifier,
    )
    if error_response is not None:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            failure=error_response,
        )
    assert identity is not None

    post_login_redirect_to, challenge_error = await _consume_sso_challenge(
        request=request,
        payload=payload,
        identity=identity,
        db=db,
    )
    if challenge_error is not None:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(
                status="challenge_expired",
                cookie_plan=SessionCookiePlan(action="clear_refresh"),
            ),
            identity=identity,
            failure=challenge_error,
            clear_challenge_cookie=challenge_error.clear_challenge_cookie,
        )

    user, resolution_error = await resolve_jit_user(db=db, identity=identity, settings=settings)
    if resolution_error is not None:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            identity=identity,
            failure=resolution_error,
            clear_challenge_cookie=True,
        )
    if user is None:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            identity=identity,
            failure=SsoFailure(
                status_code=HTTPStatus.FORBIDDEN,
                detail="User not provisioned",
                code="SSO_USER_NOT_PROVISIONED",
            ),
            clear_challenge_cookie=True,
        )

    expected_version = user.token_version
    user = await lock_session_user(db, user_id=user.id)
    if user is None or user.token_version != expected_version:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            identity=identity,
            failure=SsoFailure(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail="Session authority changed; sign in again",
                code="SSO_AUTHORITY_CHANGED",
            ),
            clear_challenge_cookie=True,
        )
    profile_sync_error = await sync_sso_user_profile(db, user=user, identity=identity)
    if profile_sync_error is not None:
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            user=user,
            identity=identity,
            failure=profile_sync_error,
            clear_challenge_cookie=True,
        )

    if not can_authenticate_user(user, settings=settings):
        return SsoExchangeResolution(
            outcome=SsoSessionOutcome(status="blocked", cookie_plan=SessionCookiePlan(action="none")),
            user=user,
            identity=identity,
            failure=SsoFailure(
                status_code=HTTPStatus.FORBIDDEN,
                detail="User account is inactive",
                code="USER_INACTIVE",
            ),
            clear_challenge_cookie=True,
        )

    now = utc_now()
    outcome = sso_session_outcome(
        now=now,
        identity_expires_at=identity.expires_at,
        settings=settings,
        renewal_minimum_seconds=SESSION_RENEWAL_MINIMUM_SECONDS,
    )
    if outcome.status == "token_expired" and outcome.audit_plan is not None:
        await log_failed_sso(
            db,
            entity_name=identity.email or "unknown",
            description="Failed SSO login: token lifetime too short for local session",
        )
    if outcome.status == "token_expired":
        return SsoExchangeResolution(
            outcome=outcome,
            user=user,
            identity=identity,
            failure=SsoFailure(
                status_code=outcome.status_code or HTTPStatus.UNAUTHORIZED,
                detail=outcome.detail or "SSO token expired",
                code=outcome.code or "SSO_TOKEN_EXPIRED",
                clear_challenge_cookie=True,
            ),
            now=now,
        )

    return SsoExchangeResolution(
        outcome=outcome,
        user=user,
        identity=identity,
        post_login_redirect_to=post_login_redirect_to,
        clear_challenge_cookie=True,
        now=now,
    )
