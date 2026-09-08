"""Password challenges, MFA enrollment, one-time factors and recent-auth proofs."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

import pyotp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import coerce_utc, utc_now
from app.core.email import email_equals, normalize_email
from app.core.exceptions import AuthorizationError, ValidationError
from app.core.local_session import LocalSessionContext
from app.core.password_policy import run_password_work, validate_local_password
from app.core.production_contract import LOCAL_CHALLENGE_TTL_SECONDS
from app.core.security import get_password_hash, password_hash_needs_update, verify_password_or_dummy
from app.core.user_query_options import user_selectinload_options
from app.models import LocalAuthFactor, LocalAuthGrant, LocalAuthRecoveryCode, User
from app.schemas.local_auth import (
    ActionProofResponse,
    FactorEnrollmentResponse,
    FactorSetupResponse,
    LocalAuthChallenge,
    RecentAuthenticationRequest,
)
from app.services._auth_session_workflow.authority import invalidate_user_sessions, lock_session_user

from .artifacts import consume_grant, failed_factor, issue_grant, read_grant, revoke_grants
from .common import NativeContext, atomic_local_work, audit_local, commit_local, invalid_proof, local_user_ready


async def begin_password_login(
    db: AsyncSession, ctx: NativeContext, *, email: str, password: str, browser: str
) -> LocalAuthChallenge:
    account = normalize_email(email) or ""
    await ctx.limiter.require("password-source", ctx.source, 30, 900)
    if await ctx.limiter.password_locked(account):
        # The same response is used for absent and present accounts.
        raise invalid_proof()
    async with atomic_local_work(db):
        user = (
            await db.execute(
                select(User)
                .options(*user_selectinload_options(include_permissions=True))
                .where(email_equals(User.email, account))
            )
        ).scalar_one_or_none()
        verified_hash = user.hashed_password if user else None
        version = user.token_version if user else None

        def verify_and_upgrade() -> tuple[bool, str | None]:
            valid = verify_password_or_dummy(password, verified_hash)
            upgraded = None
            if valid and verified_hash and password_hash_needs_update(verified_hash):
                try:
                    validate_local_password(password, additions_file=ctx.settings.local_password_blocklist_file)
                except ValidationError:
                    return False, None
                upgraded = get_password_hash(password)
            return valid, upgraded

        valid, upgraded = await run_password_work(verify_and_upgrade)
        if not valid or user is None or not (local_user_ready(user) or local_user_ready(user, enrollment=True)):
            await ctx.limiter.password_failed(account)
            await audit_local(db, None, "local_login_failed")
            await commit_local(db, "login_failed")
            raise invalid_proof()
        await ctx.limiter.password_succeeded(account)
        user = await lock_session_user(db, user_id=user.id)
        if (
            user is None
            or user.token_version != version
            or user.hashed_password != verified_hash
            or not (local_user_ready(user) or local_user_ready(user, enrollment=True))
            or not user.role.is_active
        ):
            raise invalid_proof()
        if upgraded:
            user.hashed_password = upgraded  # same credential, not a version-advancing change
        factor = await db.get(LocalAuthFactor, user.id)
        enrolling = local_user_ready(user, enrollment=True)
        if not enrolling and (factor is None or factor.confirmed_at is None):
            raise invalid_proof()
        purpose = "enrollment" if enrolling else "mfa"
        _, raw = await issue_grant(
            db,
            ctx,
            user,
            purpose,
            LOCAL_CHALLENGE_TTL_SECONDS,
            browser=browser,
            generation=factor.generation if factor and not enrolling else None,
        )
        await commit_local(db, "password_challenge")
        return LocalAuthChallenge(status="enrollment_required" if enrolling else "mfa_required", challenge=raw)


async def factor_limits(ctx: NativeContext, user_id: int) -> None:
    await ctx.limiter.require("factor-source", ctx.source, 30, 900)
    await ctx.limiter.require("factor-account", str(user_id), 10, 900)


async def setup_factor(db: AsyncSession, ctx: NativeContext, *, raw: str, browser: str) -> FactorSetupResponse:
    async with atomic_local_work(db):
        _, user = await read_grant(db, ctx, raw, "enrollment", browser=browser)
        await factor_limits(ctx, user.id)
        grant, user = await read_grant(db, ctx, raw, "enrollment", browser=browser, locked=True)
        if not local_user_ready(user, enrollment=True):
            raise invalid_proof()
        factor = await db.get(LocalAuthFactor, user.id)
        if factor and factor.confirmed_at is not None:
            raise invalid_proof()
        generation, seed = uuid4().hex, pyotp.random_base32()
        key_id, encrypted = ctx.keys.encrypt("totp", seed, [ctx.installation_id, str(user.id), generation])
        if factor is None:
            factor = LocalAuthFactor(user_id=user.id)
        factor.generation, factor.key_id, factor.encrypted_seed = generation, key_id, encrypted
        factor.setup_expires_at = utc_now() + timedelta(seconds=LOCAL_CHALLENGE_TTL_SECONDS)
        factor.last_time_step = -1
        db.add(factor)
        await consume_grant(db, grant)
        _, challenge = await issue_grant(
            db, ctx, user, "setup", LOCAL_CHALLENGE_TTL_SECONDS, browser=browser, generation=generation
        )
        await commit_local(db, "factor_setup")
        return FactorSetupResponse(
            challenge=challenge,
            provisioning_uri=pyotp.TOTP(seed).provisioning_uri(name=user.email, issuer_name="RiskHub"),
        )


def recovery_digest(ctx: NativeContext, user_id: int, generation: str, code: str) -> str:
    return hashlib.sha256(
        f"riskhub-recovery-v1:{ctx.installation_id}:{user_id}:{generation}:{code}".encode()
    ).hexdigest()


async def consume_factor(
    db: AsyncSession, ctx: NativeContext, user: User, factor: LocalAuthFactor, *, code: str, method: str
) -> bool:
    if method == "totp":
        if len(code) != 6 or not code.isascii() or not code.isdigit():
            return False
        seed = ctx.keys.decrypt(
            "totp", factor.key_id, factor.encrypted_seed, [ctx.installation_id, str(user.id), factor.generation]
        )
        totp = pyotp.TOTP(seed)
        current_step = int(utc_now().timestamp()) // 30
        matched = [
            step
            for step in range(current_step - 1, current_step + 2)
            if step > factor.last_time_step and secrets.compare_digest(totp.at(step * 30), code)
        ]
        if not matched:
            return False
        factor.last_time_step = max(matched)
        db.add(factor)
        return True
    if method == "recovery_code" and factor.confirmed_at is not None and len(code) <= 128:
        digest = recovery_digest(ctx, user.id, factor.generation, code)
        result = await db.execute(
            update(LocalAuthRecoveryCode)
            .where(
                LocalAuthRecoveryCode.user_id == user.id,
                LocalAuthRecoveryCode.factor_generation == factor.generation,
                LocalAuthRecoveryCode.digest == digest,
                LocalAuthRecoveryCode.consumed_at.is_(None),
            )
            .values(consumed_at=utc_now())
        )
        return int(getattr(result, "rowcount", 0) or 0) == 1
    return False


async def confirm_factor(
    db: AsyncSession, ctx: NativeContext, *, raw: str, browser: str, code: str, method: str
) -> FactorEnrollmentResponse:
    async with atomic_local_work(db):
        _, user = await read_grant(db, ctx, raw, "setup", browser=browser)
        await factor_limits(ctx, user.id)
        grant, user = await read_grant(db, ctx, raw, "setup", browser=browser, locked=True)
        factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
        expiry = coerce_utc(factor.setup_expires_at) if factor else None
        if (
            not local_user_ready(user, enrollment=True)
            or not user.role.is_active
            or factor is None
            or factor.confirmed_at is not None
            or grant.factor_generation != factor.generation
            or expiry is None
            or expiry <= utc_now()
        ):
            raise invalid_proof()
        if method != "totp" or not await consume_factor(db, ctx, user, factor, code=code, method=method):
            await failed_factor(db, grant, user)
        await consume_grant(db, grant)
        factor.confirmed_at, factor.setup_expires_at = utc_now(), None
        codes = [secrets.token_urlsafe(16) for _ in range(10)]
        for backup in codes:
            db.add(
                LocalAuthRecoveryCode(
                    user_id=user.id,
                    factor_generation=factor.generation,
                    digest=recovery_digest(ctx, user.id, factor.generation, backup),
                )
            )
        user.local_enrollment_state, user.is_active = "enrolled", True
        await invalidate_user_sessions(db=db, user=user, reason="local_factor_enrolled")
        await revoke_grants(db, user.id)
        await audit_local(db, user, "local_factor_enrolled")
        await commit_local(db, "factor_confirmed")
        return FactorEnrollmentResponse(recovery_codes=codes)


@dataclass(frozen=True)
class CompletedLocalAuthentication:
    user: User
    session: LocalSessionContext


async def verify_factor(
    db: AsyncSession, ctx: NativeContext, *, raw: str, browser: str, code: str, method: str
) -> CompletedLocalAuthentication:
    """Leave the transaction open so the canonical issuer commits factor + session together."""
    _, user = await read_grant(db, ctx, raw, "mfa", browser=browser)
    await factor_limits(ctx, user.id)
    grant, user = await read_grant(db, ctx, raw, "mfa", browser=browser, locked=True)
    factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
    if (
        not local_user_ready(user)
        or not user.role.is_active
        or factor is None
        or factor.confirmed_at is None
        or grant.factor_generation != factor.generation
    ):
        raise invalid_proof()
    if not await consume_factor(db, ctx, user, factor, code=code, method=method):
        await failed_factor(db, grant, user)
    await consume_grant(db, grant)
    await audit_local(db, user, "local_login_completed", actor=user)
    return CompletedLocalAuthentication(
        user, LocalSessionContext.completed(factor_generation=factor.generation, installation_id=ctx.installation_id)
    )


def intent_value(data: RecentAuthenticationRequest) -> str:
    if data.operation == "password_change":
        if data.intended_password is None:
            raise invalid_proof()
        return data.intended_password.get_secret_value()
    if data.operation == "email_change":
        if data.intended_email is None:
            raise invalid_proof()
        return normalize_email(str(data.intended_email)) or ""
    return data.operation


def intent_context(ctx: NativeContext, user: User, operation: str, target: int) -> list[str]:
    return ["recent-auth", ctx.installation_id, str(user.id), str(user.token_version), operation, str(target)]


async def recent_authentication(
    db: AsyncSession, ctx: NativeContext, actor: User, data: RecentAuthenticationRequest, *, browser: str
) -> ActionProofResponse:
    if data.target_user_id != actor.id or data.operation == "assisted_recovery":
        raise AuthorizationError("Assisted recovery is not available in this delivery")
    await ctx.limiter.require("password-source", ctx.source, 30, 900)
    await factor_limits(ctx, actor.id)
    account = normalize_email(actor.email) or ""
    if await ctx.limiter.password_locked(account):
        raise invalid_proof()
    async with atomic_local_work(db):
        snapshot_user = (
            await db.execute(
                select(User).options(*user_selectinload_options(include_permissions=True)).where(User.id == actor.id)
            )
        ).scalar_one()
        version, encoded = snapshot_user.token_version, snapshot_user.hashed_password
        if not await run_password_work(lambda: verify_password_or_dummy(data.password.get_secret_value(), encoded)):
            await ctx.limiter.password_failed(account)
            await audit_local(db, None, "local_recent_auth_failed")
            await commit_local(db, "recent_auth_failed")
            raise invalid_proof()
        user = await lock_session_user(db, user_id=actor.id)
        if (
            user is None
            or user.token_version != version
            or user.hashed_password != encoded
            or not local_user_ready(user)
            or not user.role.is_active
        ):
            raise invalid_proof()
        factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
        if factor is None or factor.confirmed_at is None:
            raise invalid_proof()
        if not await consume_factor(db, ctx, user, factor, code=data.factor.get_secret_value(), method=data.method):
            await audit_local(db, user, "local_recent_factor_failed")
            await commit_local(db, "recent_factor_failed")
            raise invalid_proof()
        key_id, commitment = ctx.keys.commitment(
            intent_value(data), context=intent_context(ctx, user, data.operation, data.target_user_id)
        )
        _, raw = await issue_grant(
            db,
            ctx,
            user,
            "recent",
            LOCAL_CHALLENGE_TTL_SECONDS,
            browser=browser,
            generation=factor.generation,
            context={"operation": data.operation, "target": user.id, "intent_key": key_id, "intent": commitment},
        )
        await commit_local(db, "recent_auth")
        return ActionProofResponse(proof=raw)


async def check_recent_proof(
    db: AsyncSession,
    ctx: NativeContext,
    actor: User,
    *,
    raw: str,
    operation: str,
    value: str,
    browser: str,
    locked: bool = True,
) -> tuple[LocalAuthGrant, User]:
    grant, user = await read_grant(db, ctx, raw, "recent", locked=locked, browser=browser, expected_user_id=actor.id)
    if (
        not local_user_ready(user)
        or grant.context.get("operation") != operation
        or grant.context.get("target") != user.id
    ):
        raise invalid_proof()
    _, expected = ctx.keys.commitment(
        value, key_id=grant.context.get("intent_key"), context=intent_context(ctx, user, operation, user.id)
    )
    if not secrets.compare_digest(expected, grant.context.get("intent", "")):
        raise invalid_proof()
    factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
    if factor is None or factor.confirmed_at is None or factor.generation != grant.factor_generation:
        raise invalid_proof()
    return grant, user
