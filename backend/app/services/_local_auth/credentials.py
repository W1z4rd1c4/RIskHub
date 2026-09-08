"""Password recovery and verified, recently authenticated credential changes."""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import utc_now
from app.core.email import email_equals, normalize_email
from app.core.exceptions import ConflictError
from app.core.password_policy import run_password_work, validate_local_password
from app.core.production_contract import LOCAL_RESET_TTL_SECONDS
from app.core.security import get_password_hash, verify_password
from app.core.user_query_options import user_selectinload_options
from app.models import LocalAuthFactor, User
from app.schemas.local_auth import CompletedResponse
from app.services._auth_session_workflow.authority import invalidate_user_sessions, lock_session_user

from .artifacts import consume_grant, issue_grant, read_grant, revoke_grants
from .common import NativeContext, atomic_local_work, audit_local, commit_local, invalid_proof, local_user_ready
from .delivery import enqueue_mail, validate_mail_configuration
from .factors import check_recent_proof


async def request_password_reset(
    db: AsyncSession, ctx: NativeContext, *, email: str, actor: User | None = None, reason: str | None = None
) -> None:
    account = normalize_email(email) or ""
    await ctx.limiter.require("reset-source", ctx.source, 30, 3600)
    target_allowed = await ctx.limiter.limit("reset-target", account, 3, 3600)
    # Configuration failures must not distinguish a real account from an unknown one.
    validate_mail_configuration(ctx.settings)
    async with atomic_local_work(db):
        user = (
            await db.execute(
                select(User)
                .options(*user_selectinload_options(include_permissions=True))
                .where(email_equals(User.email, account))
            )
        ).scalar_one_or_none()
        factor = await db.get(LocalAuthFactor, user.id) if user else None
        if target_allowed and user is not None and local_user_ready(user) and factor and factor.confirmed_at:
            if actor is not None:
                from app.core.permissions import is_platform_admin
                from app.services._identity_authority_lock import lock_identity_transition

                user = await lock_identity_transition(db, user_id=user.id, actor=actor)
                if not is_platform_admin(actor) or not local_user_ready(actor):
                    raise invalid_proof()
            else:
                user = await lock_session_user(db, user_id=user.id)
            if user is None or not local_user_ready(user):
                return
            await revoke_grants(db, user.id, purpose="reset")
            grant, raw = await issue_grant(
                db, ctx, user, "reset", LOCAL_RESET_TTL_SECONDS, context={"email": user.email}
            )
            await enqueue_mail(db, ctx, user, recipient=user.email, kind="reset", grant=grant, credential=raw)
            await audit_local(db, user, "local_password_reset_requested", actor=actor, reason=reason)
            await commit_local(db, "reset_request")
        else:
            # Comparable bounded cryptographic work without storing an account or
            # sending network mail. Public requests never alter session authority.
            ctx.keys.encrypt("delivery", secrets.token_urlsafe(32), [ctx.installation_id, "discarded-reset"])


async def complete_password_reset(
    db: AsyncSession, ctx: NativeContext, *, raw: str, password: str
) -> CompletedResponse:
    await ctx.limiter.require("redeem-source", ctx.source, 10, 900)
    async with atomic_local_work(db):
        grant, user = await read_grant(db, ctx, raw, "reset")
        if not local_user_ready(user) or grant.context.get("email") != user.email:
            raise invalid_proof()
        validate_local_password(password, additions_file=ctx.settings.local_password_blocklist_file)
        encoded = await run_password_work(lambda: get_password_hash(password))
        grant, user = await read_grant(db, ctx, raw, "reset", locked=True)
        factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
        if (
            not local_user_ready(user)
            or grant.context.get("email") != user.email
            or factor is None
            or factor.confirmed_at is None
        ):
            raise invalid_proof()
        await consume_grant(db, grant)
        user.hashed_password = encoded
        await invalidate_user_sessions(db=db, user=user, reason="local_password_reset")
        await revoke_grants(db, user.id)
        await enqueue_mail(db, ctx, user, recipient=user.email, kind="credentials_changed")
        await audit_local(db, user, "local_password_reset_completed")
        await commit_local(db, "reset_complete")
        return CompletedResponse()


async def change_password(
    db: AsyncSession, ctx: NativeContext, actor: User, *, proof: str, password: str, browser: str
) -> CompletedResponse:
    await ctx.limiter.require("credential-change-source", ctx.source, 30, 900)
    async with atomic_local_work(db):
        _, user = await check_recent_proof(
            db, ctx, actor, raw=proof, operation="password_change", value=password, browser=browser, locked=False
        )
        validate_local_password(password, additions_file=ctx.settings.local_password_blocklist_file)
        old_hash = user.hashed_password

        def encode_change() -> str | None:
            if old_hash and verify_password(password, old_hash):
                return None
            return get_password_hash(password)

        encoded = await run_password_work(encode_change)
        grant, user = await check_recent_proof(
            db, ctx, actor, raw=proof, operation="password_change", value=password, browser=browser
        )
        await consume_grant(db, grant)
        if encoded is None:
            await commit_local(db, "password_unchanged")
            return CompletedResponse(reauthentication_required=False)
        user.hashed_password = encoded
        await invalidate_user_sessions(db=db, user=user, reason="local_password_changed")
        await revoke_grants(db, user.id)
        await enqueue_mail(db, ctx, user, recipient=user.email, kind="credentials_changed")
        await audit_local(db, user, "local_password_changed", actor=user)
        await commit_local(db, "password_change")
        return CompletedResponse()


async def request_email_change(
    db: AsyncSession, ctx: NativeContext, actor: User, *, proof: str, email: str, browser: str
) -> None:
    address = normalize_email(email) or ""
    await ctx.limiter.require("email-change-user", str(actor.id), 3, 3600)
    async with atomic_local_work(db):
        grant, user = await check_recent_proof(
            db, ctx, actor, raw=proof, operation="email_change", value=address, browser=browser
        )
        if (
            address == user.email
            or (await db.execute(select(User.id).where(email_equals(User.email, address)))).scalar_one_or_none()
        ):
            raise ConflictError("The requested address is unavailable")
        await consume_grant(db, grant)
        await revoke_grants(db, user.id, purpose="email")
        email_grant, raw = await issue_grant(
            db, ctx, user, "email", LOCAL_RESET_TTL_SECONDS, context={"email": address, "old_email": user.email}
        )
        await enqueue_mail(db, ctx, user, recipient=address, kind="email", grant=email_grant, credential=raw)
        await enqueue_mail(db, ctx, user, recipient=user.email, kind="email_requested")
        await audit_local(db, user, "local_email_change_requested", actor=user)
        await commit_local(db, "email_request")


async def complete_email_change(
    db: AsyncSession, ctx: NativeContext, actor: User, *, raw: str, proof: str, browser: str
) -> CompletedResponse:
    await ctx.limiter.require("redeem-source", ctx.source, 10, 900)
    async with atomic_local_work(db):
        pending, _ = await read_grant(db, ctx, raw, "email", expected_user_id=actor.id)
        address = pending.context.get("email")
        if not isinstance(address, str):
            raise invalid_proof()
        recent, user = await check_recent_proof(
            db, ctx, actor, raw=proof, operation="email_change", value=address, browser=browser
        )
        pending, user = await read_grant(db, ctx, raw, "email", locked=True, expected_user_id=actor.id)
        if not local_user_ready(user) or pending.context.get("old_email") != user.email:
            raise invalid_proof()
        conflict = (
            await db.execute(select(User.id).where(email_equals(User.email, address), User.id != user.id))
        ).scalar_one_or_none()
        if conflict:
            raise ConflictError("The requested address is unavailable")
        old_address = user.email
        await consume_grant(db, pending)
        await consume_grant(db, recent)
        user.email, user.local_email_verified_at = address, utc_now()
        try:
            await db.flush()
            await invalidate_user_sessions(db=db, user=user, reason="local_email_changed")
            await revoke_grants(db, user.id)
            for recipient in (old_address, address):
                await enqueue_mail(db, ctx, user, recipient=recipient, kind="credentials_changed")
            await audit_local(db, user, "local_email_changed", actor=user)
            await commit_local(db, "email_complete")
        except IntegrityError:
            raise ConflictError("The requested address is unavailable") from None
        return CompletedResponse()
