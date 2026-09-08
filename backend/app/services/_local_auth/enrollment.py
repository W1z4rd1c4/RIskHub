"""Invite-only local provisioning and restricted password enrollment."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import utc_now
from app.core.email import email_equals, normalize_email
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.core.password_policy import run_password_work, validate_local_password
from app.core.permissions import is_platform_admin
from app.core.production_contract import LOCAL_CHALLENGE_TTL_SECONDS, LOCAL_INVITATION_TTL_SECONDS
from app.core.security import get_password_hash
from app.models import Department, Role, User
from app.schemas.local_auth import InvitationRequest, InvitationResponse, LocalAuthChallenge
from app.services._auth_session_workflow.authority import invalidate_user_sessions
from app.services._directory_identity import resolve_safe_default_role
from app.services._identity_authority_lock import lock_identity_transition

from .artifacts import consume_grant, issue_grant, read_grant, revoke_grants
from .common import NativeContext, atomic_local_work, audit_local, commit_local, invalid_proof, local_user_ready
from .delivery import enqueue_mail


async def local_admin(db: AsyncSession, actor: User) -> User:
    current = await lock_identity_transition(db, user_id=actor.id, actor=actor)
    if not is_platform_admin(current) or not local_user_ready(current):
        raise AuthorizationError("Platform administrator with completed enrollment required")
    return current


async def invite_user(db: AsyncSession, ctx: NativeContext, actor: User, data: InvitationRequest) -> InvitationResponse:
    email = normalize_email(str(data.email))
    if email is None:
        raise ValidationError("Invalid email", status_code=422)
    await ctx.limiter.require("invite-target", email, 3, 3600)
    await ctx.limiter.require("invite-actor", str(actor.id), 30, 3600)
    async with atomic_local_work(db):
        actor = await local_admin(db, actor)
        if (await db.execute(select(User.id).where(email_equals(User.email, email)))).scalar_one_or_none():
            raise ConflictError("An account already uses this email")
        role = await db.get(Role, data.role_id) if data.role_id else await resolve_safe_default_role(db)
        if role is None or not role.is_active:
            raise ValidationError("Invalid role", status_code=422)
        if data.department_id is not None and await db.get(Department, data.department_id) is None:
            raise ValidationError("Invalid department", status_code=422)
        if data.manager_id is not None:
            manager = await db.get(User, data.manager_id, populate_existing=True)
            if manager is None or not manager.is_active or manager.local_suspended:
                raise ValidationError("Manager must be active", status_code=422)
        user = User(
            email=email,
            name=data.name,
            role_id=role.id,
            department_id=data.department_id,
            manager_id=data.manager_id,
            is_active=False,
            local_enrollment_state="invited",
            local_suspended=False,
            hashed_password=None,
        )
        db.add(user)
        try:
            await db.flush()
            grant, credential = await issue_grant(db, ctx, user, "invite", LOCAL_INVITATION_TTL_SECONDS)
            await enqueue_mail(
                db, ctx, user, recipient=user.email, kind="invitation", grant=grant, credential=credential
            )
            await audit_local(db, user, "local_invitation_created", actor=actor)
            await commit_local(db, "invitation")
        except IntegrityError:
            raise ConflictError("The requested account conflicts with an existing account") from None
        return InvitationResponse(user_id=user.id, delivery_status="pending")


async def manage_invitation(
    db: AsyncSession, ctx: NativeContext, actor: User, user_id: int, *, resend: bool, reason: str
) -> InvitationResponse | None:
    await ctx.limiter.require("invite-actor", str(actor.id), 30, 3600)
    preliminary = await db.get(User, user_id)
    if preliminary is None:
        raise NotFoundError("User not found")
    if resend:
        await ctx.limiter.require("invite-target", preliminary.email, 3, 3600)
    async with atomic_local_work(db):
        # The administration guard serializes this with other lifecycle writers.
        target = await lock_identity_transition(db, user_id=user_id, actor=actor)
        if not is_platform_admin(actor) or not local_user_ready(actor):
            raise AuthorizationError("Platform administrator required")
        if target.external_id or target.local_enrollment_state != "invited" or target.local_suspended:
            raise ConflictError("Only an unsuspended pending invitation can be changed")
        await revoke_grants(db, target.id, purpose="invite")
        if resend:
            grant, raw = await issue_grant(db, ctx, target, "invite", LOCAL_INVITATION_TTL_SECONDS)
            await enqueue_mail(db, ctx, target, recipient=target.email, kind="invitation", grant=grant, credential=raw)
        await audit_local(
            db,
            target,
            "local_invitation_reissued" if resend else "local_invitation_cancelled",
            actor=actor,
            reason=reason,
        )
        await commit_local(db, "invitation_update")
        return InvitationResponse(user_id=target.id, delivery_status="pending") if resend else None


async def start_enrollment(
    db: AsyncSession, ctx: NativeContext, *, raw: str, password: str, browser: str
) -> LocalAuthChallenge:
    await ctx.limiter.require("redeem-source", ctx.source, 10, 900)
    async with atomic_local_work(db):
        _, user = await read_grant(db, ctx, raw, "invite")
        if user.local_enrollment_state != "invited":
            raise invalid_proof()
        validate_local_password(password, additions_file=ctx.settings.local_password_blocklist_file)
        encoded = await run_password_work(lambda: get_password_hash(password))
        grant, user = await read_grant(db, ctx, raw, "invite", locked=True)
        if user.local_enrollment_state != "invited":
            raise invalid_proof()
        await consume_grant(db, grant)
        user.hashed_password = encoded
        user.local_email_verified_at = utc_now()
        user.local_enrollment_state = "password_set"
        user.is_active = False
        await invalidate_user_sessions(db=db, user=user, reason="local_password_enrollment")
        await revoke_grants(db, user.id)
        _, challenge = await issue_grant(db, ctx, user, "enrollment", LOCAL_CHALLENGE_TTL_SECONDS, browser=browser)
        await audit_local(db, user, "local_password_enrolled")
        await commit_local(db, "enrollment_start")
        return LocalAuthChallenge(status="enrollment_required", challenge=challenge)
