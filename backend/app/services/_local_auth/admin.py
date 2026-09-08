"""Nonsecret administrative projection and reset-link request, never direct reset."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import coerce_utc, utc_now
from app.core.exceptions import AuthorizationError, NotFoundError
from app.core.permissions import is_platform_admin
from app.models import LocalAuthDelivery, LocalAuthGrant, OutboxEvent, User

from .common import NativeContext, local_user_ready
from .credentials import request_password_reset


def authorize(actor: User) -> None:
    if not is_platform_admin(actor) or not local_user_ready(actor):
        raise AuthorizationError("Platform administrator with completed enrollment required")


async def admin_reset(db: AsyncSession, ctx: NativeContext, actor: User, *, user_id: int, reason: str) -> None:
    authorize(actor)
    target = await db.get(User, user_id)
    if target is None or target.external_id is not None:
        raise NotFoundError("User not found")
    await ctx.limiter.require("reset-actor", str(actor.id), 30, 3600)
    # Send a link only; possession of the admin session never changes credentials.
    await request_password_reset(db, ctx, email=target.email, actor=actor, reason=reason)


async def identity_status(db: AsyncSession, ctx: NativeContext, actor: User, *, user_id: int) -> dict:
    authorize(actor)
    user = await db.get(User, user_id)
    if user is None or user.external_id is not None:
        raise NotFoundError("User not found")
    delivery = (
        await db.execute(
            select(LocalAuthDelivery)
            .where(LocalAuthDelivery.user_id == user_id)
            .order_by(LocalAuthDelivery.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    status = None
    if delivery is not None:
        status = delivery.status
        grant = await db.get(LocalAuthGrant, delivery.grant_id) if delivery.grant_id else None
        if grant and (grant.revoked_at or grant.token_version != user.token_version):
            status = "cancelled"
        elif (
            grant
            and not grant.consumed_at
            and (grant_expires := coerce_utc(grant.expires_at)) is not None
            and grant_expires <= utc_now()
        ):
            status = "expired"
        elif (expires := coerce_utc(delivery.expires_at)) is not None and expires <= utc_now() and not delivery.sent_at:
            status = "expired"
        elif status == "pending":
            event = (
                await db.execute(
                    select(OutboxEvent).where(OutboxEvent.idempotency_key == f"local-auth-mail:{delivery.id}")
                )
            ).scalar_one_or_none()
            if event and event.last_error:
                status = "failed"
    return {
        "user_id": user.id,
        "enrollment_state": user.local_enrollment_state,
        "local_suspended": user.local_suspended,
        "is_active": user.is_active,
        "delivery_status": status,
    }
