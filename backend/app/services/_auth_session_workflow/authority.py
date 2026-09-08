"""Common session-authority mutations. Callers own the transaction and audit.

Lock the User before changing authority; never commit here. Lifecycle writers
acquire their ownership/org guards before this row lock. Authentication writers
only take User -> refresh rows, so they cannot invert the lifecycle lock order.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import utc_now
from app.core.user_query_options import user_selectinload_options
from app.models import RefreshToken, User


async def lock_session_user(db: AsyncSession, *, user_id: int) -> User | None:
    return (
        await db.execute(
            select(User)
            .options(*user_selectinload_options(include_permissions=True))
            .where(User.id == user_id)
            .with_for_update(of=User)
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()


async def revoke_user_refresh_tokens(
    *,
    db: AsyncSession,
    user_id: int,
    reason: str,
    now: datetime | None = None,
) -> int:
    result = await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now or utc_now(), revoked_reason=reason)
    )
    return int(getattr(result, "rowcount", 0) or 0)


async def invalidate_user_sessions(
    *,
    db: AsyncSession,
    user: User,
    reason: str,
    now: datetime | None = None,
) -> int:
    from app.models.local_auth import LocalAuthGrant

    await db.execute(
        update(LocalAuthGrant)
        .where(
            LocalAuthGrant.user_id == user.id, LocalAuthGrant.consumed_at.is_(None), LocalAuthGrant.revoked_at.is_(None)
        )
        .values(revoked_at=now or utc_now())
    )
    user.token_version += 1
    db.add(user)
    return await revoke_user_refresh_tokens(db=db, user_id=user.id, reason=reason, now=now)
