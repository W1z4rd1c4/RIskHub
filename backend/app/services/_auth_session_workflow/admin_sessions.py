from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.activity_logger import log_activity
from app.core.datetime_utils import utc_now
from app.models import RefreshToken, User
from app.models.activity_log import ActivityAction, ActivityEntityType

from .authority import invalidate_user_sessions


class SessionWorkflowError(Exception):
    def __init__(self, *, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class ActiveSessionProjection:
    user_id: int
    user_name: str
    user_email: str
    role: str
    department: str | None
    last_activity: datetime | None
    last_login: datetime | None
    active_sessions: int


@dataclass(frozen=True)
class SessionRevocationResult:
    user: User
    revoked_count: int


async def list_active_session_projections(
    db: AsyncSession,
    *,
    now: datetime | None = None,
) -> list[ActiveSessionProjection]:
    current_time = now or utc_now()
    session_subquery = (
        select(
            RefreshToken.user_id.label("user_id"),
            func.count(RefreshToken.id).label("active_sessions"),
            func.max(func.coalesce(RefreshToken.last_used_at, RefreshToken.issued_at)).label("last_activity"),
            func.max(RefreshToken.issued_at).label("last_login"),
        )
        .where(RefreshToken.revoked_at.is_(None))
        .where(RefreshToken.expires_at > current_time)
        .group_by(RefreshToken.user_id)
        .subquery()
    )

    rows = (
        await db.execute(
            select(
                User,
                session_subquery.c.active_sessions,
                session_subquery.c.last_activity,
                session_subquery.c.last_login,
            )
            .join(session_subquery, User.id == session_subquery.c.user_id)
            .where(User.is_active.is_(True))
            .options(selectinload(User.role), selectinload(User.department))
            .order_by(session_subquery.c.last_activity.desc())
        )
    ).all()

    return [
        ActiveSessionProjection(
            user_id=user.id,
            user_name=user.name,
            user_email=user.email,
            role=user.role.display_name if user.role else "Unknown",
            department=user.department.name if user.department else None,
            last_activity=last_activity,
            last_login=last_login,
            active_sessions=int(active_sessions or 0),
        )
        for user, active_sessions, last_activity, last_login in rows
    ]


async def revoke_user_sessions(
    db: AsyncSession,
    *,
    target_user_id: int,
    admin_user: User,
    now: datetime | None = None,
) -> SessionRevocationResult:
    if target_user_id == admin_user.id:
        raise SessionWorkflowError(status_code=400, detail="Cannot revoke your own session")

    user = (
        await db.execute(
            select(User).where(User.id == target_user_id).with_for_update().execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()

    if user is None:
        raise SessionWorkflowError(status_code=404, detail="User not found")

    current_time = now or utc_now()
    revoked_count = await invalidate_user_sessions(
        db=db,
        user=user,
        reason=f"admin_revoke:{admin_user.id}",
        now=current_time,
    )

    await log_activity(
        db=db,
        actor=admin_user,
        action=ActivityAction.UPDATE,
        entity_type=ActivityEntityType.USER,
        entity_id=target_user_id,
        entity_name=user.name,
        description=f"Sessions revoked for user {user.email} by admin (count={revoked_count})",
    )

    return SessionRevocationResult(user=user, revoked_count=revoked_count)
