from __future__ import annotations

from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.activity_logger import log_activity
from app.core.identity_policy import AUTHORITY_FIELDS
from app.core.user_query_options import user_selectinload_options
from app.models import User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.services._auth_session_workflow.authority import invalidate_user_sessions
from app.services.transaction_boundary import commit_service_boundary


async def log_user_update_and_commit(
    *,
    db: AsyncSession,
    user: User,
    current_user: User,
    changes: dict,
    description: str | None = None,
    include_permissions: bool = False,
    log_when_empty: bool = False,
) -> User:
    if AUTHORITY_FIELDS.intersection(changes):
        reason = "identity_access_changed"
        revoked = await invalidate_user_sessions(db=db, user=user, reason=reason)
        changes["session_authority"] = {
            "old": None,
            "new": {
                "reason": reason,
                "revoked_sessions": revoked,
                "token_version": user.token_version,
            },
        }
    if changes or log_when_empty:
        await log_activity(
            db,
            entity_type=ActivityEntityType.USER,
            entity_id=user.id,
            entity_name=user.name,
            action=ActivityAction.UPDATE,
            actor=current_user,
            department_id=user.department_id,
            changes=changes,
            description=description,
        )

    await commit_service_boundary(db, boundary="identity_access.log_user_update")
    await db.refresh(user)

    result = await db.execute(
        select(User)
        .options(*user_selectinload_options(include_permissions=include_permissions))
        .where(User.id == user.id)
    )
    return result.scalar_one()


async def commit_directory_import(
    *,
    db: AsyncSession,
    user: User,
    current_user: User,
    import_status: Literal["created", "updated"],
    provider_name: str,
    account_enabled: bool,
) -> None:
    if account_enabled:
        await log_activity(
            db=db,
            actor=current_user,
            action=ActivityAction.CREATE if import_status == "created" else ActivityAction.UPDATE,
            entity_type=ActivityEntityType.USER,
            entity_id=user.id,
            entity_name=user.name,
            description=f"Directory import ({provider_name}) for {user.email}",
        )

    await commit_service_boundary(db, boundary="identity_access.directory_import")


async def load_directory_import_user(db: AsyncSession, *, user_id: int) -> User:
    result = await db.execute(
        select(User).options(selectinload(User.role), selectinload(User.department)).where(User.id == user_id)
    )
    return result.scalar_one()
