from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.datetime_utils import utc_now
from app.core.exceptions import AuthorizationError, ConflictError, ValidationError
from app.core.identity_policy import DIRECTORY_OWNED_FIELDS, can_authenticate_user, upstream_and_enrollment_allow_access
from app.core.permissions import is_platform_admin
from app.models import Role, User
from app.models.user import AccessScope
from app.services._access_workflow import ADMIN_PRIVILEGED_ROLES
from app.services._directory_identity import requires_break_glass_for_reenable


def is_global_privileged_user(user: User) -> bool:
    return bool(user.role and user.role.name in ADMIN_PRIVILEGED_ROLES and user.access_scope == AccessScope.GLOBAL)


async def ensure_remaining_global_privileged_user(
    db: AsyncSession,
    *,
    user: User,
    detail: str,
    require_active: bool = True,
) -> None:
    query = (
        select(User.id)
        .join(Role)
        .where(Role.name.in_(ADMIN_PRIVILEGED_ROLES))
        .where(User.id != user.id)
        .where(User.access_scope == AccessScope.GLOBAL)
        .limit(1)
    )
    if require_active:
        query = query.where(User.is_active.is_(True))

    remaining = await db.execute(query)
    if not remaining.scalar_one_or_none():
        raise ValidationError(detail)


def ensure_sso_local_field_update_allowed(
    *,
    settings: Settings,
    user: User,
    update_data: dict,
    fields: set[str],
) -> None:
    if settings.auth_mode != "microsoft_sso" or not user.external_id:
        return
    for field in fields & DIRECTORY_OWNED_FIELDS:
        if field in update_data and update_data[field] != getattr(user, field):
            raise AuthorizationError(f"{field} is managed by directory sync for SSO-linked users.")


def ensure_directory_reenable_allowed(*, user: User, update_data: dict) -> None:
    if update_data.get("is_active") is True and requires_break_glass_for_reenable(user):
        raise AuthorizationError("Directory-deprovisioned users require break-glass enable before reactivation.")


async def ensure_role_change_keeps_privileged_access(
    db: AsyncSession,
    *,
    current_user: User,
    user: User,
    new_role: Role,
    require_active: bool = True,
) -> None:
    old_role_is_privileged = bool(user.role and user.role.name in ADMIN_PRIVILEGED_ROLES)
    new_role_is_privileged = new_role.name in ADMIN_PRIVILEGED_ROLES
    if current_user.id == user.id and old_role_is_privileged and not new_role_is_privileged:
        raise ValidationError("Cannot demote yourself from admin/CRO role")
    if old_role_is_privileged and not new_role_is_privileged and user.access_scope == AccessScope.GLOBAL:
        await ensure_remaining_global_privileged_user(
            db,
            user=user,
            detail="Cannot demote the last admin/CRO user",
            require_active=require_active,
        )


def prepare_manual_activity_update(*, user: User, update_data: dict, settings: Settings) -> None:
    if "is_active" not in update_data:
        return
    active = update_data["is_active"]
    if type(active) is not bool:
        raise ValidationError("is_active must be a boolean")
    if active and not upstream_and_enrollment_allow_access(user, settings=settings):
        raise AuthorizationError("Account cannot resume until upstream eligibility and enrollment are satisfied")
    update_data["local_suspended"] = not active
    if bool(user.local_suspended) != (not active):
        update_data["local_suspended_at"] = None if active else utc_now()


async def effective_platform_admin_ids(db: AsyncSession, *, settings: Settings | None = None) -> set[int]:
    from app.core.user_query_options import user_selectinload_options

    users = (
        (
            await db.execute(
                select(User)
                .join(Role)
                .options(*user_selectinload_options(include_permissions=True))
                .where(
                    Role.name == "admin",
                    Role.is_active.is_(True),
                    User.is_active.is_(True),
                    User.local_suspended.is_(False),
                    User.access_scope == AccessScope.GLOBAL,
                )
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    return {user.id for user in users if can_authenticate_user(user, settings=settings)}


async def ensure_platform_admin_survives(
    db: AsyncSession,
    *,
    user: User,
    update_data: dict,
    settings: Settings,
) -> None:
    """Caller holds the administration guard before counting and mutating."""
    if not is_platform_admin(user) or user.access_scope != AccessScope.GLOBAL or not user.is_active:
        return
    removes = update_data.get("is_active") is False
    if "access_scope" in update_data:
        removes = removes or update_data["access_scope"] != AccessScope.GLOBAL
    if "role_id" in update_data and update_data["role_id"] != user.role_id:
        role = (await db.execute(select(Role).where(Role.id == update_data["role_id"]))).scalar_one_or_none()
        removes = removes or role is None or role.name != "admin" or not role.is_active
    if removes and not ((await effective_platform_admin_ids(db, settings=settings)) - {user.id}):
        raise ConflictError("Cannot remove the last effective platform administrator", code="LAST_PLATFORM_ADMIN")
