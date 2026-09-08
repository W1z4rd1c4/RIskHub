from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import build_change_set
from app.core.config import Settings
from app.core.email import email_equals
from app.core.exceptions import AuthorizationError, NotFoundError, ValidationError
from app.core.local_session import native_identity_selected
from app.models import User
from app.models.user import AccessScope
from app.schemas.access import AccessUserUpdate
from app.services._access_workflow import (
    PLATFORM_ADMIN_FIELDS,
    authorize_access_update_fields,
    is_platform_admin,
)
from app.services._identity_authority_lock import lock_identity_transition
from app.services._org_chart import (
    acquire_org_chart_lock,
    clear_manager_references_for_inactive_user,
    validate_dept_manager_dept_change,
    validate_no_manager_cycle,
)

from .ciso_stewardship import (
    flag_orphaned_items_for_deactivation,
    flag_orphaned_threats_for_ciso_role_loss,
    role_change_removes_ciso_stewardship,
)
from .execution import log_user_update_and_commit
from .policy import (
    ensure_directory_reenable_allowed,
    ensure_platform_admin_survives,
    ensure_remaining_global_privileged_user,
    ensure_role_change_keeps_privileged_access,
    ensure_sso_local_field_update_allowed,
    is_global_privileged_user,
    prepare_manual_activity_update,
)


def normalize_access_scope_update(update_data: dict) -> None:
    if "access_scope" in update_data:
        update_data["access_scope"] = AccessScope(update_data["access_scope"])


async def update_access_profile(
    *,
    db: AsyncSession,
    settings: Settings,
    current_user: User,
    user_id: int,
    user_data: AccessUserUpdate | dict,
) -> User:
    update_data = user_data if isinstance(user_data, dict) else user_data.model_dump(exclude_unset=True)
    update_data = dict(update_data)
    user = await lock_identity_transition(db, user_id=user_id, actor=current_user)
    if is_platform_admin(user) and not is_platform_admin(current_user):
        raise NotFoundError("User not found")

    if native_identity_selected(settings) and "email" in update_data and update_data["email"] != user.email:
        raise AuthorizationError(
            "Use the verified local credential workflow", code="LOCAL_CREDENTIAL_WORKFLOW_REQUIRED"
        )

    platform_update = {field: value for field, value in update_data.items() if field in PLATFORM_ADMIN_FIELDS}
    new_role = await authorize_access_update_fields(
        db=db,
        current_user=current_user,
        target_user=user,
        update_data=update_data,
    )

    prepare_manual_activity_update(user=user, update_data=update_data, settings=settings)
    await ensure_platform_admin_survives(db, user=user, update_data=update_data, settings=settings)

    is_deactivating = user.is_active is True and update_data.get("is_active") is False
    if is_deactivating and current_user.id == user.id and is_global_privileged_user(user):
        raise ValidationError("Cannot deactivate your own privileged access")
    if is_deactivating and is_global_privileged_user(user):
        await ensure_remaining_global_privileged_user(
            db,
            user=user,
            detail="Cannot deactivate the last admin/CRO user",
            require_active=False,
        )

    ensure_sso_local_field_update_allowed(
        settings=settings,
        user=user,
        update_data=platform_update,
        fields=set(platform_update),
    )
    ensure_directory_reenable_allowed(user=user, update_data=update_data)

    if "email" in platform_update and platform_update["email"] != user.email:
        email_check = await db.execute(
            select(User.id).where(email_equals(User.email, platform_update["email"])).where(User.id != user.id).limit(1)
        )
        if email_check.scalar_one_or_none():
            raise ValidationError("Email already registered")

    if new_role is not None:
        removes_ciso_stewardship = await role_change_removes_ciso_stewardship(
            db,
            user=user,
            new_role=new_role,
        )
        await ensure_role_change_keeps_privileged_access(
            db,
            current_user=current_user,
            user=user,
            new_role=new_role,
            require_active=False,
        )
    else:
        removes_ciso_stewardship = False

    if "access_scope" in update_data:
        normalize_access_scope_update(update_data)
        if current_user.id == user.id and update_data["access_scope"] != AccessScope.GLOBAL:
            raise ValidationError("Cannot remove your own privileged access")
        if is_global_privileged_user(user) and update_data["access_scope"] != AccessScope.GLOBAL:
            await ensure_remaining_global_privileged_user(
                db,
                user=user,
                detail="Cannot remove the last admin/CRO from privileged access",
                require_active=False,
            )

    if "manager_id" in update_data and update_data["manager_id"] != user.manager_id:
        await acquire_org_chart_lock(db)
        await validate_no_manager_cycle(db, user_id=user.id, new_manager_id=update_data["manager_id"])
    if "department_id" in update_data and update_data["department_id"] != user.department_id:
        await acquire_org_chart_lock(db)
        await validate_dept_manager_dept_change(db, user=user, new_department_id=update_data["department_id"])

    extra_changes: dict[str, dict[str, object]] = {}
    if is_deactivating:
        orphan_count = await flag_orphaned_items_for_deactivation(db, user=user)
        await acquire_org_chart_lock(db)
        await clear_manager_references_for_inactive_user(db, user_id=user.id)
        extra_changes["orphaned_items_flagged"] = {"old": None, "new": orphan_count}
    elif removes_ciso_stewardship:
        orphan_count = await flag_orphaned_threats_for_ciso_role_loss(db, user=user)
        extra_changes["orphaned_items_flagged"] = {"old": None, "new": orphan_count}

    changes = build_change_set(user, update_data, extra_changes=extra_changes)
    for field, value in update_data.items():
        setattr(user, field, value)

    return await log_user_update_and_commit(
        db=db,
        user=user,
        current_user=current_user,
        changes=changes or {},
        include_permissions=True,
    )
