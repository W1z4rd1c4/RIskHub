from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import build_change_set, log_activity
from app.core.config import Settings
from app.core.email import email_equals
from app.core.exceptions import AuthorizationError, ConflictError, NotFoundError, ValidationError
from app.core.security import get_password_hash, verify_password
from app.core.user_query_options import user_selectinload_options
from app.models import Role, User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.schemas import UserCreate, UserUpdate
from app.services._identity_authority_lock import lock_identity_transition
from app.services._org_chart import (
    acquire_org_chart_lock,
    clear_manager_references_for_inactive_user,
    validate_dept_manager_dept_change,
    validate_no_manager_cycle,
)
from app.services.transaction_boundary import commit_service_boundary

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


async def create_user_profile(
    *,
    db: AsyncSession,
    settings: Settings,
    current_user: User,
    user_data: UserCreate,
) -> User:
    if settings.auth_mode == "microsoft_sso":
        raise AuthorizationError(
            "Manual user creation is disabled in microsoft_sso mode. Use /api/v1/directory/users/{oid}/import."
        )

    result = await db.execute(select(User).where(email_equals(User.email, user_data.email)))
    if result.scalar_one_or_none():
        raise ValidationError("Email already registered")

    new_user = User(
        email=user_data.email,
        name=user_data.name,
        role_id=user_data.role_id,
        department_id=user_data.department_id,
        manager_id=user_data.manager_id,
        is_active=user_data.is_active,
        local_suspended=not user_data.is_active,
        hashed_password=get_password_hash(user_data.password),
    )

    if new_user.manager_id is not None:
        await acquire_org_chart_lock(db)

    db.add(new_user)
    await db.flush()
    if new_user.manager_id is not None:
        await validate_no_manager_cycle(db, user_id=new_user.id, new_manager_id=new_user.manager_id)

    await log_activity(
        db,
        entity_type=ActivityEntityType.USER,
        entity_id=new_user.id,
        entity_name=new_user.name,
        action=ActivityAction.CREATE,
        actor=current_user,
        department_id=new_user.department_id,
    )
    await commit_service_boundary(db, boundary="identity_access.create_user_profile")
    await db.refresh(new_user)

    result = await db.execute(select(User).options(*user_selectinload_options()).where(User.id == new_user.id))
    return result.scalar_one()


async def update_user_profile(
    *,
    db: AsyncSession,
    settings: Settings,
    current_user: User,
    user_id: int,
    user_data: UserUpdate,
) -> User:
    password_field_provided = "password" in user_data.model_fields_set
    if settings.auth_mode == "microsoft_sso" and password_field_provided:
        raise AuthorizationError("Password updates are disabled in microsoft_sso mode.")

    # Compare/hash before locks. A concurrent reset must not be overwritten by
    # the result of verification against an older credential.
    password_hash = None
    verified_credential = None
    if user_data.password is not None:
        snapshot = (
            await db.execute(select(User.hashed_password, User.token_version).where(User.id == user_id))
        ).one_or_none()
        if snapshot is None:
            raise NotFoundError("User not found")
        verified_credential = (snapshot.hashed_password, snapshot.token_version)
        unchanged = bool(snapshot.hashed_password) and verify_password(user_data.password, snapshot.hashed_password)
        if not unchanged:
            password_hash = get_password_hash(user_data.password)
    user = await lock_identity_transition(db, user_id=user_id, actor=current_user)
    if verified_credential is not None and verified_credential != (user.hashed_password, user.token_version):
        raise ConflictError("Account authority changed during password verification; retry with current state")

    if user_data.email and user_data.email != user.email:
        email_check = await db.execute(select(User).where(email_equals(User.email, user_data.email)))
        if email_check.scalar_one_or_none():
            raise ValidationError("Email already registered")

    update_data = user_data.model_dump(exclude_unset=True)
    update_data.pop("password", None)

    ensure_sso_local_field_update_allowed(
        settings=settings,
        user=user,
        update_data=update_data,
        fields={"email", "name", "department_id"},
    )
    ensure_directory_reenable_allowed(user=user, update_data=update_data)

    removes_ciso_stewardship = False
    if "role_id" in update_data:
        new_role_id = update_data["role_id"]
        if new_role_id != user.role_id:
            new_role = (
                await db.execute(
                    select(Role).where(
                        Role.id == new_role_id,
                        Role.is_active.is_(True),
                    )
                )
            ).scalar_one_or_none()
            if not new_role:
                raise ValidationError("Invalid role_id")
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
            )

    prepare_manual_activity_update(user=user, update_data=update_data, settings=settings)
    await ensure_platform_admin_survives(db, user=user, update_data=update_data, settings=settings)

    extra_changes: dict[str, dict[str, object]] = {}
    if password_hash is not None:
        user.hashed_password = password_hash
        extra_changes["password_changed"] = {"old": None, "new": True}

    is_deactivating = user.is_active is True and update_data.get("is_active") is False
    if is_deactivating and current_user.id == user.id and is_global_privileged_user(user):
        raise ValidationError("Cannot deactivate your own privileged access")
    if is_deactivating and is_global_privileged_user(user):
        await ensure_remaining_global_privileged_user(
            db,
            user=user,
            detail="Cannot deactivate the last admin/CRO user",
        )
    if is_deactivating:
        orphan_count = await flag_orphaned_items_for_deactivation(db, user=user)
        await acquire_org_chart_lock(db)
        await clear_manager_references_for_inactive_user(db, user_id=user.id)
        extra_changes["orphaned_items_flagged"] = {"old": None, "new": orphan_count}
    elif removes_ciso_stewardship:
        orphan_count = await flag_orphaned_threats_for_ciso_role_loss(db, user=user)
        extra_changes["orphaned_items_flagged"] = {"old": None, "new": orphan_count}

    if "manager_id" in update_data and update_data["manager_id"] != user.manager_id:
        await acquire_org_chart_lock(db)
        await validate_no_manager_cycle(db, user_id=user.id, new_manager_id=update_data["manager_id"])
    if "department_id" in update_data and update_data["department_id"] != user.department_id:
        await acquire_org_chart_lock(db)
        await validate_dept_manager_dept_change(db, user=user, new_department_id=update_data["department_id"])

    changes = build_change_set(user, update_data, extra_changes=extra_changes)
    for field, value in update_data.items():
        setattr(user, field, value)

    return await log_user_update_and_commit(
        db=db,
        user=user,
        current_user=current_user,
        changes=changes or {},
        description="Password updated" if password_hash is not None and not update_data else None,
    )
