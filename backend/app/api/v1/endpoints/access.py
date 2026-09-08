"""Access management endpoints with privileged gating."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api import deps
from app.core.config import Settings, get_settings
from app.core.permissions import get_effective_permissions, get_scope_label, has_permission, is_privileged_user
from app.core.user_query_options import user_selectinload_options
from app.db.session import get_db
from app.models import Role, RolePermission, User
from app.models.role import RoleType
from app.models.user import AccessScope
from app.schemas.access import AccessUserRead, AccessUserUpdate, PermissionRead, RoleWithPermissions
from app.schemas.user import AccessScopeEnum, RoleRead
from app.services._access_workflow import (
    access_user_capabilities,
    build_department_access_roster_query,
    is_cro,
    is_platform_admin,
    resolve_department_access_roster_target,
)
from app.services._identity_access_lifecycle import update_access_profile
from app.services._identity_access_lifecycle.policy import effective_platform_admin_ids

router = APIRouter()


def _require_privileged(user: User) -> None:
    """
    Require global scope plus explicit User-directory read authority.

    Global business-data scope alone must not expose User administration.
    """
    if not is_privileged_user(user) or not has_permission(user, "users", "read"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


def _can_manage_privileged_status(user: User) -> bool:
    """
    Check if user can submit access-management mutations.

    Field-level checks split platform Admin and CRO authority after this
    coarse write gate. Not all privileged users can use this write surface.
    """
    return is_platform_admin(user) or is_cro(user)


def _require_access_user_write(user: User) -> None:
    """
    Require explicit admin/CRO authority for access-management mutations.

    Read/list endpoints may be available to global privileged users, but any
    write to access-user fields is restricted to admin/CRO roles.
    """
    if not _can_manage_privileged_status(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admin or CRO can update user access settings",
        )


def _build_access_user_read(
    user: User,
    *,
    current_user: User,
    settings: Settings | None = None,
    effective_admin_ids: set[int] | None = None,
) -> AccessUserRead:
    return AccessUserRead(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
        local_suspended=user.local_suspended,
        local_enrollment_state=user.local_enrollment_state,
        role_id=user.role_id,
        role=RoleRead.model_validate(user.role),
        department_id=user.department_id,
        department_name=user.department.name if user.department else None,
        manager_id=user.manager_id,
        manager_name=user.manager.name if user.manager else None,
        access_scope=AccessScopeEnum(user.access_scope.value),
        scope_label=get_scope_label(user),
        effective_permissions=get_effective_permissions(user),
        external_id=user.external_id,
        job_title=user.job_title,
        entra_business_role=user.entra_business_role,
        directory_last_checked_at=user.directory_last_checked_at,
        directory_last_seen_at=user.directory_last_seen_at,
        directory_sync_status=user.directory_sync_status,
        deprovisioned_at=user.deprovisioned_at,
        deprovision_reason=user.deprovision_reason,
        capabilities=access_user_capabilities(
            current_user, user, settings=settings, effective_admin_ids=effective_admin_ids
        ),
    )


def _build_role_with_permissions(role: Role) -> RoleWithPermissions:
    permissions = [PermissionRead.model_validate(rp.permission) for rp in role.permissions]
    return RoleWithPermissions(
        id=role.id,
        name=role.name,
        display_name=role.display_name,
        description=role.description,
        permissions=permissions,
    )


@router.get("/users", response_model=list[AccessUserRead])
async def list_access_users(
    department_id: int | None = None,
    role_id: int | None = None,
    access_scope: AccessScope | None = None,
    is_privileged: bool | None = None,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """List users for access management with scope filters."""
    _require_privileged(current_user)

    query = select(User).options(*user_selectinload_options(include_permissions=True))
    if not is_platform_admin(current_user):
        query = query.join(Role).where(Role.name != RoleType.ADMIN)

    if department_id is not None:
        query = query.where(User.department_id == department_id)
    if role_id is not None:
        query = query.where(User.role_id == role_id)
    if access_scope is not None:
        query = query.where(User.access_scope == access_scope)
    if is_privileged is not None:
        if is_privileged:
            query = query.where(User.access_scope == AccessScope.GLOBAL)
        else:
            query = query.where(User.access_scope != AccessScope.GLOBAL)

    result = await db.execute(query)
    users = result.scalars().all()
    admin_ids = await effective_platform_admin_ids(db, settings=settings) if is_platform_admin(current_user) else None
    return [
        _build_access_user_read(user, current_user=current_user, settings=settings, effective_admin_ids=admin_ids)
        for user in users
    ]


@router.get("/users/my-department", response_model=list[AccessUserRead])
async def list_department_access_users(
    department_id: int | None = None,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """
    List users in current user's department with their access info.
    Available to department heads and privileged users.
    Department heads are always limited to their own department. Privileged
    callers with users:read may request another department for its roster.
    """
    target_department_id = resolve_department_access_roster_target(
        current_user,
        department_id,
    )
    query = build_department_access_roster_query(
        current_user,
        department_id=target_department_id,
    ).options(*user_selectinload_options(include_permissions=True))

    result = await db.execute(query)
    users = result.scalars().all()
    admin_ids = await effective_platform_admin_ids(db, settings=settings) if is_platform_admin(current_user) else None
    return [
        _build_access_user_read(user, current_user=current_user, settings=settings, effective_admin_ids=admin_ids)
        for user in users
    ]


@router.get("/roles", response_model=list[RoleWithPermissions])
async def list_access_roles(
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List roles with permissions for access management UI."""
    _require_privileged(current_user)

    query = (
        select(Role)
        .options(selectinload(Role.permissions).selectinload(RolePermission.permission))
        .where(Role.is_active.is_(True))
    )
    if not is_platform_admin(current_user):
        query = query.where(Role.name != RoleType.ADMIN)

    result = await db.execute(query)
    roles = result.scalars().all()
    return [_build_role_with_permissions(role) for role in roles]


@router.patch("/users/{user_id}", response_model=AccessUserRead)
async def update_access_user(
    user_id: int,
    user_data: AccessUserUpdate,
    current_user: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    """
    Update access management fields for a user.

    Note: write access is stricter than read/list access. Admin owns platform
    identity fields and Admin-role assignment. CRO owns business access fields,
    non-admin role assignment, and local department assignment.
    """
    _require_privileged(current_user)
    _require_access_user_write(current_user)

    update_data = user_data.model_dump(exclude_unset=True)
    updated_user = await update_access_profile(
        db=db,
        settings=settings,
        current_user=current_user,
        user_id=user_id,
        user_data=update_data,
    )
    admin_ids = await effective_platform_admin_ids(db, settings=settings) if is_platform_admin(current_user) else None
    return _build_access_user_read(
        updated_user, current_user=current_user, settings=settings, effective_admin_ids=admin_ids
    )
