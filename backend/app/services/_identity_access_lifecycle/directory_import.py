from __future__ import annotations

from typing import Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.email import email_equals
from app.core.exceptions import ConflictError, ServiceFailure, ValidationError
from app.core.identity_policy import projected_account_active
from app.models import Role, User
from app.schemas.directory import DirectoryImportRequest, DirectoryUserRead
from app.services._auth_session_workflow.authority import invalidate_user_sessions
from app.services._directory_identity import (
    DirectoryIdentityConflictError,
    apply_directory_profile,
    resolve_directory_email,
)
from app.services._directory_identity import (
    resolve_safe_default_role as resolve_directory_safe_default_role,
)
from app.services._identity_authority_lock import lock_identity_transition
from app.services.ad_deprovision_service import ADDeprovisionService

from .ciso_stewardship import (
    flag_orphaned_threats_for_ciso_role_loss,
    role_change_removes_ciso_stewardship,
)
from .contracts import IdentityImportOutcome
from .execution import commit_directory_import, load_directory_import_user
from .policy import ensure_platform_admin_survives, ensure_role_change_keeps_privileged_access
from .projection import build_directory_import_response


def _is_external_id_integrity_error(exc: IntegrityError) -> bool:
    message = str(exc).lower()
    return "external_id" in message or "ix_users_external_id" in message


async def resolve_safe_default_role(db: AsyncSession) -> Role:
    return await resolve_directory_safe_default_role(db, exception_factory=ServiceFailure)


async def resolve_role_for_directory_import(
    db: AsyncSession,
    *,
    override_role_id: int | None,
) -> Role:
    if override_role_id is not None:
        result = await db.execute(select(Role).where(Role.id == override_role_id).where(Role.is_active.is_(True)))
        role = result.scalar_one_or_none()
        if role is None:
            raise ValidationError("Invalid role_id override")
        return role
    return await resolve_safe_default_role(db)


async def import_directory_identity(
    *,
    db: AsyncSession,
    settings: Settings,
    current_user: User,
    directory_user: DirectoryUserRead,
    payload: DirectoryImportRequest,
    provider_name: str,
) -> IdentityImportOutcome:
    normalized_email = resolve_directory_email(directory_user)
    if normalized_email is None:
        raise ValidationError("Directory user is missing an importable email address")

    user = (await db.execute(select(User).where(User.external_id == directory_user.external_id))).scalar_one_or_none()
    import_status: Literal["created", "updated"] = "updated"
    seed_directory_department = False
    if user is None:
        existing_email_user = (
            await db.execute(select(User).where(email_equals(User.email, normalized_email)))
        ).scalar_one_or_none()
        if existing_email_user is not None and existing_email_user.external_id not in (
            None,
            directory_user.external_id,
        ):
            raise ConflictError("Directory identity conflict: email already linked to a different external_id")
        if existing_email_user is not None:
            user = existing_email_user
        else:
            role = await resolve_role_for_directory_import(db, override_role_id=payload.role_id)
            user = User(
                email=normalized_email,
                name=directory_user.display_name or normalized_email,
                external_id=directory_user.external_id,
                hashed_password=None,
                role_id=role.id,
                is_active=True,
            )
            db.add(user)
            import_status = "created"
            seed_directory_department = True

    if import_status == "updated":
        user = await lock_identity_transition(db, user_id=user.id, actor=current_user)
        if user.external_id not in (None, directory_user.external_id):
            raise ConflictError("Directory identity binding changed; retry the import")
    previous_version = user.token_version or 0
    previous_authority = (user.role_id, user.is_active, user.external_id)

    if payload.role_id is not None and import_status == "updated":
        role = await resolve_role_for_directory_import(db, override_role_id=payload.role_id)
        await ensure_platform_admin_survives(db, user=user, update_data={"role_id": role.id}, settings=settings)
        await ensure_role_change_keeps_privileged_access(db, current_user=current_user, user=user, new_role=role)
        if directory_user.account_enabled and await role_change_removes_ciso_stewardship(
            db,
            user=user,
            new_role=role,
        ):
            await flag_orphaned_threats_for_ciso_role_loss(db, user=user)
        user.role_id = role.id

    try:
        try:
            await apply_directory_profile(
                db,
                user=user,
                directory_user=directory_user,
                sync_business_role=settings.entra_business_role_enabled,
                seed_department=seed_directory_department,
            )
        except DirectoryIdentityConflictError as exc:
            raise ConflictError(str(exc)) from exc

        if directory_user.account_enabled and user.deprovision_reason in ADDeprovisionService.AUTO_DEPROVISION_REASONS:
            user.deprovisioned_at = None
            user.deprovision_reason = None
            user.is_active = projected_account_active(user, settings=settings)
            user.break_glass_expires_at = None
            user.break_glass_reason = None
            user.break_glass_granted_by_user_id = None

        if not directory_user.account_enabled:
            await ADDeprovisionService.deprovision_user(
                db,
                user=user,
                actor=current_user,
                trigger="directory_import",
                sync_status="directory_disabled",
                deprovision_reason=ADDeprovisionService.DEPROVISION_REASON_DIRECTORY_DISABLED,
            )

        if (
            import_status == "updated"
            and user.token_version == previous_version
            and previous_authority != (user.role_id, user.is_active, user.external_id)
        ):
            await invalidate_user_sessions(db=db, user=user, reason="directory_import_identity_changed")
        db.add(user)
        await db.flush()
        await commit_directory_import(
            db=db,
            user=user,
            current_user=current_user,
            import_status=import_status,
            provider_name=provider_name,
            account_enabled=directory_user.account_enabled,
        )
    except IntegrityError as exc:
        await db.rollback()
        if _is_external_id_integrity_error(exc):
            raise ConflictError("Directory identity conflict: external_id already imported") from exc
        raise

    refreshed = await load_directory_import_user(db, user_id=user.id)
    response = build_directory_import_response(
        refreshed=refreshed,
        directory_user=directory_user,
        import_status=import_status,
    )
    return IdentityImportOutcome(status=import_status, user=refreshed, response=response)
