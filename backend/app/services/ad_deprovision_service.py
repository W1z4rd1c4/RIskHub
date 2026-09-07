from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import log_activity
from app.core.config import Settings
from app.core.datetime_utils import utc_now
from app.core.identity_policy import projected_account_active
from app.core.permissions import is_platform_admin
from app.models import User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.services._auth_session_workflow.authority import invalidate_user_sessions, revoke_user_refresh_tokens
from app.services._directory_identity import DirectoryIdentityConflictError, apply_directory_profile
from app.services._identity_authority_lock import lock_identity_transition
from app.services._org_chart import acquire_org_chart_lock, clear_manager_references_for_inactive_user
from app.services._orphaned_items import flag_orphaned_items
from app.services.directory_provider_service import (
    DirectoryProviderError,
    DirectoryProviderService,
    DirectoryProviderUnavailableError,
    DirectoryUserNotFoundError,
)
from app.services.transaction_boundary import commit_service_boundary


class ADDeprovisionService:
    """Directory deprovision checks and automatic local-account remediation."""

    DEPROVISION_REASON = "ad_deprovision"  # legacy marker kept for backwards compatibility
    DEPROVISION_REASON_MISSING = "missing"
    DEPROVISION_REASON_DIRECTORY_DISABLED = "directory_disabled"
    AUTO_DEPROVISION_REASONS = frozenset(
        {
            DEPROVISION_REASON,
            DEPROVISION_REASON_MISSING,
            DEPROVISION_REASON_DIRECTORY_DISABLED,
        }
    )

    @classmethod
    async def check_user_by_id(
        cls,
        db: AsyncSession,
        *,
        user_id: int,
        settings: Settings,
        actor: User | None = None,
        trigger: str = "manual_check_user",
    ) -> dict[str, Any]:
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is None:
            raise ValueError("User not found")

        provider = DirectoryProviderService(settings)
        result = await cls._check_user(
            db,
            user=user,
            provider=provider,
            settings=settings,
            actor=actor,
            trigger=trigger,
        )
        await commit_service_boundary(db, boundary="identity_access.directory_check")
        return result

    @classmethod
    async def check_all_users(
        cls,
        db: AsyncSession,
        *,
        settings: Settings,
        actor: User | None = None,
        trigger: str = "manual_check_all",
    ) -> dict[str, Any]:
        provider = DirectoryProviderService(settings)
        users = (
            (await db.execute(select(User).where(User.external_id.is_not(None)).order_by(User.id.asc())))
            .scalars()
            .all()
        )

        results: list[dict[str, Any]] = []
        for user in users:
            outcome = await cls._check_user(
                db,
                user=user,
                provider=provider,
                settings=settings,
                actor=actor,
                trigger=trigger,
            )
            results.append(outcome)
            # Release identity/User locks before the next external directory call.
            await commit_service_boundary(db, boundary="identity_access.directory_check")
        return {
            "checked": len(results),
            "deprovisioned": sum(1 for item in results if item["status"] == "deprovisioned"),
            "active": sum(1 for item in results if item["status"] == "active"),
            "errors": sum(1 for item in results if item["status"] == "error"),
            "skipped": sum(1 for item in results if item["status"] == "skipped"),
            "results": results,
        }

    @classmethod
    async def deprovision_user(
        cls,
        db: AsyncSession,
        *,
        user: User,
        actor: User | None,
        trigger: str,
        sync_status: str,
        deprovision_reason: str,
    ) -> dict[str, Any]:
        return await cls._deprovision_user(
            db,
            user=user,
            actor=actor,
            trigger=trigger,
            sync_status=sync_status,
            deprovision_reason=deprovision_reason,
        )

    @classmethod
    async def _check_user(
        cls,
        db: AsyncSession,
        *,
        user: User,
        provider: DirectoryProviderService,
        settings: Settings,
        actor: User | None,
        trigger: str,
    ) -> dict[str, Any]:
        now = utc_now()
        if not user.external_id:
            user.directory_sync_status = "skipped"
            return {
                "user_id": user.id,
                "email": user.email,
                "status": "skipped",
                "reason": "missing_external_id",
                "revoked_sessions": 0,
                "orphaned_items_flagged": 0,
            }

        expected_external_id = user.external_id
        try:
            remote_user = await provider.get_user(expected_external_id)
        except DirectoryUserNotFoundError:
            return await cls._deprovision_user(
                db,
                user=user,
                actor=actor,
                trigger=trigger,
                sync_status="missing",
                deprovision_reason=cls.DEPROVISION_REASON_MISSING,
            )
        except DirectoryProviderUnavailableError as exc:
            user = await lock_identity_transition(db, user_id=user.id, actor=actor)
            user.directory_last_checked_at = now
            user.directory_sync_status = "provider_unavailable"
            db.add(user)
            return {
                "user_id": user.id,
                "email": user.email,
                "status": "error",
                "reason": f"provider_unavailable:{exc}",
                "revoked_sessions": 0,
                "orphaned_items_flagged": 0,
            }
        except DirectoryProviderError as exc:
            user = await lock_identity_transition(db, user_id=user.id, actor=actor)
            user.directory_last_checked_at = now
            user.directory_sync_status = "provider_error"
            db.add(user)
            return {
                "user_id": user.id,
                "email": user.email,
                "status": "error",
                "reason": f"provider_error:{exc}",
                "revoked_sessions": 0,
                "orphaned_items_flagged": 0,
            }

        user = await lock_identity_transition(db, user_id=user.id, actor=actor)
        if user.external_id != expected_external_id or remote_user.external_id != expected_external_id:
            return {
                "user_id": user.id,
                "status": "error",
                "reason": "identity_changed",
                "revoked_sessions": 0,
                "orphaned_items_flagged": 0,
            }
        user.directory_last_checked_at = now
        user.directory_last_seen_at = now
        if not remote_user.account_enabled:
            try:
                await apply_directory_profile(
                    db,
                    user=user,
                    directory_user=remote_user,
                    sync_business_role=settings.entra_business_role_enabled,
                )
            except DirectoryIdentityConflictError:
                user.directory_sync_status = "directory_disabled"
                db.add(user)
            if not user.local_suspended and user.has_active_break_glass(now=now):
                user.deprovisioned_at = user.deprovisioned_at or now
                user.deprovision_reason = cls.DEPROVISION_REASON_DIRECTORY_DISABLED
                db.add(user)
                return {
                    "user_id": user.id,
                    "email": user.email,
                    "status": "active",
                    "reason": "break_glass_override",
                    "revoked_sessions": 0,
                    "orphaned_items_flagged": 0,
                }
            return await cls._deprovision_user(
                db,
                user=user,
                actor=actor,
                trigger=trigger,
                sync_status="directory_disabled",
                deprovision_reason=cls.DEPROVISION_REASON_DIRECTORY_DISABLED,
            )

        try:
            await apply_directory_profile(
                db,
                user=user,
                directory_user=remote_user,
                sync_business_role=settings.entra_business_role_enabled,
            )
        except DirectoryIdentityConflictError as exc:
            user.directory_sync_status = "identity_conflict"
            db.add(user)
            return {
                "user_id": user.id,
                "email": user.email,
                "status": "error",
                "reason": f"identity_conflict:{exc}",
                "revoked_sessions": 0,
                "orphaned_items_flagged": 0,
            }
        was_active = user.is_active
        if user.deprovision_reason in cls.AUTO_DEPROVISION_REASONS:
            user.deprovisioned_at = None
            user.deprovision_reason = None
            user.is_active = projected_account_active(user, settings=settings)
        elif user.local_suspended:
            user.is_active = False
        revoked_sessions = 0
        if was_active != user.is_active:
            revoked_sessions = await invalidate_user_sessions(db=db, user=user, reason="directory_eligibility_changed")
            await log_activity(
                db=db,
                actor=actor,
                action=ActivityAction.UPDATE,
                entity_type=ActivityEntityType.USER,
                entity_id=user.id,
                entity_name=user.name,
                description=f"Directory eligibility changed (revoked_sessions={revoked_sessions})",
            )
        user.break_glass_expires_at = None
        user.break_glass_reason = None
        user.break_glass_granted_by_user_id = None
        db.add(user)
        return {
            "user_id": user.id,
            "email": user.email,
            "status": "active" if user.is_active else "suspended" if user.local_suspended else "inactive",
            "reason": "local_suspension" if user.local_suspended else None,
            "revoked_sessions": revoked_sessions,
            "orphaned_items_flagged": 0,
        }

    @classmethod
    async def _deprovision_user(
        cls,
        db: AsyncSession,
        *,
        user: User,
        actor: User | None,
        trigger: str,
        sync_status: str,
        deprovision_reason: str,
    ) -> dict[str, Any]:
        user = await lock_identity_transition(db, user_id=user.id, actor=actor)
        authority_changed = bool(user.is_active or user.deprovision_reason != deprovision_reason)
        now = utc_now()
        user.directory_sync_status = sync_status
        user.deprovisioned_at = user.deprovisioned_at or now
        user.deprovision_reason = deprovision_reason

        user.is_active = False
        user.directory_last_checked_at = now
        await acquire_org_chart_lock(db)
        await clear_manager_references_for_inactive_user(db, user_id=user.id)
        db.add(user)

        if authority_changed:
            revoked_sessions = await invalidate_user_sessions(
                db=db, user=user, reason=f"{deprovision_reason}:{trigger}", now=now
            )
        else:
            revoked_sessions = await revoke_user_refresh_tokens(
                db=db, user_id=user.id, reason=f"{deprovision_reason}:{trigger}", now=now
            )

        orphaned_items = await flag_orphaned_items(db, user.id)
        orphan_count = len(orphaned_items)

        if is_platform_admin(user):
            from app.services._identity_access_lifecycle.policy import effective_platform_admin_ids

            if not await effective_platform_admin_ids(db):
                await log_activity(
                    db=db,
                    actor=actor,
                    action=ActivityAction.UPDATE,
                    entity_type=ActivityEntityType.USER,
                    entity_id=user.id,
                    entity_name=user.name,
                    description=(
                        "Platform administrator unavailable after upstream revocation; " "operator recovery required"
                    ),
                )

        await log_activity(
            db=db,
            actor=actor,
            action=ActivityAction.UPDATE,
            entity_type=ActivityEntityType.USER,
            entity_id=user.id,
            entity_name=user.name,
            description=(
                f"User auto-deactivated due to directory deprovision "
                f"(reason={deprovision_reason}, trigger={trigger}, revoked_sessions={revoked_sessions})"
            ),
        )
        return {
            "user_id": user.id,
            "email": user.email,
            "status": "deprovisioned",
            "reason": deprovision_reason,
            "revoked_sessions": revoked_sessions,
            "orphaned_items_flagged": orphan_count,
        }
