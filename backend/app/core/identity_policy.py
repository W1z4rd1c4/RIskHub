"""One account-eligibility policy shared by authentication and lifecycle writers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from app.core.datetime_utils import utc_now

if TYPE_CHECKING:
    from app.core.config import Settings
    from app.models.user import User

AUTO_DEPROVISION_REASONS = frozenset({"ad_deprovision", "missing", "directory_disabled"})
DIRECTORY_OWNED_FIELDS = frozenset({"name", "email", "job_title", "entra_business_role", "external_id"})
AUTHORITY_FIELDS = frozenset(
    {
        "password_changed",
        "is_active",
        "local_suspended",
        "local_enrollment_state",
        "role_id",
        "access_scope",
        "department_id",
        "manager_id",
        "email",
    }
)


def projected_account_active(user: User, *, settings: Settings | None = None) -> bool:
    """Recompute eligibility after an authorized underlying-state transition.

    NULL enrollment is compatible only with Entra and existing debug accounts;
    native production requires explicit completed enrollment. Unrelated profile
    synchronization must not use this to erase unexplained legacy inactivity.
    """
    if user.local_suspended:
        return False
    return upstream_and_enrollment_allow_access(user, settings=settings)


def upstream_and_enrollment_allow_access(user: User, *, settings: Settings | None = None) -> bool:
    if user.external_id:
        denied = user.deprovision_reason in AUTO_DEPROVISION_REASONS or user.directory_sync_status in {
            "directory_disabled",
            "missing",
        }
        if denied and not user.has_active_break_glass(now=utc_now()):
            return False
    elif user.local_enrollment_state is not None:
        if user.local_enrollment_state != "enrolled":
            return False
    elif settings is not None and not settings.debug and settings.auth_mode == "password":
        return False
    return True


def can_authenticate_user(user: User, *, settings: Settings | None = None) -> bool:
    # Also respect the stored projection: unknown legacy inactivity fails closed.
    return bool(user.is_active and projected_account_active(user, settings=settings))
