"""Local identity orchestration context and shared transaction/audit contracts."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import AsyncIterator
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import log_activity
from app.core.config import Settings
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.local_session import native_identity_selected
from app.core.password_policy import KDF_SLOTS_PER_PROCESS
from app.core.production_contract import resolve_identity_profile
from app.models import User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.services._auth_session_workflow.transactions import commit_auth_transaction
from app.services.identity_installation import IdentityBindingError, validate_installation_binding

from .keys import LocalKeyring, unavailable
from .limiter import NativeRateLimiter


def require_native_identity(settings: Settings) -> None:
    if not native_identity_selected(settings):
        raise AuthorizationError("This authentication method is disabled", code="AUTH_METHOD_DISABLED")
    try:
        resolve_identity_profile(settings)
    except ValueError:
        raise unavailable() from None


def invalid_proof() -> AuthenticationError:
    return AuthenticationError("Invalid or expired authentication proof", code="LOCAL_AUTH_INVALID")


@dataclass(frozen=True)
class NativeContext:
    settings: Settings = field(repr=False)
    installation_id: str
    keys: LocalKeyring = field(repr=False)
    limiter: NativeRateLimiter = field(repr=False)
    source: str
    public_url: str


async def build_context(db: AsyncSession, *, settings: Settings, redis, source: str) -> NativeContext:
    require_native_identity(settings)
    try:
        binding = await validate_installation_binding(db, settings=settings)
        parsed = urlsplit(settings.public_url or "")
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.scheme not in ({"http", "https"} if settings.debug else {"https"})
        ):
            raise ValueError("Invalid public origin")
        origin = (settings.public_url or "").rstrip("/")
        if origin not in settings.cors_origins or redis is None:
            raise ValueError("Missing local security dependencies")
        from app.core.scheduler_jobs import resolve_process_worker_count

        if resolve_process_worker_count() * KDF_SLOTS_PER_PROCESS * 64 > settings.local_kdf_memory_budget_mib:
            raise ValueError("KDF memory allowance is below the configured worker envelope")
        keys = LocalKeyring.load(settings.local_auth_keyring_file)
        return NativeContext(
            settings, binding.installation_id, keys, NativeRateLimiter(redis, binding.installation_id), source, origin
        )
    except (IdentityBindingError, ValueError):
        raise unavailable() from None


def local_user_ready(user: User, *, enrollment: bool = False) -> bool:
    if user.external_id is not None or user.local_suspended or user.local_email_verified_at is None:
        return False
    if enrollment:
        return user.local_enrollment_state == "password_set"
    return bool(user.is_active and user.local_enrollment_state == "enrolled")


@asynccontextmanager
async def atomic_local_work(db: AsyncSession) -> AsyncIterator[None]:
    """Rollback rejected multi-step changes; deliberate failure counters commit before denial."""
    try:
        yield
    except BaseException:
        await db.rollback()
        raise


async def audit_local(
    db: AsyncSession, user: User | None, event: str, *, actor: User | None = None, reason: str | None = None
) -> None:
    await log_activity(
        db=db,
        actor=actor,
        action=ActivityAction.UPDATE if user is not None else ActivityAction.FAILED_LOGIN,
        entity_type=ActivityEntityType.USER,
        entity_id=user.id if user else 0,
        entity_name=user.name if user else "local authentication",
        description=event,
        safe_description=event,
        safe_description_siem=event,
        changes={"security_event": event, **({"reason": reason} if reason is not None else {})},
    )


async def commit_local(db: AsyncSession, boundary: str) -> None:
    await commit_auth_transaction(db, boundary=f"local_{boundary}")
