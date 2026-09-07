"""Explicit installation binding and read-only admission validation.

Normal startup never establishes a binding. Existing Entra adoption requires a
verified directory snapshot and a quiesced installation; it never relinks Users.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.datetime_utils import utc_now
from app.core.production_contract import IDENTITY_CONTRACT_VERSION, IdentityProfile, resolve_identity_profile
from app.models import InstallationIdentity, User
from app.services.directory_provider_service import DirectoryProviderService
from app.services.transaction_boundary import commit_service_boundary


class IdentityBindingError(RuntimeError):
    """Unsafe or ambiguous installation identity; admission must stop."""


@dataclass(frozen=True)
class BindingValidation:
    installation_id: str
    auth_mode: str
    tenant_id: str | None
    contract_version: int


def _profile(settings: Settings) -> IdentityProfile:
    try:
        profile = resolve_identity_profile(settings)
        tenant = str(UUID(profile.tenant_id)) if profile.tenant_id is not None else None
    except (ValueError, TypeError) as exc:
        raise IdentityBindingError(f"Invalid installation identity configuration: {exc}") from exc
    return IdentityProfile(profile.auth_mode, profile.directory_provider, tenant)


def _validate(binding: InstallationIdentity, profile: IdentityProfile) -> BindingValidation:
    if binding.contract_version != IDENTITY_CONTRACT_VERSION:
        raise IdentityBindingError("Unsupported installation identity contract_version")
    if binding.auth_mode != profile.auth_mode:
        raise IdentityBindingError("Installation identity profile mismatch; provider conversion is not supported")
    if binding.tenant_id != profile.tenant_id:
        raise IdentityBindingError("Installation Entra tenant mismatch; tenant conversion is not supported")
    try:
        UUID(binding.installation_id)
    except (ValueError, TypeError) as exc:
        raise IdentityBindingError("Malformed installation identity identifier") from exc
    return BindingValidation(binding.installation_id, binding.auth_mode, binding.tenant_id, binding.contract_version)


async def validate_installation_binding(db: AsyncSession, *, settings: Settings) -> BindingValidation:
    profile = _profile(settings)
    binding = (await db.execute(select(InstallationIdentity).where(InstallationIdentity.id == 1))).scalar_one_or_none()
    if binding is None:
        raise IdentityBindingError(
            "Production database is unbound. In maintenance, run python -m scripts.identity_installation "
            "initialize (fresh database) or adopt-entra (verified existing installation), then verify."
        )
    outcome = _validate(binding, profile)
    if profile.auth_mode == "password":
        external = (
            await db.execute(select(User.id).where(User.external_id.is_not(None)).limit(1))
        ).scalar_one_or_none()
        if external is not None:
            raise IdentityBindingError("Local installation contains a directory-bound User; reconciliation required")
    return outcome


async def _user_inventory(db: AsyncSession) -> tuple[tuple[int, str | None, int], ...]:
    rows = (await db.execute(select(User.id, User.external_id, User.token_version).order_by(User.id))).all()
    return tuple((row.id, row.external_id, row.token_version) for row in rows)


async def establish_installation_binding(
    db: AsyncSession,
    *,
    settings: Settings,
    source: str,
    adopt_entra: bool = False,
    dry_run: bool = False,
) -> InstallationIdentity:
    profile = _profile(settings)
    source = source.strip()
    if not source or len(source) > 255:
        raise IdentityBindingError("An auditable establishment source of 1–255 characters is required")
    existing = (await db.execute(select(InstallationIdentity).where(InstallationIdentity.id == 1))).scalar_one_or_none()
    if existing is not None:
        _validate(existing, profile)
        await validate_installation_binding(db, settings=settings)
        return existing

    inventory = await _user_inventory(db)
    if inventory and (profile.auth_mode != "microsoft_sso" or not adopt_entra):
        raise IdentityBindingError(
            "Refusing populated database initialization; explicit verified Entra adoption required"
        )
    if adopt_entra and profile.auth_mode != "microsoft_sso":
        raise IdentityBindingError("adopt-entra is unavailable for a local profile")
    if inventory:
        provider = DirectoryProviderService(settings)
        # No advisory/User row lock is held across Graph network I/O.
        for user_id, oid, _version in inventory:
            try:
                canonical_oid = str(UUID(oid or ""))
                remote = await provider.get_user(canonical_oid)
                if str(UUID(remote.external_id)) != canonical_oid:
                    raise ValueError("Directory subject mismatch")
            except Exception as exc:
                # Do not expose credentials or upstream response bodies in operator logs.
                raise IdentityBindingError(
                    f"Entra adoption cannot verify User {user_id}; reconcile its object ID"
                ) from exc

    # Serializes both identical and conflicting initializers, even before a row exists.
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.installation'))"))
    existing = (
        await db.execute(
            select(InstallationIdentity).where(InstallationIdentity.id == 1).execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if existing is not None:
        _validate(existing, profile)
        return existing
    if await _user_inventory(db) != inventory:
        raise IdentityBindingError("User inventory changed during adoption; quiesce writers and retry")
    binding = InstallationIdentity(
        id=1,
        installation_id=str(uuid4()),
        auth_mode=profile.auth_mode,
        tenant_id=profile.tenant_id,
        contract_version=IDENTITY_CONTRACT_VERSION,
        established_at=utc_now(),
        establishment_source=source,
    )
    if not dry_run:
        db.add(binding)
        await commit_service_boundary(db, boundary="identity_installation.establish")
    return binding


async def eligibility_backfill_report(db: AsyncSession) -> dict[str, int]:
    """Read-only inventory for operators; never reinterpret suspension as permission."""
    total = int((await db.execute(select(func.count(User.id)))).scalar_one())
    suspended = int((await db.execute(select(func.count(User.id)).where(User.local_suspended.is_(True)))).scalar_one())
    inactive = int((await db.execute(select(func.count(User.id)).where(User.is_active.is_(False)))).scalar_one())
    return {
        "users": total,
        "locally_suspended": suspended,
        "inactive": inactive,
        "inactive_upstream_or_unresolved": max(inactive - suspended, 0),
    }
