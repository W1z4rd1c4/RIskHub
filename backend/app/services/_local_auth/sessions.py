"""Verify native context on the canonical access/refresh session boundary."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.datetime_utils import coerce_utc
from app.core.local_session import LocalSessionContext
from app.models import LocalAuthFactor, RefreshToken, User
from app.services.identity_installation import IdentityBindingError, validate_installation_binding

from .common import local_user_ready


async def validate_native_session(
    db: AsyncSession, *, settings: Settings, user: User, payload: dict, refresh_row: RefreshToken | None = None
) -> LocalSessionContext:
    context = LocalSessionContext.from_claims(payload)
    try:
        binding = await validate_installation_binding(db, settings=settings)
    except IdentityBindingError as exc:
        raise ValueError("Installation binding mismatch") from exc
    factor = await db.get(LocalAuthFactor, user.id, populate_existing=True)
    if (
        not local_user_ready(user)
        or user.role is None
        or not user.role.is_active
        or factor is None
        or factor.confirmed_at is None
        or factor.generation != context.factor_generation
        or binding.installation_id != context.installation_id
    ):
        raise ValueError("Native session authority is no longer valid")
    if refresh_row is not None:
        issued, expires = coerce_utc(refresh_row.authenticated_at), coerce_utc(refresh_row.expires_at)
        if (
            refresh_row.auth_method != "local_mfa"
            or issued is None
            or expires is None
            or int(issued.timestamp()) != int(context.authenticated_at.timestamp())
            or int(expires.timestamp()) != int(context.expires_at.timestamp())
            or refresh_row.factor_generation != context.factor_generation
            or refresh_row.installation_id != context.installation_id
        ):
            raise ValueError("Native refresh lineage mismatch")
    return context
