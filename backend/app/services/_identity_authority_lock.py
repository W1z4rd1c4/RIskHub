"""Serialization for identity lifecycle and last-platform-admin decisions.

Order: administration guard -> ownership advisory guards -> org-chart guard ->
User rows in ID order -> refresh/resource rows. No network or KDF work belongs
inside this boundary. This is a lifecycle-specific lock, not a generic framework.
"""

from __future__ import annotations

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, NotFoundError
from app.core.identity_policy import can_authenticate_user
from app.core.user_query_options import user_selectinload_options
from app.models import User
from app.services._asset_owner_lock import acquire_asset_owner_identity_lock
from app.services._org_chart import acquire_org_chart_lock
from app.services._process_owner_lock import acquire_process_owner_identity_lock
from app.services._threat_stewardship_lock import acquire_threat_steward_identity_lock
from app.services._vendor_owner_lock import acquire_vendor_owner_identity_lock


async def lock_identity_transition(
    db: AsyncSession,
    *,
    user_id: int,
    actor: User | None = None,
) -> User:
    actor_version = actor.token_version if actor is not None else None
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.administration'))"))
    await acquire_threat_steward_identity_lock(db, user_id=user_id)
    await acquire_process_owner_identity_lock(db, user_id=user_id)
    await acquire_asset_owner_identity_lock(db, user_id=user_id)
    await acquire_vendor_owner_identity_lock(db, user_id=user_id)
    await acquire_org_chart_lock(db)
    ids = {user_id}
    if actor is not None:
        ids.add(actor.id)
    # Manager cleanup changes subordinate assignments. Include their authority
    # rows in the same ordered acquisition, while the org guard freezes the set.
    users = (
        (
            await db.execute(
                select(User)
                .options(*user_selectinload_options(include_permissions=True, include_manager=False))
                .where(or_(User.id.in_(ids), User.manager_id == user_id))
                .order_by(User.id)
                .with_for_update(of=User)
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    by_id = {user.id: user for user in users}
    if user_id not in by_id:
        raise NotFoundError("User not found")
    if actor is not None:
        current_actor = by_id.get(actor.id)
        if (
            current_actor is None
            or not can_authenticate_user(current_actor)
            or current_actor.token_version != actor_version
        ):
            raise AuthenticationError("Session revoked; reauthenticate before changing identity")
    return by_id[user_id]
