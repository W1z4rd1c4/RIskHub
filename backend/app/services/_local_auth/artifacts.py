"""Purpose-bound opaque credentials. Lock order is User -> grant -> factor/code."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.datetime_utils import coerce_utc, utc_now
from app.models import LocalAuthGrant, User
from app.services._auth_session_workflow.authority import lock_session_user

from .common import NativeContext, audit_local, commit_local, invalid_proof

_TOKEN = re.compile(r"([a-f0-9]{32})\.([A-Za-z0-9_-]{43})")


def secret_digest(secret: str, *, installation: str, purpose: str) -> str:
    return hashlib.sha256(f"riskhub-local-v1:{installation}:{purpose}:{secret}".encode()).hexdigest()


def browser_digest(browser: str) -> str:
    return hashlib.sha256(("riskhub-browser-v1:" + browser).encode()).hexdigest()


async def issue_grant(
    db: AsyncSession,
    ctx: NativeContext,
    user: User,
    purpose: str,
    seconds: int,
    *,
    browser: str | None = None,
    generation: str | None = None,
    context: dict | None = None,
) -> tuple[LocalAuthGrant, str]:
    selector, secret = uuid4().hex, secrets.token_urlsafe(32)
    row = LocalAuthGrant(
        id=selector,
        user_id=user.id,
        installation_id=ctx.installation_id,
        purpose=purpose,
        secret_hash=secret_digest(secret, installation=ctx.installation_id, purpose=purpose),
        token_version=user.token_version,
        factor_generation=generation,
        browser_hash=browser_digest(browser) if browser is not None else None,
        context=context or {},
        issued_at=utc_now(),
        expires_at=utc_now() + timedelta(seconds=seconds),
        failures=0,
    )
    db.add(row)
    await db.flush()
    return row, f"{selector}.{secret}"


def grant_active(row: LocalAuthGrant, user: User, installation_id: str) -> bool:
    expires = coerce_utc(row.expires_at)
    return bool(
        row.installation_id == installation_id
        and row.user_id == user.id
        and row.token_version == user.token_version
        and not user.local_suspended
        and user.external_id is None
        and row.consumed_at is None
        and row.revoked_at is None
        and row.failures < 5
        and expires is not None
        and expires > utc_now()
    )


async def read_grant(
    db: AsyncSession,
    ctx: NativeContext,
    raw: str,
    purpose: str,
    *,
    browser: str | None = None,
    locked: bool = False,
    expected_user_id: int | None = None,
) -> tuple[LocalAuthGrant, User]:
    match = _TOKEN.fullmatch(raw)
    if match is None:
        raise invalid_proof()
    selector, secret = match.groups()
    row = await db.get(LocalAuthGrant, selector, populate_existing=True)
    if row is None or row.purpose != purpose or row.installation_id != ctx.installation_id:
        raise invalid_proof()
    digest = secret_digest(secret, installation=ctx.installation_id, purpose=purpose)
    if not secrets.compare_digest(digest, row.secret_hash):
        failures, _ = await ctx.limiter.count("grant-secret-fail", selector, 900)
        if failures >= 5:
            failed_user = await lock_session_user(db, user_id=row.user_id)
            failed_row = (
                await db.execute(
                    select(LocalAuthGrant)
                    .where(LocalAuthGrant.id == selector)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).scalar_one()
            if failed_user is not None and failed_row.consumed_at is None and failed_row.revoked_at is None:
                failed_row.revoked_at = utc_now()
                await audit_local(db, failed_user, "local_grant_attempts_exhausted")
                await commit_local(db, "grant_exhausted")
        raise invalid_proof()
    if expected_user_id is not None and row.user_id != expected_user_id:
        raise invalid_proof()
    user = await lock_session_user(db, user_id=row.user_id) if locked else await db.get(User, row.user_id)
    if user is None:
        raise invalid_proof()
    if locked:
        row = (
            await db.execute(
                select(LocalAuthGrant)
                .where(LocalAuthGrant.id == selector)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
    if not grant_active(row, user, ctx.installation_id):
        raise invalid_proof()
    if row.browser_hash is not None:
        if not browser or not secrets.compare_digest(row.browser_hash, browser_digest(browser)):
            raise invalid_proof()
    return row, user


async def consume_grant(db: AsyncSession, row: LocalAuthGrant) -> None:
    now = utc_now()
    result = await db.execute(
        update(LocalAuthGrant)
        .execution_options(synchronize_session="fetch")
        .where(
            LocalAuthGrant.id == row.id,
            LocalAuthGrant.consumed_at.is_(None),
            LocalAuthGrant.revoked_at.is_(None),
            LocalAuthGrant.expires_at > now,
            LocalAuthGrant.failures < 5,
        )
        .values(consumed_at=now)
    )
    if int(getattr(result, "rowcount", 0) or 0) != 1:
        raise invalid_proof()


async def revoke_grants(db: AsyncSession, user_id: int, *, purpose: str | None = None) -> None:
    statement = (
        update(LocalAuthGrant)
        .execution_options(synchronize_session="fetch")
        .where(
            LocalAuthGrant.user_id == user_id, LocalAuthGrant.revoked_at.is_(None), LocalAuthGrant.consumed_at.is_(None)
        )
    )
    if purpose:
        statement = statement.where(LocalAuthGrant.purpose == purpose)
    await db.execute(statement.values(revoked_at=utc_now()))


async def failed_factor(db: AsyncSession, row: LocalAuthGrant, user: User) -> None:
    row.failures += 1
    if row.failures >= 5:
        row.revoked_at = utc_now()
    db.add(row)
    await audit_local(db, user, "local_factor_failed")
    await commit_local(db, "factor_failed")
    raise invalid_proof()
