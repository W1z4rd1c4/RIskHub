"""Independent-transaction proofs; SQLite is deliberately not sufficient."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.security import get_password_hash
from app.models import InstallationIdentity, User
from app.models.user import AccessScope
from app.services.identity_installation import (
    IdentityBindingError,
    establish_installation_binding,
)
from tests.backend.pytest.test_identity_foundations import identity_settings

pytestmark = [pytest.mark.asyncio, pytest.mark.postgres]


def require_postgres(engine) -> None:
    if engine.dialect.name != "postgresql":
        pytest.skip("Authoritative PostgreSQL lock proof; not emulated on SQLite")


async def wait_for_lock_waiters(observer: AsyncSession, names: set[str]) -> None:
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        await observer.execute(text("SELECT pg_stat_clear_snapshot()"))
        found = set(
            (
                await observer.execute(
                    text(
                        "SELECT application_name FROM pg_stat_activity WHERE wait_event_type='Lock'"
                    )
                )
            ).scalars()
        )
        if names <= found:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"Concurrent requests did not reach lock admission: {names}")


@pytest.mark.parametrize("conflicting", [False, True])
async def test_concurrent_installation_initialization_has_one_binding(
    async_engine, db_session, conflicting
):
    require_postgres(async_engine)
    maker = async_sessionmaker(async_engine, expire_on_commit=False)
    settings = [identity_settings(), identity_settings()]
    if conflicting:
        settings[1] = identity_settings(
            auth_mode="password",
            directory_provider="none",
            entra_tenant_id=None,
            entra_client_id=None,
            entra_client_secret=None,
        )

    async def initialize(index):
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('application_name', :name, true)"),
                {"name": f"identity-init-{index}"},
            )
            try:
                result = await establish_installation_binding(
                    session, settings=settings[index], source="postgres-test"
                )
                return result.installation_id
            except IdentityBindingError:
                return "conflict"

    async with maker() as gate, maker() as observer:
        await gate.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.installation'))"
            )
        )
        tasks = [asyncio.create_task(initialize(i)) for i in range(2)]
        try:
            await wait_for_lock_waiters(
                observer, {"identity-init-0", "identity-init-1"}
            )
        finally:
            await gate.commit()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=15)
    rows = (await db_session.execute(select(InstallationIdentity))).scalars().all()
    assert len(rows) == 1
    if conflicting:
        assert results.count("conflict") == 1
    else:
        assert results[0] == results[1] == rows[0].installation_id


@pytest.mark.parametrize("operation", ["deactivate", "demote"])
async def test_concurrent_last_admin_removal_preserves_one_admin(
    async_engine,
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    operation,
):
    require_postgres(async_engine)
    actor = User(
        name="Lifecycle operator",
        email="operator@example.com",
        role_id=test_user.role_id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    second = User(
        name="Second global admin",
        email="other-admin@example.com",
        role_id=test_user.role_id,
        access_scope=AccessScope.GLOBAL,
        is_active=True,
    )
    db_session.add_all([actor, second])
    await db_session.commit()
    maker = async_sessionmaker(async_engine, expire_on_commit=False)
    names = iter(["identity-remove-0", "identity-remove-1"])

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('application_name', :name, true)"),
                {"name": next(names)},
            )
            yield session

    payload = (
        {"is_active": False}
        if operation == "deactivate"
        else {"role_id": test_user_employee.role_id}
    )
    async with maker() as gate, maker() as observer:
        await gate.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.administration'))"
            )
        )
        async with client_factory(
            user=actor,
            settings=identity_settings(mock_auth_enabled=True),
            db_override=independent_db,
        ) as client:
            tasks = [
                asyncio.create_task(
                    client.patch(f"/api/v1/users/{user.id}", json=payload)
                )
                for user in (test_user, second)
            ]
            try:
                await wait_for_lock_waiters(
                    observer, {"identity-remove-0", "identity-remove-1"}
                )
            finally:
                await gate.commit()
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=20)
    assert sorted(response.status_code for response in results) == [200, 409]
    survivors = (
        (
            await db_session.execute(
                select(User.id).where(
                    User.role_id == test_user.role_id,
                    User.access_scope == AccessScope.GLOBAL,
                    User.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(survivors) == 1


@pytest.mark.parametrize(
    "mutation", [{"is_active": False}, {"password": "New concurrent password 123"}]
)
async def test_login_rechecks_authority_after_concurrent_account_change(
    async_engine,
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    monkeypatch,
    mutation,
):
    require_postgres(async_engine)
    from app.api.v1.endpoints.auth import password as password_endpoint

    employee = test_user_employee
    employee.hashed_password = get_password_hash("Original password 123")
    await db_session.commit()
    reached = asyncio.Event()
    release = asyncio.Event()
    original_lock = password_endpoint.lock_session_user

    async def delayed_lock(db, *, user_id):
        reached.set()
        await asyncio.wait_for(release.wait(), timeout=15)
        return await original_lock(db, user_id=user_id)

    monkeypatch.setattr(password_endpoint, "lock_session_user", delayed_lock)
    maker = async_sessionmaker(async_engine, expire_on_commit=False)

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    settings = identity_settings(auth_mode="password", mock_auth_enabled=True)
    async with client_factory(settings=settings, db_override=independent_db) as client:
        login = asyncio.create_task(
            client.post(
                "/api/v1/auth/login",
                headers={"Origin": "http://test"},
                json={"email": employee.email, "password": "Original password 123"},
            )
        )
        try:
            await asyncio.wait_for(reached.wait(), timeout=10)
            result = await client.patch(
                f"/api/v1/users/{employee.id}",
                json=mutation,
                headers={"X-Mock-User-Id": str(test_user.id)},
            )
            assert result.status_code == 200, result.text
        finally:
            release.set()
        response = await asyncio.wait_for(login, timeout=10)
        assert response.status_code == 401
        assert "access_token" not in response.json()
        assert "riskhub_refresh_token=" not in response.headers.get("set-cookie", "")


@pytest.mark.parametrize(
    "mutation", [{"is_active": False}, {"password": "New concurrent password 123"}]
)
async def test_refresh_rechecks_authority_after_concurrent_account_change(
    async_engine,
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    monkeypatch,
    mutation,
):
    require_postgres(async_engine)
    from app.api.v1.endpoints.auth import refresh as refresh_endpoint

    employee = test_user_employee
    employee.hashed_password = get_password_hash("Original password 123")
    await db_session.commit()
    reached, release = asyncio.Event(), asyncio.Event()
    original_lock = refresh_endpoint.lock_refresh_rotation_user

    async def delayed_lock(**kwargs):
        reached.set()
        await asyncio.wait_for(release.wait(), timeout=15)
        return await original_lock(**kwargs)

    monkeypatch.setattr(refresh_endpoint, "lock_refresh_rotation_user", delayed_lock)
    maker = async_sessionmaker(async_engine, expire_on_commit=False)

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    settings = identity_settings(auth_mode="password", mock_auth_enabled=True)
    async with client_factory(settings=settings, db_override=independent_db) as client:
        login = await client.post(
            "/api/v1/auth/login",
            headers={"Origin": "http://test"},
            json={"email": employee.email, "password": "Original password 123"},
        )
        assert login.status_code == 200, login.text
        access = login.json()["access_token"]
        old_refresh = client.cookies.get("riskhub_refresh_token")
        csrf = client.cookies.get("riskhub_csrf_token")
        refresh = asyncio.create_task(
            client.post(
                "/api/v1/auth/refresh",
                headers={
                    "Origin": "http://test",
                    "X-CSRF-Token": str(csrf),
                    "Cookie": f"riskhub_refresh_token={old_refresh}; riskhub_csrf_token={csrf}",
                },
            )
        )
        try:
            await asyncio.wait_for(reached.wait(), timeout=10)
            changed = await client.patch(
                f"/api/v1/users/{employee.id}",
                json=mutation,
                headers={"X-Mock-User-Id": str(test_user.id)},
            )
            assert changed.status_code == 200, changed.text
        finally:
            release.set()
        response = await asyncio.wait_for(refresh, timeout=10)
        assert response.status_code == 401, response.text
        assert "access_token" not in response.json()
        me = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
        )
        assert me.status_code == 401
