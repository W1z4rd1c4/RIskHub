"""Public regressions for identity delivery group 1 (#193--#196)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core import production_contract
from app.core.config import Settings
from app.core.security import create_access_token, get_password_hash
from app.models import RefreshToken, User
from app.models.user import AccessScope
from app.schemas.directory import DirectoryUserRead
from app.services.directory_provider_service import DirectoryProviderService

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def identity_settings(**overrides) -> Settings:
    values = dict(
        debug=True,
        mock_auth_enabled=False,
        auth_mode="microsoft_sso",
        directory_provider="graph",
        entra_tenant_id=TENANT,
        entra_client_id=CLIENT,
        entra_client_secret="test-credential-not-for-deployment",
        cors_origins=["http://test"],
        refresh_token_migration_grace=False,
        access_token_expire_minutes=30,
        platform_admin_access_token_expire_minutes=15,
    )
    values.update(overrides)
    return Settings(**values)


def test_local_profile_is_representable_but_not_release_admitted():
    settings = identity_settings(
        auth_mode="password",
        directory_provider="none",
        entra_tenant_id=None,
        entra_client_id=None,
        entra_client_secret=None,
    )
    profile = production_contract.resolve_identity_profile(settings)
    assert profile.auth_mode == "password"
    assert profile.directory_provider == "none"
    with pytest.raises(RuntimeError, match="208"):
        production_contract.enforce_identity_release_admission(profile)


@pytest.mark.parametrize(
    "overrides",
    [
        {"directory_provider": "ad_emulator"},
        {"directory_provider": "auto"},
        {"auth_mode": "hybrid_dev"},
        {"mock_auth_enabled": True},
        {"entra_tenant_id": None},
        {"entra_client_id": None},
        {"entra_client_secret": None},
    ],
)
def test_production_profile_rejects_invalid_combinations(overrides):
    with pytest.raises(ValueError):
        production_contract.resolve_identity_profile(identity_settings(**overrides))


@pytest.mark.asyncio
async def test_password_change_invalidates_retained_access_and_refresh(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
):
    employee = test_user_employee
    employee.hashed_password = get_password_hash("Old local password 123")
    await db_session.commit()
    settings = identity_settings(auth_mode="password", mock_auth_enabled=True)
    async with client_factory(settings=settings) as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": employee.email,
                "password": "Old local password 123",
            },
            headers={"Origin": "http://test"},
        )
        assert login.status_code == 200
        old_access = login.json()["access_token"]
        old_refresh = client.cookies.get("riskhub_refresh_token")
        csrf = client.cookies.get("riskhub_csrf_token")
        version = employee.token_version
        changed = await client.patch(
            f"/api/v1/users/{employee.id}",
            json={"password": "Replacement local password 123"},
            headers={"X-Mock-User-Id": str(test_user.id)},
        )
        assert changed.status_code == 200, changed.text
        old_me = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {old_access}"}
        )
        assert old_me.status_code == 401
        refresh = await client.post(
            "/api/v1/auth/refresh",
            headers={
                "Origin": "http://test",
                "X-CSRF-Token": str(csrf),
                "Cookie": f"riskhub_refresh_token={old_refresh}; riskhub_csrf_token={csrf}",
            },
        )
        assert refresh.status_code == 401
        await db_session.refresh(employee)
        assert employee.token_version == version + 1
        active = (
            (
                await db_session.execute(
                    select(RefreshToken).where(
                        RefreshToken.user_id == employee.id,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        assert not active


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter", ["users", "access/users"])
async def test_manual_deactivate_reactivate_cannot_revive_bearer(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    adapter,
):
    employee = test_user_employee
    settings = identity_settings(mock_auth_enabled=True)
    old = create_access_token(
        {"user_id": employee.id, "token_version": employee.token_version},
        settings=settings,
    )
    version = employee.token_version
    async with client_factory(settings=settings) as client:
        for active in (False, True):
            response = await client.patch(
                f"/api/v1/{adapter}/{employee.id}",
                json={"is_active": active},
                headers={"X-Mock-User-Id": str(test_user.id)},
            )
            assert response.status_code == 200, response.text
        result = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {old}"}
        )
        assert result.status_code == 401
        await db_session.refresh(employee)
        assert employee.token_version > version


@pytest.mark.asyncio
async def test_local_suspension_survives_directory_disable_then_reenable(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    monkeypatch,
):
    employee = test_user_employee
    employee.external_id = "11111111-0000-4000-8000-000000000001"
    await db_session.commit()

    def remote(enabled):
        return DirectoryUserRead(
            external_id=employee.external_id,
            display_name=employee.name,
            email=employee.email,
            user_principal_name=employee.email,
            account_enabled=enabled,
            source="graph",
        )

    monkeypatch.setattr(
        DirectoryProviderService,
        "get_user",
        AsyncMock(side_effect=[remote(False), remote(True)]),
    )
    async with client_factory(
        user=test_user, settings=identity_settings(mock_auth_enabled=True)
    ) as client:
        suspended = await client.patch(
            f"/api/v1/users/{employee.id}", json={"is_active": False}
        )
        assert suspended.status_code == 200
        for _ in range(2):
            check = await client.post(
                f"/api/v1/admin/directory/check-user/{employee.id}"
            )
            assert check.status_code == 200, check.text
        await db_session.refresh(employee)
        assert employee.is_active is False
        assert employee.local_suspended is True
        assert employee.directory_sync_status == "active"


@pytest.mark.asyncio
async def test_last_global_platform_admin_is_not_replaced_by_a_cro(
    db_session,
    client_factory,
    test_user,
    test_user_cro,
):
    actor = User(
        email="second-admin@example.com",
        name="Second administrator",
        role_id=test_user.role_id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    db_session.add(actor)
    await db_session.commit()
    async with client_factory(
        user=actor, settings=identity_settings(mock_auth_enabled=True)
    ) as client:
        result = await client.patch(
            f"/api/v1/users/{test_user.id}", json={"is_active": False}
        )
        assert result.status_code == 409, result.text
        await db_session.refresh(test_user)
        assert test_user.is_active is True


@pytest.mark.asyncio
@pytest.mark.parametrize("version", [None, False, "0"])
async def test_production_bearer_requires_strict_version(
    client_factory, test_user, version
):
    settings = identity_settings(debug=False)
    claims = {"user_id": test_user.id}
    if version is not None:
        claims["token_version"] = version
    token = create_access_token(claims, settings=settings)
    async with client_factory(settings=settings) as client:
        result = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert result.status_code == 401


@pytest.mark.asyncio
async def test_installation_binding_requires_explicit_establishment(db_session):
    from app.services.identity_installation import (
        IdentityBindingError,
        validate_installation_binding,
    )

    with pytest.raises(IdentityBindingError, match="unbound"):
        await validate_installation_binding(db_session, settings=identity_settings())


@pytest.mark.asyncio
async def test_installation_binding_is_idempotent_and_rejects_tenant_drift(db_session):
    from app.models import InstallationIdentity
    from app.services.identity_installation import (
        IdentityBindingError,
        establish_installation_binding,
        validate_installation_binding,
    )

    settings = identity_settings()
    created = await establish_installation_binding(
        db_session, settings=settings, source="pytest-initialization"
    )
    installation_id = created.installation_id
    repeated = await establish_installation_binding(
        db_session, settings=settings, source="pytest-repeat"
    )
    assert repeated.installation_id == installation_id
    await validate_installation_binding(db_session, settings=settings)
    with pytest.raises(IdentityBindingError, match="tenant"):
        await validate_installation_binding(
            db_session,
            settings=identity_settings(
                entra_tenant_id="99999999-2222-4333-8444-555555555555"
            ),
        )
    assert (
        await db_session.execute(select(InstallationIdentity))
    ).scalars().one().installation_id == installation_id


@pytest.mark.asyncio
async def test_local_binding_refuses_populated_database(db_session, test_user):
    from app.services.identity_installation import (
        IdentityBindingError,
        establish_installation_binding,
    )

    settings = identity_settings(
        auth_mode="password",
        directory_provider="none",
        entra_tenant_id=None,
        entra_client_id=None,
        entra_client_secret=None,
    )
    with pytest.raises(IdentityBindingError, match="populated"):
        await establish_installation_binding(
            db_session, settings=settings, source="pytest-unsafe"
        )


@pytest.mark.asyncio
async def test_binding_dry_run_does_not_write(db_session):
    from app.models import InstallationIdentity
    from app.services.identity_installation import establish_installation_binding

    await establish_installation_binding(
        db_session, settings=identity_settings(), source="pytest", dry_run=True
    )
    assert not (await db_session.execute(select(InstallationIdentity))).scalars().all()


@pytest.mark.asyncio
async def test_access_change_revokes_once_but_noop_and_display_edit_do_not(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    test_user_cro,
):
    employee = test_user_employee
    settings = identity_settings(mock_auth_enabled=True)
    token = create_access_token(
        {"user_id": employee.id, "token_version": employee.token_version},
        settings=settings,
    )
    initial_version = employee.token_version
    async with client_factory(settings=settings) as client:
        for _ in range(2):
            result = await client.patch(
                f"/api/v1/access/users/{employee.id}",
                json={"access_scope": "global"},
                headers={"X-Mock-User-Id": str(test_user_cro.id)},
            )
            assert result.status_code == 200, result.text
        result = await client.patch(
            f"/api/v1/users/{employee.id}",
            json={"name": "Changed display name"},
            headers={"X-Mock-User-Id": str(test_user.id)},
        )
        assert result.status_code == 200
        assert (
            await client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
        ).status_code == 401
    await db_session.refresh(employee)
    assert employee.token_version == initial_version + 1


@pytest.mark.asyncio
async def test_break_glass_cannot_clear_local_suspension(
    db_session, client_factory, test_user, test_user_employee
):
    user = test_user_employee
    user.external_id = "11111111-0000-4000-8000-000000000001"
    user.local_suspended = True
    user.is_active = False
    user.deprovision_reason = "directory_disabled"
    await db_session.commit()
    async with client_factory(user=test_user) as client:
        result = await client.post(
            f"/api/v1/admin/directory/break-glass-enable/{user.id}",
            json={"reason": "Test recovery incident", "expires_in_hours": 1},
        )
        assert result.status_code == 409
    await db_session.refresh(user)
    assert user.is_active is False
    assert user.local_suspended is True
    assert user.break_glass_expires_at is None


@pytest.mark.asyncio
async def test_entra_identity_is_readonly_but_department_is_local(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
    test_department,
):
    test_user_employee.external_id = "11111111-0000-4000-8000-000000000001"
    await db_session.commit()
    async with client_factory(
        user=test_user, settings=identity_settings(mock_auth_enabled=True)
    ) as client:
        result = await client.patch(
            f"/api/v1/users/{test_user_employee.id}", json={"department_id": None}
        )
        assert result.status_code == 200, result.text
        forbidden = await client.patch(
            f"/api/v1/users/{test_user_employee.id}",
            json={"name": "Forged upstream name"},
        )
        assert forbidden.status_code == 403


@pytest.mark.asyncio
async def test_admin_capabilities_report_last_admin_and_local_suspension(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
):
    test_user_employee.local_suspended = True
    test_user_employee.is_active = False
    await db_session.commit()
    async with client_factory(
        user=test_user, settings=identity_settings(mock_auth_enabled=True)
    ) as client:
        response = await client.get("/api/v1/access/users")
        assert response.status_code == 200
        rows = {row["id"]: row for row in response.json()}
        admin = rows[test_user.id]["capabilities"]
        assert admin["active_status_block_reason"] == "LAST_PLATFORM_ADMIN"
        assert admin["can_deactivate"] is False
        employee = rows[test_user_employee.id]
        assert employee["local_suspended"] is True
        assert employee["capabilities"]["can_resume"] is True


def test_reserved_auth_schemas_and_frontend_types_have_one_source():
    from pydantic import ValidationError

    from app.schemas.local_auth import LocalAuthChallenge
    from scripts.export_local_auth_contract import documents

    for path, expected in documents().items():
        assert path.read_text() == expected, f"Regenerate {path}"
    with pytest.raises(ValidationError):
        LocalAuthChallenge(
            status="mfa_required", challenge="restricted", access_token="ordinary-token"
        )


@pytest.mark.asyncio
async def test_startup_unbound_fails_before_runtime_services(async_engine, monkeypatch):
    from fastapi import FastAPI
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app import main
    from app.services.identity_installation import IdentityBindingError

    app = FastAPI()
    app.state.settings = identity_settings(debug=False)
    app.state.db_engine = async_engine
    app.state.db_sessionmaker = async_sessionmaker(async_engine, expire_on_commit=False)
    runtime = AsyncMock()
    monkeypatch.setattr(main, "bootstrap_runtime_services", runtime)
    with pytest.raises(IdentityBindingError, match="unbound"):
        async with main.lifespan(app):
            pytest.fail("An unbound installation must not admit requests")
    runtime.assert_not_awaited()


def test_additive_migration_backfill_preserves_inactivity_and_user_ids():
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import create_engine, text

    path = (
        Path(__file__).resolve().parents[3]
        / "backend/alembic/versions/t9u0v1w2x3y4_identity_foundations.py"
    )
    spec = importlib.util.spec_from_file_location(
        "identity_foundations_migration", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, is_active BOOLEAN NOT NULL, "
                "external_id TEXT, deprovision_reason TEXT)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO users VALUES (10, true, 'oid-active', NULL), "
                "(20, false, 'oid-manual', NULL), (30, false, 'oid-auto', 'missing'), "
                "(40, false, NULL, 'missing')"
            )
        )
        conn.execute(
            text("CREATE TABLE ownership (user_id INTEGER REFERENCES users(id))")
        )
        conn.execute(text("INSERT INTO ownership VALUES (20)"))
        with Operations.context(MigrationContext.configure(conn)):
            module.upgrade()
        assert conn.execute(
            text("SELECT id, is_active, local_suspended FROM users ORDER BY id")
        ).all() == [(10, 1, 0), (20, 0, 1), (30, 0, 0), (40, 0, 1)]
        assert conn.execute(text("SELECT user_id FROM ownership")).scalar_one() == 20
        assert (
            conn.execute(
                text("SELECT count(*) FROM installation_identity")
            ).scalar_one()
            == 0
        )
    engine.dispose()


@pytest.mark.asyncio
async def test_repeated_same_password_does_not_churn_session_authority(
    db_session,
    client_factory,
    test_user,
    test_user_employee,
):
    employee = test_user_employee
    employee.hashed_password = get_password_hash("Unchanged local password 123")
    await db_session.commit()
    original = (employee.hashed_password, employee.token_version)
    settings = identity_settings(auth_mode="password", mock_auth_enabled=True)
    async with client_factory(settings=settings) as client:
        for _ in range(2):
            result = await client.patch(
                f"/api/v1/users/{employee.id}",
                json={"password": "Unchanged local password 123"},
                headers={"X-Mock-User-Id": str(test_user.id)},
            )
            assert result.status_code == 200, result.text
        await db_session.refresh(employee)
        assert (employee.hashed_password, employee.token_version) == original


@pytest.mark.asyncio
@pytest.mark.parametrize("suspended", [False, True])
async def test_production_sso_bootstrap_never_restores_privilege_or_reactivates(
    db_session,
    test_role,
    monkeypatch,
    suspended,
):
    import argparse
    from contextlib import asynccontextmanager

    from app.services.identity_installation import establish_installation_binding
    from scripts import bootstrap_sso_user

    settings = identity_settings(debug=False)
    await establish_installation_binding(
        db_session, settings=settings, source="fresh test"
    )
    oid = "aabbccdd-0000-4000-8000-112233445566"
    user = User(
        email="existing@example.com",
        name="Existing",
        role_id=test_role.id,
        external_id=oid,
        access_scope=AccessScope.DEPARTMENT,
        is_active=not suspended,
        local_suspended=suspended,
    )
    db_session.add(user)
    await db_session.commit()

    @asynccontextmanager
    async def session(_settings):
        yield db_session

    monkeypatch.setattr(bootstrap_sso_user, "get_settings", lambda: settings)
    monkeypatch.setattr(bootstrap_sso_user, "session_context", session)
    with pytest.raises(SystemExit, match="authenticated identity lifecycle"):
        await bootstrap_sso_user._run(
            argparse.Namespace(
                email=user.email,
                external_id=oid,
                role=test_role.name,
                access_scope="global",
                department=None,
                name=None,
            )
        )
    await db_session.refresh(user)
    assert user.access_scope == AccessScope.DEPARTMENT
    assert user.is_active is (not suspended)
    assert user.local_suspended is suspended


@pytest.mark.asyncio
async def test_fresh_explicit_oid_bootstrap_commits_the_new_identity(
    db_session,
    test_role,
    monkeypatch,
):
    import argparse
    from contextlib import asynccontextmanager

    from app.services.identity_installation import establish_installation_binding
    from scripts import bootstrap_sso_user

    settings = identity_settings(debug=False)
    await establish_installation_binding(
        db_session, settings=settings, source="fresh test"
    )
    oid = "aabbccdd-0000-4000-8000-112233445566"

    @asynccontextmanager
    async def session(_settings):
        yield db_session

    monkeypatch.setattr(bootstrap_sso_user, "get_settings", lambda: settings)
    monkeypatch.setattr(bootstrap_sso_user, "session_context", session)
    assert (
        await bootstrap_sso_user._run(
            argparse.Namespace(
                email="fresh@example.com",
                external_id=oid,
                role=test_role.name,
                access_scope="global",
                department=None,
                name=None,
            )
        )
        == 0
    )
    await db_session.rollback()
    user = (
        await db_session.execute(select(User).where(User.external_id == oid))
    ).scalar_one()
    assert user.email == "fresh@example.com"
    assert user.hashed_password is None


@pytest.mark.asyncio
async def test_last_platform_admin_demotion_uses_conflict_even_without_cro(
    db_session, client_factory, test_user, test_user_employee,
):
    actor = User(
        name="Scoped lifecycle operator",
        email="scoped-lifecycle@example.com",
        role_id=test_user.role_id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    db_session.add(actor)
    await db_session.commit()
    original_role = test_user.role_id
    async with client_factory(
        user=actor, settings=identity_settings(mock_auth_enabled=True),
    ) as client:
        response = await client.patch(
            f"/api/v1/users/{test_user.id}",
            json={"role_id": test_user_employee.role_id},
        )
    assert response.status_code == 409, response.text
    await db_session.refresh(test_user)
    assert test_user.role_id == original_role


def test_empty_object_wire_types_do_not_accept_primitives():
    from scripts.export_local_auth_contract import typescript_type

    closed_object = {"type": "object", "properties": {}, "additionalProperties": False}
    assert typescript_type(closed_object) == "Record<string, never>"
    assert typescript_type({"type": "object", "additionalProperties": False}) == "Record<string, never>"
    assert typescript_type({"type": "object", "properties": {}}) == "Record<string, unknown>"
    assert typescript_type({"type": "object", "additionalProperties": {"type": "string"}}) == "Record<string, string>"
