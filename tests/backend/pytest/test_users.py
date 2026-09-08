import asyncio

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.security import verify_password
from app.main import app
from app.models import Department, Permission, Role, RolePermission, User
from app.schemas import UserUpdate
from app.services._identity_access_lifecycle.profile_updates import update_user_profile


@pytest_asyncio.fixture
async def auth_client_sso(client_factory, test_user: User):
    settings = Settings(mock_auth_enabled=True, debug=True, auth_mode="microsoft_sso")
    async with client_factory(current_user=test_user, settings=settings) as ac:
        yield ac


@pytest_asyncio.fixture
async def users_read_employee_role(
    db_session: AsyncSession, test_role_employee: Role
) -> Role:
    """Canonical employee role with the explicit grant these lookup tests require."""
    users_read = Permission(
        resource="users", action="read", description="View users"
    )
    db_session.add(users_read)
    await db_session.flush()
    db_session.add(
        RolePermission(role_id=test_role_employee.id, permission_id=users_read.id)
    )
    await db_session.commit()
    return test_role_employee


@pytest.mark.asyncio
async def test_list_users(auth_client: AsyncClient, test_user: User):
    """Test listing users."""
    response = await auth_client.get("/api/v1/users")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # At least the test_user should be there
    assert len(data) >= 1
    assert any(u["email"] == test_user.email for u in data)


@pytest.mark.asyncio
async def test_list_directory_users_for_global_directory_reader(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
):
    response = await client_risk_manager.get("/api/v1/users/directory")
    assert response.status_code == 200
    payload = response.json()
    assert payload["skip"] == 0
    assert payload["limit"] == 50
    assert payload["total"] >= 1
    assert any(role["name"] == "employee" for role in payload["available_roles"])
    assert any(item["email"] == test_user_employee.email for item in payload["items"])
    assert payload["capabilities"] == {
        "can_read_directory": True,
        "can_view_access_details": True,
        "can_use_role_facets": True,
        "can_create_local_user": False,
        "can_import_directory_user": False,
    }


@pytest.mark.asyncio
async def test_directory_capabilities_match_user_lifecycle_authority_for_cro(
    client_cro: AsyncClient,
    test_user: User,
):
    directory_response = await client_cro.get("/api/v1/users/directory")
    assert directory_response.status_code == 200
    assert directory_response.json()["capabilities"]["can_create_local_user"] is False

    create_response = await client_cro.post(
        "/api/v1/users",
        json={
            "email": "cro.local.create@example.com",
            "name": "CRO Local Create",
            "password": "StrongPass123!",
            "role_id": test_user.role_id,
            "department_id": None,
            "manager_id": None,
            "is_active": True,
        },
    )
    assert create_response.status_code == 403
    assert create_response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_directory_capabilities_allow_local_user_creation_for_platform_admin(
    client_platform_admin: AsyncClient,
):
    response = await client_platform_admin.get("/api/v1/users/directory")
    assert response.status_code == 200
    assert response.json()["capabilities"]["can_create_local_user"] is True


@pytest.mark.asyncio
async def test_list_directory_users_requires_users_read(client_employee: AsyncClient):
    response = await client_employee.get("/api/v1/users/directory")
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


@pytest.mark.asyncio
async def test_directory_reader_gets_scope_filtered_directory_with_role_facets(
    client_directory_reader: AsyncClient,
    db_session: AsyncSession,
    test_department,
    test_user_directory_reader: User,
):
    viewer_role = Role(name="viewer", display_name="Viewer", description="Read-only viewer")
    db_session.add(viewer_role)
    await db_session.commit()
    await db_session.refresh(viewer_role)

    visible_user = User(
        email="visible.viewer@example.com",
        hashed_password="hash",
        name="Visible Viewer",
        role_id=viewer_role.id,
        department_id=test_department.id,
        is_active=True,
        access_scope=test_user_directory_reader.access_scope,
    )
    hidden_department = Department(name="Hidden Directory Dept", code="DIR-HIDDEN", description="Hidden dept")
    db_session.add(hidden_department)
    await db_session.commit()
    await db_session.refresh(hidden_department)

    hidden_user = User(
        email="hidden.viewer@example.com",
        hashed_password="hash",
        name="Hidden Viewer",
        role_id=viewer_role.id,
        department_id=hidden_department.id,
        is_active=True,
        access_scope=test_user_directory_reader.access_scope,
    )
    db_session.add_all([visible_user, hidden_user])
    await db_session.commit()

    response = await client_directory_reader.get("/api/v1/users/directory")

    assert response.status_code == 200
    payload = response.json()
    emails = {item["email"] for item in payload["items"]}
    role_names = {role["name"] for role in payload["available_roles"]}

    assert "visible.viewer@example.com" in emails
    assert "hidden.viewer@example.com" not in emails
    assert "directory_reader" in role_names
    assert "viewer" in role_names


@pytest.mark.asyncio
async def test_directory_role_filter_keeps_alternative_role_facets(
    client_directory_reader: AsyncClient,
    db_session: AsyncSession,
    test_department,
):
    employee_role = Role(name="employee", display_name="Employee", description="Employee")
    viewer_role = Role(name="viewer", display_name="Viewer", description="Viewer")
    db_session.add_all([employee_role, viewer_role])
    await db_session.commit()
    await db_session.refresh(employee_role)
    await db_session.refresh(viewer_role)

    db_session.add_all(
        [
            User(
                email="facet.employee@example.com",
                hashed_password="hash",
                name="Facet Employee",
                role_id=employee_role.id,
                department_id=test_department.id,
                is_active=True,
            ),
            User(
                email="facet.viewer@example.com",
                hashed_password="hash",
                name="Facet Viewer",
                role_id=viewer_role.id,
                department_id=test_department.id,
                is_active=True,
            ),
        ]
    )
    await db_session.commit()

    response = await client_directory_reader.get("/api/v1/users/directory?role_name=viewer")

    assert response.status_code == 200
    payload = response.json()
    assert {item["email"] for item in payload["items"]} == {"facet.viewer@example.com"}
    assert {role["name"] for role in payload["available_roles"]} >= {"employee", "viewer"}


@pytest.mark.asyncio
async def test_get_user(auth_client: AsyncClient, test_user: User):
    """Test getting a single user."""
    response = await auth_client.get(f"/api/v1/users/{test_user.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == test_user.email
    assert data["id"] == test_user.id


@pytest.mark.asyncio
async def test_get_user_includes_entra_business_role(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
):
    test_user.entra_business_role = "Regional Director"
    db_session.add(test_user)
    await db_session.commit()

    response = await auth_client.get(f"/api/v1/users/{test_user.id}")

    assert response.status_code == 200
    assert response.json()["entra_business_role"] == "Regional Director"


@pytest.mark.asyncio
async def test_get_user_requires_platform_admin_for_other_users(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
):
    response = await client_risk_manager.get(f"/api/v1/users/{test_user_employee.id}")
    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_get_user_requires_platform_admin_even_for_self(
    client_employee: AsyncClient,
    test_user_employee: User,
):
    response = await client_employee.get(f"/api/v1/users/{test_user_employee.id}")
    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_update_user_fields(auth_client: AsyncClient, test_user: User):
    """Test updating user fields (PATCH)."""
    update_data = {"name": "Updated Name"}
    response = await auth_client.patch(f"/api/v1/users/{test_user.id}", json=update_data)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Name"
    # Email should remain unchanged
    assert data["email"] == test_user.email


@pytest.mark.asyncio
async def test_update_user_rejects_inactive_role_assignment(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user_employee: User,
):
    inactive_role = Role(
        name="inactive_profile_role",
        display_name="Inactive Profile Role",
        description="Inactive role must not be assignable through user lifecycle",
        is_active=False,
    )
    db_session.add(inactive_role)
    await db_session.commit()
    await db_session.refresh(inactive_role)

    original_role_id = test_user_employee.role_id
    response = await auth_client.patch(
        f"/api/v1/users/{test_user_employee.id}",
        json={"role_id": inactive_role.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid role_id"
    await db_session.refresh(test_user_employee)
    assert test_user_employee.role_id == original_role_id


@pytest.mark.asyncio
async def test_update_user_ignores_entra_business_role_payload(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
):
    test_user.entra_business_role = "Original Role"
    db_session.add(test_user)
    await db_session.commit()

    response = await auth_client.patch(
        f"/api/v1/users/{test_user.id}",
        json={"name": "Updated Name", "entra_business_role": "Tampered Role"},
    )

    assert response.status_code == 200
    assert response.json()["name"] == "Updated Name"
    assert response.json()["entra_business_role"] == "Original Role"

    await db_session.refresh(test_user)
    assert test_user.entra_business_role == "Original Role"


@pytest.mark.asyncio
async def test_update_user_rejects_manager_cycle(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user: User,
    test_user_employee: User,
):
    test_user_employee.manager_id = test_user.id
    db_session.add(test_user_employee)
    await db_session.commit()

    response = await auth_client.patch(
        f"/api/v1/users/{test_user.id}",
        json={"manager_id": test_user_employee.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User manager hierarchy cannot contain a cycle"


@pytest.mark.asyncio
async def test_update_user_rejects_self_manager_cycle(
    auth_client: AsyncClient,
    test_user: User,
):
    response = await auth_client.patch(
        f"/api/v1/users/{test_user.id}",
        json={"manager_id": test_user.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User manager hierarchy cannot contain a cycle"


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_concurrent_manager_updates_cannot_create_two_user_cycle(
    async_engine: AsyncEngine,
    db_session: AsyncSession,
    test_user: User,
    test_user_employee: User,
):
    if async_engine.dialect.name != "postgresql":
        pytest.skip("Postgres advisory-lock behavior only applies under PostgreSQL")

    peer = User(
        email="org-cycle-peer@example.com",
        hashed_password="hash",
        name="Org Cycle Peer",
        role_id=test_user_employee.role_id,
        department_id=test_user_employee.department_id,
        is_active=True,
    )
    db_session.add(peer)
    await db_session.commit()
    await db_session.refresh(peer)

    session_maker = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    settings = Settings(mock_auth_enabled=True, debug=True)

    async def assign_manager(user_id: int, manager_id: int) -> str:
        async with session_maker() as session:
            actor = await session.get(User, test_user.id)
            try:
                await update_user_profile(
                    db=session,
                    settings=settings,
                    current_user=actor,
                    user_id=user_id,
                    user_data=UserUpdate(manager_id=manager_id),
                )
            except HTTPException as exc:
                await session.rollback()
                return str(exc.detail)
            return "ok"

    results = await asyncio.gather(
        assign_manager(test_user_employee.id, peer.id),
        assign_manager(peer.id, test_user_employee.id),
    )

    assert results.count("ok") == 1
    assert "User manager hierarchy cannot contain a cycle" in results

    async with session_maker() as session:
        first = await session.get(User, test_user_employee.id)
        second = await session.get(User, peer.id)
        assert not (first.manager_id == second.id and second.manager_id == first.id)


@pytest.mark.asyncio
async def test_update_user_rejects_department_change_when_user_manages_current_department(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user_employee: User,
):
    source_dept = Department(name="Managed Source", code="MANAGED_SRC", is_active=True)
    target_dept = Department(name="Transfer Target", code="TRANSFER_TGT", is_active=True)
    db_session.add_all([source_dept, target_dept])
    await db_session.flush()
    test_user_employee.department_id = source_dept.id
    source_dept.manager_id = test_user_employee.id
    await db_session.commit()
    await db_session.refresh(target_dept)

    response = await auth_client.patch(
        f"/api/v1/users/{test_user_employee.id}",
        json={"department_id": target_dept.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Clear the department manager before moving this user"


@pytest.mark.asyncio
async def test_update_user_requires_platform_admin(
    client_cro: AsyncClient,
    test_user_employee: User,
):
    response = await client_cro.patch(f"/api/v1/users/{test_user_employee.id}", json={"name": "Blocked"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_create_user_rejected_in_microsoft_sso_mode(auth_client_sso: AsyncClient, test_user: User):
    response = await auth_client_sso.post(
        "/api/v1/users",
        json={
            "email": "new.user@example.com",
            "name": "New User",
            "password": "StrongPass123!",
            "role_id": test_user.role_id,
            "department_id": None,
            "manager_id": None,
            "is_active": True,
        },
    )
    assert response.status_code == 403
    assert "directory/users/{oid}/import" in response.json()["detail"]


@pytest.mark.asyncio
async def test_create_user_requires_platform_admin(client_cro: AsyncClient, test_user: User):
    response = await client_cro.post(
        "/api/v1/users",
        json={
            "email": "new.user@example.com",
            "name": "New User",
            "password": "StrongPass123!",
            "role_id": test_user.role_id,
            "department_id": None,
            "manager_id": None,
            "is_active": True,
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_create_user_with_manager_keeps_valid_manager_chain(
    client_platform_admin: AsyncClient,
    test_user_employee: User,
):
    response = await client_platform_admin.post(
        "/api/v1/users",
        json={
            "email": "managed.new.user@example.com",
            "name": "Managed New User",
            "password": "StrongPass123!",
            "role_id": test_user_employee.role_id,
            "department_id": test_user_employee.department_id,
            "manager_id": test_user_employee.id,
            "is_active": True,
        },
    )

    assert response.status_code == 201
    assert response.json()["manager_id"] == test_user_employee.id


@pytest.mark.asyncio
async def test_update_user_password(auth_client: AsyncClient, test_user: User, db_session: AsyncSession):
    """Test updating user password hashes correctly."""
    new_password = "new_secure_password"
    update_data = {"password": new_password}

    response = await auth_client.patch(f"/api/v1/users/{test_user.id}", json=update_data)
    assert response.status_code == 200

    # Verify in DB
    await db_session.refresh(test_user)
    assert verify_password(new_password, test_user.hashed_password)
    # Ensure it's not stored as plain text
    assert test_user.hashed_password != new_password


@pytest.mark.asyncio
async def test_update_user_password_rejected_in_microsoft_sso_mode(
    auth_client_sso: AsyncClient,
    test_user: User,
    db_session: AsyncSession,
):
    old_hash = test_user.hashed_password
    response = await auth_client_sso.patch(f"/api/v1/users/{test_user.id}", json={"password": "another-password"})
    assert response.status_code == 403
    assert "disabled in microsoft_sso mode" in response.json()["detail"]

    await db_session.refresh(test_user)
    assert test_user.hashed_password == old_hash


@pytest.mark.asyncio
async def test_update_user_password_key_null_rejected_in_microsoft_sso_mode(
    auth_client_sso: AsyncClient,
    test_user: User,
    db_session: AsyncSession,
):
    old_hash = test_user.hashed_password
    response = await auth_client_sso.patch(f"/api/v1/users/{test_user.id}", json={"password": None})
    assert response.status_code == 403
    assert "disabled in microsoft_sso mode" in response.json()["detail"]

    await db_session.refresh(test_user)
    assert test_user.hashed_password == old_hash


@pytest.mark.asyncio
async def test_update_user_non_password_fields_allowed_in_microsoft_sso_mode(
    auth_client_sso: AsyncClient,
    test_user: User,
):
    response = await auth_client_sso.patch(
        f"/api/v1/users/{test_user.id}",
        json={"name": "SSO Allowed Update", "is_active": test_user.is_active},
    )
    assert response.status_code == 200
    assert response.json()["name"] == "SSO Allowed Update"


@pytest.mark.asyncio
async def test_update_user_email_conflict(auth_client: AsyncClient, test_user: User, db_session: AsyncSession):
    """Test email uniqueness check during update."""
    # Create another user to conflict with
    other_user = User(
        email="conflict@example.com",
        hashed_password="hash",
        name="Conflict User",
        role_id=test_user.role_id,
        department_id=test_user.department_id,
        is_active=True,
    )
    db_session.add(other_user)
    await db_session.commit()

    update_data = {"email": "Conflict@Example.com"}
    response = await auth_client.patch(f"/api/v1/users/{test_user.id}", json=update_data)
    assert response.status_code == 400
    assert "Email already registered" in response.json()["detail"]


@pytest.mark.asyncio
async def test_update_user_rejects_self_privileged_role_demotion(
    auth_client: AsyncClient,
    test_user: User,
    test_user_employee: User,
):
    response = await auth_client.patch(f"/api/v1/users/{test_user.id}", json={"role_id": test_user_employee.role_id})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "LAST_PLATFORM_ADMIN"


@pytest.mark.asyncio
async def test_update_user_rejects_deactivating_last_privileged_user(auth_client: AsyncClient, test_user: User):
    response = await auth_client.patch(f"/api/v1/users/{test_user.id}", json={"is_active": False})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "LAST_PLATFORM_ADMIN"


@pytest.mark.asyncio
async def test_update_user_deactivation_clears_org_manager_references(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_user_employee: User,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.services._identity_access_lifecycle import profile_updates

    call_order: list[str] = []
    original_clear = profile_updates.clear_manager_references_for_inactive_user

    async def capture_lock(db: AsyncSession) -> None:
        call_order.append("lock")

    async def capture_clear(db: AsyncSession, *, user_id: int) -> None:
        call_order.append("clear")
        await original_clear(db, user_id=user_id)

    monkeypatch.setattr(profile_updates, "acquire_org_chart_lock", capture_lock)
    monkeypatch.setattr(profile_updates, "clear_manager_references_for_inactive_user", capture_clear)

    managed_dept = Department(name="Managed Deactivation", code="MANAGED_DEACT", is_active=True)
    db_session.add(managed_dept)
    await db_session.flush()
    test_user_employee.department_id = managed_dept.id
    managed_dept.manager_id = test_user_employee.id
    subordinate = User(
        email="deactivation-subordinate@example.com",
        hashed_password="hash",
        name="Deactivation Subordinate",
        role_id=test_user_employee.role_id,
        department_id=managed_dept.id,
        manager_id=test_user_employee.id,
        is_active=True,
    )
    db_session.add(subordinate)
    await db_session.commit()
    await db_session.refresh(managed_dept)
    await db_session.refresh(subordinate)

    response = await auth_client.patch(f"/api/v1/users/{test_user_employee.id}", json={"is_active": False})

    assert response.status_code == 200
    assert call_order == ["lock", "clear"]
    await db_session.refresh(managed_dept)
    await db_session.refresh(subordinate)
    assert managed_dept.manager_id is None
    assert subordinate.manager_id is None


@pytest.mark.asyncio
async def test_list_roles(client_platform_admin: AsyncClient):
    """Test listing roles for admin-only lifecycle flows."""
    response = await client_platform_admin.get("/api/v1/users/roles")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1  # At least 'admin' from test_user fixture
    role_names = [r["name"] for r in data]
    assert "admin" in role_names


@pytest.mark.asyncio
async def test_list_roles_requires_platform_admin(client_cro: AsyncClient):
    response = await client_cro.get("/api/v1/users/roles")
    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can manage user lifecycle"


@pytest.mark.asyncio
async def test_mock_login_disabled_returns_404(
    client: AsyncClient,
    test_user: User,
):
    """Mock login endpoint should be unavailable unless debug+mock auth are both enabled."""

    def override_settings_disabled():
        return Settings(secret_key="test-secret-key-32-chars-minimum-value", debug=True, mock_auth_enabled=False)

    app.dependency_overrides[get_settings] = override_settings_disabled
    try:
        response = await client.post(f"/api/v1/users/mock-login/{test_user.id}")
        assert response.status_code == 404
        assert response.json()["detail"] == "Mock auth not enabled"
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.asyncio
async def test_mock_login_enabled_in_debug_mode(
    client: AsyncClient,
    test_user: User,
):
    """Mock login endpoint should work only when debug+mock auth are enabled."""

    def override_settings_enabled():
        return Settings(secret_key="test-secret-key-32-chars-minimum-value", debug=True, mock_auth_enabled=True)

    app.dependency_overrides[get_settings] = override_settings_enabled
    try:
        response = await client.post(f"/api/v1/users/mock-login/{test_user.id}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["user"]["id"] == test_user.id
        assert payload["user"]["email"] == test_user.email
    finally:
        app.dependency_overrides.pop(get_settings, None)


@pytest.mark.asyncio
async def test_lookup_paging_determinism(auth_client: AsyncClient, db_session: AsyncSession, test_role):
    """Test that user lookup paging is deterministic (no overlap between pages)."""
    from app.models import Department

    # Create a department for test users
    dept = Department(name="Paging Test Dept", code="PAGE-TEST")
    db_session.add(dept)
    await db_session.commit()
    await db_session.refresh(dept)

    # Create 5 users
    users = []
    for i in range(5):
        u = User(
            name=f"Paging User {i}",
            email=f"paging-user-{i}@example.com",
            role_id=test_role.id,
            department_id=dept.id,
            is_active=True,
        )
        db_session.add(u)
        users.append(u)
    await db_session.commit()

    # Request page 1 (limit=2, skip=0)
    resp1 = await auth_client.get("/api/v1/users/lookup?limit=2&skip=0")
    assert resp1.status_code == 200
    ids1 = {u["id"] for u in resp1.json()}

    # Request page 2 (limit=2, skip=2)
    resp2 = await auth_client.get("/api/v1/users/lookup?limit=2&skip=2")
    assert resp2.status_code == 200
    ids2 = {u["id"] for u in resp2.json()}

    # No overlap between pages
    assert ids1.isdisjoint(ids2), "Paging should be deterministic with no overlap"


@pytest.mark.asyncio
async def test_lookup_users_by_ids_resolves_beyond_default_page(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_role,
):
    """Exact-ID lookup must not be limited to the first default lookup page."""
    from app.models import Department

    dept = Department(name="Exact Lookup Dept", code="EXACT-LOOKUP")
    db_session.add(dept)
    await db_session.commit()
    await db_session.refresh(dept)

    users = []
    for i in range(55):
        user = User(
            name=f"Exact Lookup User {i:02d}",
            email=f"exact-lookup-user-{i:02d}@example.com",
            role_id=test_role.id,
            department_id=dept.id,
            is_active=True,
        )
        db_session.add(user)
        users.append(user)
    await db_session.commit()
    target = users[-1]
    await db_session.refresh(target)

    response = await auth_client.get(f"/api/v1/users/lookup?ids={target.id}")

    assert response.status_code == 200
    assert [user["id"] for user in response.json()] == [target.id]


@pytest.mark.asyncio
async def test_lookup_users_by_ids_can_include_inactive_historical_actor(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_role,
):
    """Audit actor resolution can explicitly include inactive historical users."""
    from app.models import Department

    dept = Department(name="Inactive Lookup Dept", code="INACTIVE-LOOKUP")
    db_session.add(dept)
    await db_session.commit()
    await db_session.refresh(dept)

    inactive_user = User(
        name="Inactive Audit Actor",
        email="inactive-audit-actor@example.com",
        role_id=test_role.id,
        department_id=dept.id,
        is_active=False,
    )
    db_session.add(inactive_user)
    await db_session.commit()
    await db_session.refresh(inactive_user)

    hidden_response = await auth_client.get(f"/api/v1/users/lookup?ids={inactive_user.id}")
    visible_response = await auth_client.get(
        f"/api/v1/users/lookup?ids={inactive_user.id}&include_inactive=true"
    )

    assert hidden_response.status_code == 200
    assert hidden_response.json() == []
    assert visible_response.status_code == 200
    assert [user["id"] for user in visible_response.json()] == [inactive_user.id]


@pytest.mark.asyncio
async def test_lookup_users_by_ids_rejects_oversized_id_lists(auth_client: AsyncClient):
    query = "&".join(f"ids={i}" for i in range(1, 202))

    response = await auth_client.get(f"/api/v1/users/lookup?{query}")

    assert response.status_code == 400
    assert response.json()["detail"] == "Too many user ids requested"


@pytest.mark.asyncio
async def test_lookup_department_scoping(
    client: AsyncClient,
    db_session: AsyncSession,
    users_read_employee_role: Role,
):
    """Test that department-scoped users cannot see users from other departments."""
    from app.models import Department
    from app.models.user import AccessScope

    # Create two departments
    dept_a = Department(name="Scope Dept A", code="SCOPE-A")
    dept_b = Department(name="Scope Dept B", code="SCOPE-B")
    db_session.add_all([dept_a, dept_b])
    await db_session.commit()
    await db_session.refresh(dept_a)
    await db_session.refresh(dept_b)

    # Create user in dept A with DEPARTMENT scope
    user_a = User(
        name="Scope User A",
        email="scope-user-a@example.com",
        role_id=users_read_employee_role.id,
        department_id=dept_a.id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    db_session.add(user_a)
    await db_session.commit()
    await db_session.refresh(user_a)

    # Request lookup with dept B filter → should return empty
    response = await client.get(
        f"/api/v1/users/lookup?department_id={dept_b.id}",
        headers={"X-Mock-User-Id": str(user_a.id)},
    )
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_lookup_manager_department_filter_narrows_to_own_department(
    client: AsyncClient,
    db_session: AsyncSession,
    users_read_employee_role: Role,
):
    """Managers can optionally narrow lookup to their own department only."""
    from app.models import Department
    from app.models.user import AccessScope

    dept_a = Department(name="Manager Scope Dept A", code="MGR-SCOPE-A")
    dept_b = Department(name="Manager Scope Dept B", code="MGR-SCOPE-B")
    db_session.add_all([dept_a, dept_b])
    await db_session.commit()
    await db_session.refresh(dept_a)
    await db_session.refresh(dept_b)

    manager = User(
        name="Manager Scope User",
        email="manager-scope@example.com",
        role_id=users_read_employee_role.id,
        department_id=dept_a.id,
        access_scope=AccessScope.MANAGER,
        is_active=True,
    )
    db_session.add(manager)
    await db_session.commit()
    await db_session.refresh(manager)

    same_dept_report = User(
        name="Manager Same Dept Report",
        email="manager-scope-same-dept@example.com",
        role_id=users_read_employee_role.id,
        department_id=dept_a.id,
        manager_id=manager.id,
        is_active=True,
    )
    cross_dept_report = User(
        name="Manager Cross Dept Report",
        email="manager-scope-cross-dept@example.com",
        role_id=users_read_employee_role.id,
        department_id=dept_b.id,
        manager_id=manager.id,
        is_active=True,
    )
    unrelated_user = User(
        name="Manager Unrelated User",
        email="manager-scope-unrelated@example.com",
        role_id=users_read_employee_role.id,
        department_id=dept_a.id,
        is_active=True,
    )
    db_session.add_all([same_dept_report, cross_dept_report, unrelated_user])
    await db_session.commit()
    await db_session.refresh(same_dept_report)
    await db_session.refresh(cross_dept_report)
    await db_session.refresh(unrelated_user)

    headers = {"X-Mock-User-Id": str(manager.id)}

    # No department filter: manager sees self + direct reports (cross-dept report included).
    response = await client.get("/api/v1/users/lookup", headers=headers)
    assert response.status_code == 200
    visible_ids = {u["id"] for u in response.json()}
    assert manager.id in visible_ids
    assert same_dept_report.id in visible_ids
    assert cross_dept_report.id in visible_ids
    assert unrelated_user.id not in visible_ids

    # Own-department filter narrows manager scope to own department only.
    response = await client.get(f"/api/v1/users/lookup?department_id={dept_a.id}", headers=headers)
    assert response.status_code == 200
    own_dept_ids = {u["id"] for u in response.json()}
    assert manager.id in own_dept_ids
    assert same_dept_report.id in own_dept_ids
    assert cross_dept_report.id not in own_dept_ids

    # Other department filter remains fail-closed.
    response = await client.get(f"/api/v1/users/lookup?department_id={dept_b.id}", headers=headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_lookup_limit_enforcement(auth_client: AsyncClient):
    """Test that lookup limit is capped at MAX_LOOKUP_SIZE (200) via Query validation."""
    # Request with limit above max → FastAPI Query rejects with 422
    response = await auth_client.get("/api/v1/users/lookup?limit=9999")
    assert response.status_code == 422  # Validation error

    # Request at max limit → should succeed
    response = await auth_client.get("/api/v1/users/lookup?limit=200")
    assert response.status_code == 200
    assert len(response.json()) <= 200
