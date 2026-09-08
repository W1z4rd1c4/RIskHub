import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import Settings
from app.models import Department, Role, User
from app.models.user import AccessScope
from app.services.ad_deprovision_service import ADDeprovisionService


@pytest_asyncio.fixture
async def client_cro_sso(client_factory, test_user_cro: User):
    settings = Settings(mock_auth_enabled=True, debug=True, auth_mode="microsoft_sso")
    async with client_factory(user=test_user_cro, settings=settings) as ac:
        yield ac


@pytest.mark.asyncio
async def test_access_users_requires_privileged(client_employee: AsyncClient):
    response = await client_employee.get("/api/v1/access/users")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_access_users_list_privileged(client_risk_manager: AsyncClient):
    response = await client_risk_manager.get("/api/v1/access/users")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_access_users_list_hides_admins_from_cro(
    client_cro: AsyncClient,
    test_user_platform_admin: User,
):
    response = await client_cro.get("/api/v1/access/users")

    assert response.status_code == 200
    data = response.json()
    assert test_user_platform_admin.id not in {item["id"] for item in data}
    assert all(item["role"]["name"] != "admin" for item in data)


@pytest.mark.asyncio
async def test_department_access_users_list_hides_admins_from_non_admin(
    client_cro: AsyncClient,
    test_user_platform_admin: User,
):
    response = await client_cro.get("/api/v1/access/users/my-department")

    assert response.status_code == 200
    data = response.json()
    assert test_user_platform_admin.id not in {item["id"] for item in data}
    assert all(item["role"]["name"] != "admin" for item in data)


@pytest.mark.asyncio
async def test_department_access_roster_target_scope(
    db_session,
    client_cro: AsyncClient,
    client_department_head: AsyncClient,
    test_role_department_head: Role,
):
    other_department = Department(name="Roster Target", code="RST", description="Roster target")
    db_session.add(other_department)
    await db_session.flush()
    other_user = User(
        name="Roster User",
        email="roster.user@example.com",
        hashed_password="x",
        role_id=test_role_department_head.id,
        department_id=other_department.id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    db_session.add(other_user)
    await db_session.commit()

    privileged = await client_cro.get(
        f"/api/v1/access/users/my-department?department_id={other_department.id}"
    )
    assert privileged.status_code == 200
    assert {row["id"] for row in privileged.json()} == {other_user.id}

    denied = await client_department_head.get(
        f"/api/v1/access/users/my-department?department_id={other_department.id}"
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_access_users_list_shows_admins_to_admin(
    client_platform_admin: AsyncClient,
    test_user_platform_admin: User,
):
    response = await client_platform_admin.get("/api/v1/access/users")

    assert response.status_code == 200
    data = response.json()
    admin_rows = [item for item in data if item["id"] == test_user_platform_admin.id]
    assert admin_rows
    assert admin_rows[0]["role"]["name"] == "admin"


@pytest.mark.asyncio
async def test_access_users_include_backend_capabilities(
    auth_client: AsyncClient,
    test_user_employee: User,
):
    response = await auth_client.get("/api/v1/access/users")

    assert response.status_code == 200
    data = response.json()
    target = next(item for item in data if item["id"] == test_user_employee.id)
    assert target["capabilities"]["can_edit_identity"] is True
    assert target["capabilities"]["can_edit_business_access"] is False
    assert target["capabilities"]["can_edit_role"] is True
    assert target["capabilities"]["can_change_active_status"] is True
    assert target["capabilities"]["can_deactivate"] is True
    assert target["capabilities"]["can_break_glass_enable"] is False


@pytest.mark.asyncio
async def test_access_users_do_not_advertise_lifecycle_capability_to_cro(
    client_cro: AsyncClient,
    test_user_employee: User,
):
    response = await client_cro.get("/api/v1/access/users")

    assert response.status_code == 200
    target = next(item for item in response.json() if item["id"] == test_user_employee.id)
    assert target["capabilities"]["can_change_active_status"] is False
    assert target["capabilities"]["can_deactivate"] is False
    assert target["capabilities"]["can_break_glass_enable"] is False


@pytest.mark.asyncio
async def test_access_users_include_break_glass_capability_for_directory_deprovisioned_user(
    auth_client: AsyncClient,
    db_session,
    test_user_employee: User,
):
    test_user_employee.external_id = "oid-break-glass-capability"
    test_user_employee.is_active = False
    test_user_employee.deprovision_reason = ADDeprovisionService.DEPROVISION_REASON_DIRECTORY_DISABLED
    db_session.add(test_user_employee)
    await db_session.commit()

    response = await auth_client.get("/api/v1/access/users")

    assert response.status_code == 200
    target = next(item for item in response.json() if item["id"] == test_user_employee.id)
    # Ordinary resumption remains denied; the separately bounded override is available.
    assert target["capabilities"]["can_change_active_status"] is False
    assert target["capabilities"]["can_resume"] is False
    assert target["capabilities"]["can_break_glass_enable"] is True


@pytest.mark.asyncio
async def test_access_roles_hides_admin_role_from_cro(
    client_cro: AsyncClient,
    test_role_platform_admin,
):
    response = await client_cro.get("/api/v1/access/roles")

    assert response.status_code == 200
    data = response.json()
    assert all(item["name"] != "admin" for item in data)


@pytest.mark.asyncio
async def test_access_roles_shows_admin_role_to_admin(
    client_platform_admin: AsyncClient,
):
    response = await client_platform_admin.get("/api/v1/access/roles")

    assert response.status_code == 200
    data = response.json()
    assert any(item["name"] == "admin" for item in data)


@pytest.mark.asyncio
async def test_access_update_allows_admin(auth_client: AsyncClient, test_user_employee: User, test_role):
    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"role_id": test_role.id},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"]["name"] == "admin"


@pytest.mark.asyncio
async def test_access_users_list_includes_entra_business_role(
    auth_client: AsyncClient,
    db_session,
    test_user_employee: User,
):
    test_user_employee.entra_business_role = "Claims Manager"
    db_session.add(test_user_employee)
    await db_session.commit()

    response = await auth_client.get("/api/v1/access/users")

    assert response.status_code == 200
    payload = response.json()
    target = next(item for item in payload if item["id"] == test_user_employee.id)
    assert target["entra_business_role"] == "Claims Manager"


@pytest.mark.asyncio
async def test_access_update_rejects_non_cro_scope_change(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
):
    response = await client_risk_manager.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"access_scope": "global"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_access_update_rejects_non_cro_department_change(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
):
    response = await client_risk_manager.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": None},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_access_update_rejects_non_cro_manager_change(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
    test_user: User,
):
    response = await client_risk_manager.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"manager_id": test_user.id},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_access_update_rejects_non_cro_mixed_mutation_payload(
    client_risk_manager: AsyncClient,
    test_user_employee: User,
    test_user: User,
):
    response = await client_risk_manager.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": None, "manager_id": test_user.id},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_access_update_rejects_admin_manager_change(
    auth_client: AsyncClient,
    test_user_employee: User,
    test_user: User,
):
    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"manager_id": test_user.id},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Only CRO can update user business access fields"


@pytest.mark.asyncio
async def test_access_update_rejects_manager_cycle(
    client_cro: AsyncClient,
    db_session,
    test_user_employee: User,
):
    manager = User(
        email="cycle-manager@example.com",
        hashed_password="hash",
        name="Cycle Manager",
        role_id=test_user_employee.role_id,
        department_id=test_user_employee.department_id,
        is_active=True,
    )
    db_session.add(manager)
    await db_session.flush()
    test_user_employee.manager_id = manager.id
    db_session.add(test_user_employee)
    await db_session.commit()
    await db_session.refresh(manager)

    response = await client_cro.patch(
        f"/api/v1/access/users/{manager.id}",
        json={"manager_id": test_user_employee.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "User manager hierarchy cannot contain a cycle"


@pytest.mark.asyncio
async def test_access_update_rejects_department_change_when_user_manages_current_department(
    client_cro: AsyncClient,
    db_session,
    test_user_employee: User,
):
    source_dept = Department(name="Access Managed Source", code="ACCESS_SRC", is_active=True)
    target_dept = Department(name="Access Transfer Target", code="ACCESS_TGT", is_active=True)
    db_session.add_all([source_dept, target_dept])
    await db_session.flush()
    test_user_employee.department_id = source_dept.id
    source_dept.manager_id = test_user_employee.id
    await db_session.commit()
    await db_session.refresh(target_dept)

    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": target_dept.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Clear the department manager before moving this user"


@pytest.mark.asyncio
async def test_access_prevents_self_scope_demotion(client_cro: AsyncClient, test_user_cro: User):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_cro.id}",
        json={"access_scope": "department"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_access_update_allows_admin_identity_only(
    auth_client: AsyncClient,
    test_user_employee: User,
):
    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={
            "name": "Updated Employee",
            "email": "updated.employee@example.com",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Employee"
    assert data["email"] == "updated.employee@example.com"


@pytest.mark.asyncio
async def test_access_update_allows_admin_combined_identity_and_access(
    auth_client: AsyncClient,
    test_user_employee: User,
    test_role,
):
    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={
            "name": "Combined Update",
            "email": "combined.update@example.com",
            "role_id": test_role.id,
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Combined Update"
    assert data["email"] == "combined.update@example.com"
    assert data["role"]["name"] == "admin"


@pytest.mark.asyncio
async def test_access_update_ignores_entra_business_role_payload(
    client_cro: AsyncClient,
    db_session,
    test_user_employee: User,
):
    test_user_employee.entra_business_role = "Claims Manager"
    db_session.add(test_user_employee)
    await db_session.commit()

    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": None, "entra_business_role": "Tampered Role"},
    )

    assert response.status_code == 200
    assert response.json()["department_id"] is None
    assert response.json()["entra_business_role"] == "Claims Manager"

    await db_session.refresh(test_user_employee)
    assert test_user_employee.entra_business_role == "Claims Manager"


@pytest.mark.asyncio
async def test_access_update_rejects_cro_identity_mutation(
    client_cro: AsyncClient,
    test_user_employee: User,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"email": "cro.identity@example.com"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can update user identity fields"


@pytest.mark.asyncio
async def test_access_update_allows_cro_access_only_mutation(
    client_cro: AsyncClient,
    test_user_employee: User,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"access_scope": "manager"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["access_scope"] == "manager"


@pytest.mark.asyncio
async def test_access_update_allows_cro_business_access_mutation(
    client_cro: AsyncClient,
    test_user_employee: User,
    test_user: User,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": None, "manager_id": test_user.id, "access_scope": "manager"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["department_id"] is None
    assert data["manager_id"] == test_user.id
    assert data["access_scope"] == "manager"


@pytest.mark.asyncio
async def test_access_update_allows_cro_sso_department_override(
    client_cro_sso: AsyncClient,
    db_session,
    test_user_employee: User,
):
    test_user_employee.external_id = "entra-user-123"
    db_session.add(test_user_employee)
    await db_session.commit()

    response = await client_cro_sso.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"department_id": None},
    )

    assert response.status_code == 200
    assert response.json()["department_id"] is None


@pytest.mark.asyncio
async def test_access_update_rejects_cro_admin_role_assignment(
    client_cro: AsyncClient,
    test_user_employee: User,
    test_role,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"role_id": test_role.id},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only Admin can assign the Admin role"


@pytest.mark.asyncio
async def test_access_update_conceals_admin_target_from_cro(
    client_cro: AsyncClient,
    db_session,
    test_user_platform_admin: User,
    test_role_department_head,
):
    original_role_id = test_user_platform_admin.role_id

    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_platform_admin.id}",
        json={"role_id": test_role_department_head.id},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"

    await db_session.refresh(test_user_platform_admin)
    assert test_user_platform_admin.role_id == original_role_id


@pytest.mark.asyncio
async def test_access_update_rejects_admin_business_role_assignment(
    auth_client: AsyncClient,
    test_user_employee: User,
    test_role_department_head,
):
    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"role_id": test_role_department_head.id},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only CRO can assign business roles"


@pytest.mark.asyncio
async def test_access_update_allows_cro_business_role_assignment(
    client_cro: AsyncClient,
    test_user_employee: User,
    test_role_department_head,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"role_id": test_role_department_head.id},
    )

    assert response.status_code == 200
    assert response.json()["role"]["name"] == "department_head"


@pytest.mark.asyncio
async def test_access_update_rejects_inactive_role_assignment(
    client_cro: AsyncClient,
    db_session,
    test_user_employee: User,
):
    inactive_role = Role(
        name="inactive_access_role",
        display_name="Inactive Access Role",
        description="Inactive role must not be assignable through access management",
        is_active=False,
    )
    db_session.add(inactive_role)
    await db_session.commit()
    await db_session.refresh(inactive_role)

    original_role_id = test_user_employee.role_id
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"role_id": inactive_role.id},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid role_id"
    await db_session.refresh(test_user_employee)
    assert test_user_employee.role_id == original_role_id


@pytest.mark.asyncio
async def test_access_update_allows_privileged_role_demotion_when_another_privileged_user_remains(
    client_cro: AsyncClient,
    db_session,
    test_department,
    test_role_cro,
    test_role_department_head,
):
    target_cro = User(
        email="second.cro@example.com",
        hashed_password="hash",
        name="Second CRO",
        role_id=test_role_cro.id,
        department_id=test_department.id,
        access_scope=AccessScope.GLOBAL,
        is_active=True,
    )
    db_session.add(target_cro)
    await db_session.commit()

    response = await client_cro.patch(
        f"/api/v1/access/users/{target_cro.id}",
        json={"role_id": test_role_department_head.id},
    )

    assert response.status_code == 200
    assert response.json()["role"]["name"] == "department_head"

    await db_session.refresh(target_cro)
    assert target_cro.role_id == test_role_department_head.id


@pytest.mark.asyncio
async def test_access_update_allows_privileged_scope_downgrade_when_another_privileged_user_remains(
    client_cro: AsyncClient,
    db_session,
    test_department,
    test_role_cro,
):
    target_cro = User(
        email="scoped.cro@example.com",
        hashed_password="hash",
        name="Scoped CRO",
        role_id=test_role_cro.id,
        department_id=test_department.id,
        access_scope=AccessScope.GLOBAL,
        is_active=True,
    )
    db_session.add(target_cro)
    await db_session.commit()

    response = await client_cro.patch(
        f"/api/v1/access/users/{target_cro.id}",
        json={"access_scope": "department"},
    )

    assert response.status_code == 200
    assert response.json()["access_scope"] == "department"

    await db_session.refresh(target_cro)
    assert target_cro.access_scope == AccessScope.DEPARTMENT


@pytest.mark.asyncio
async def test_access_update_rejects_admin_mixed_identity_and_business_payload(
    auth_client: AsyncClient,
    db_session,
    test_user_employee: User,
):
    original_name = test_user_employee.name
    original_department_id = test_user_employee.department_id

    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={"name": "Should Not Persist", "department_id": None},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Only CRO can update user business access fields"

    await db_session.refresh(test_user_employee)
    assert test_user_employee.name == original_name
    assert test_user_employee.department_id == original_department_id


@pytest.mark.asyncio
async def test_access_update_duplicate_email_rolls_back_access_changes(
    auth_client: AsyncClient,
    db_session,
    test_user_employee: User,
    test_role,
):
    conflict_user = User(
        email="conflict@example.com",
        hashed_password="hash",
        name="Conflict User",
        role_id=test_user_employee.role_id,
        department_id=test_user_employee.department_id,
        is_active=True,
    )
    db_session.add(conflict_user)
    await db_session.commit()

    original_role_id = test_user_employee.role_id
    original_name = test_user_employee.name
    original_email = test_user_employee.email

    response = await auth_client.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={
            "name": "Should Roll Back",
            "email": "Conflict@Example.com",
            "role_id": test_role.id,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"

    await db_session.refresh(test_user_employee)
    assert test_user_employee.role_id == original_role_id
    assert test_user_employee.name == original_name
    assert test_user_employee.email == original_email


@pytest.mark.asyncio
async def test_access_update_logs_combined_user_changes(
    client_cro: AsyncClient,
    db_session,
    test_user_employee: User,
    test_user: User,
):
    response = await client_cro.patch(
        f"/api/v1/access/users/{test_user_employee.id}",
        json={
            "department_id": None,
            "manager_id": test_user.id,
        },
    )

    assert response.status_code == 200

    from app.models.activity_log import ActivityAction, ActivityEntityType, ActivityLog

    result = await db_session.execute(
        select(ActivityLog).where(
            ActivityLog.entity_type == ActivityEntityType.USER.value,
            ActivityLog.entity_id == test_user_employee.id,
            ActivityLog.action == ActivityAction.UPDATE.value,
        )
    )
    entry = result.scalars().first()
    assert entry is not None
    assert entry.changes["department_id"]["new"] is None
    assert entry.changes["manager_id"]["new"] == "[REDACTED]"
