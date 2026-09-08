from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.activity_logger import log_activity
from app.core.config import Settings
from app.core.datetime_utils import utc_now
from app.core.exceptions import ConflictError
from app.core.security import check_permission
from app.db.rbac_seed_contract import RBAC_ROLE_PERMISSIONS, expand_permission_keys
from app.models import (
    ApprovalActionType,
    ApprovalRequest,
    ApprovalResourceType,
    ApprovalScenario,
    ApprovalStatus,
    Control,
    Department,
    GovernedMutationImpactLock,
    GovernedMutationProposal,
    OrphanedItem,
    Permission,
    Risk,
    Role,
    RolePermission,
    Threat,
    User,
)
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.models.user import AccessScope
from app.services._orphaned_items import flag_orphaned_items, resolve_orphan

EXPECTED_CISO_PERMISSIONS = {
    "threats:read",
    "threats:write",
    "threats:delete",
    "risks:read",
    "controls:read",
    "issues:read",
    "processes:read",
    "assets:read",
    "vendors:read",
    "vendor_contracts:read",
    "departments:read",
    "reports:read",
    "ict_committee:read",
    "activity_log:read",
}


@pytest_asyncio.fixture
async def ciso_user(db_session: AsyncSession, test_department) -> User:
    role = Role(name="ciso", display_name="Chief Information Security Officer")
    db_session.add(role)
    await db_session.flush()
    permissions = []
    for key in sorted(EXPECTED_CISO_PERMISSIONS):
        resource, action = key.split(":", maxsplit=1)
        permission = Permission(resource=resource, action=action, description=key)
        db_session.add(permission)
        permissions.append(permission)
    await db_session.flush()
    db_session.add_all(
        RolePermission(role_id=role.id, permission_id=p.id) for p in permissions
    )
    user = User(
        name="Clara Security",
        email="ciso@test.local",
        role_id=role.id,
        department_id=test_department.id,
        access_scope=AccessScope.GLOBAL,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role)
            .selectinload(Role.permissions)
            .selectinload(RolePermission.permission)
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


def test_ciso_seed_contract_is_exactly_least_privilege() -> None:
    assert (
        expand_permission_keys(RBAC_ROLE_PERMISSIONS["ciso"])
        == EXPECTED_CISO_PERMISSIONS
    )
    assert "approvals:write" not in EXPECTED_CISO_PERMISSIONS
    assert "users:read" not in EXPECTED_CISO_PERMISSIONS
    assert "users:write" not in EXPECTED_CISO_PERMISSIONS
    assert not any(
        key.endswith(":write") and not key.startswith("threats:")
        for key in EXPECTED_CISO_PERMISSIONS
    )


@pytest.mark.asyncio
async def test_ciso_role_contract_cannot_be_edited_or_deleted(
    client_cro,
    db_session: AsyncSession,
) -> None:
    role = Role(
        name="ciso",
        display_name="Chief Information Security Officer",
        is_system=False,
        is_active=True,
    )
    db_session.add(role)
    await db_session.commit()

    update = await client_cro.patch(
        f"/api/v1/riskhub/roles/{role.id}",
        json={"permission_ids": []},
    )
    delete = await client_cro.delete(f"/api/v1/riskhub/roles/{role.id}")
    listed = await client_cro.get("/api/v1/riskhub/roles")

    assert update.status_code == 400
    assert "core system role" in update.json()["detail"]
    assert delete.status_code == 400
    assert "protected system role" in delete.json()["detail"]
    listed_role = next(item for item in listed.json() if item["id"] == role.id)
    assert listed_role["capabilities"]["can_update"] is False
    assert listed_role["capabilities"]["can_delete"] is False


@pytest.mark.asyncio
async def test_user_lookup_can_filter_server_side_to_active_ciso_stewards(
    client_factory,
    test_department,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    async with client_factory(user=test_user_cro) as client:
        response = await client.get("/api/v1/users/lookup?role_name=ciso")

    assert response.status_code == 200, response.text
    assert response.json() == [
        {
            "id": ciso_user.id,
            "name": ciso_user.name,
            "email": ciso_user.email,
            "role_name": "ciso",
            "department_id": ciso_user.department_id,
            "department_name": test_department.name,
            "manager_id": None,
        }
    ]


@pytest.mark.asyncio
async def test_generic_user_lookup_requires_users_read_even_when_role_filter_changes(
    client_factory,
    ciso_user: User,
) -> None:
    async with client_factory(user=ciso_user) as client:
        responses = [
            await client.get("/api/v1/users/lookup"),
            await client.get("/api/v1/users/lookup?role_name=ciso"),
            await client.get("/api/v1/users/lookup?role_name=employee"),
        ]

    assert [response.status_code for response in responses] == [403, 403, 403]


@pytest.mark.asyncio
async def test_ciso_uses_minimal_activity_actor_lookup_without_user_directory_access(
    client_factory,
    db_session: AsyncSession,
    ciso_user: User,
    test_user_employee: User,
) -> None:
    await log_activity(
        db_session,
        entity_type=ActivityEntityType.THREAT,
        entity_id=73,
        entity_name="T-073",
        action=ActivityAction.UPDATE,
        actor=ciso_user,
        department_id=ciso_user.department_id,
        changes=None,
        description="Updated Threat",
    )
    await db_session.commit()

    async with client_factory(user=ciso_user) as client:
        actors = await client.get("/api/v1/activity-log/actors")
        generic_users = await client.get("/api/v1/users/lookup")

    assert actors.status_code == 200, actors.text
    assert actors.json() == [{"id": ciso_user.id, "name": ciso_user.name}]
    assert all(actor["id"] != test_user_employee.id for actor in actors.json())
    assert generic_users.status_code == 403


@pytest.mark.asyncio
async def test_threat_steward_lookup_is_minimal_active_ciso_and_cross_department(
    client_factory,
    db_session: AsyncSession,
    ciso_user: User,
) -> None:
    remote_department = Department(name="Remote Security", code="REMOTE-SEC")
    db_session.add(remote_department)
    await db_session.flush()
    remote_ciso = User(
        name="Remote CISO",
        email="remote-ciso@test.local",
        role_id=ciso_user.role_id,
        department_id=remote_department.id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    inactive_remote_ciso = User(
        name="Remote Inactive CISO",
        email="remote-inactive-ciso@test.local",
        role_id=ciso_user.role_id,
        department_id=remote_department.id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=False,
    )
    db_session.add_all([remote_ciso, inactive_remote_ciso])
    ciso_user.access_scope = AccessScope.DEPARTMENT
    await db_session.commit()

    async with client_factory(user=ciso_user) as client:
        response = await client.get("/api/v1/users/lookup/threat-stewards?q=Remote")

    assert response.status_code == 200, response.text
    assert response.json() == [
        {
            "id": remote_ciso.id,
            "name": "Remote CISO",
            "email": "remote-ciso@test.local",
        }
    ]


@pytest.mark.asyncio
async def test_threat_steward_lookup_rejects_callers_without_threat_write(
    client_factory,
    test_user_employee: User,
) -> None:
    async with client_factory(user=test_user_employee) as client:
        response = await client.get("/api/v1/users/lookup/threat-stewards")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_threat_creation_requires_active_ciso_steward(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_employee: User,
    ciso_user: User,
) -> None:
    async with client_factory(user=test_user_cro) as client:
        missing = await client.post("/api/v1/threats", json={"name": "Missing steward"})
        employee = await client.post(
            "/api/v1/threats",
            json={
                "name": "Wrong steward",
                "threat_steward_user_id": test_user_employee.id,
            },
        )

        ciso_user.is_active = False
        await db_session.commit()
        inactive = await client.post(
            "/api/v1/threats",
            json={"name": "Inactive steward", "threat_steward_user_id": ciso_user.id},
        )
        ciso_user.is_active = True
        await db_session.commit()
        created = await client.post(
            "/api/v1/threats",
            json={"name": "Governed threat", "threat_steward_user_id": ciso_user.id},
        )

    assert missing.status_code == 422
    assert employee.status_code == 400
    assert inactive.status_code == 400
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["threat_steward_user_id"] == ciso_user.id
    assert body["threat_steward"]["name"] == "Clara Security"
    assert body["threat_steward"]["email"] == "ciso@test.local"
    assert body["threat_steward"]["role_name"] == "ciso"
    assert "id" not in body["threat_steward"]


@pytest.mark.asyncio
async def test_inactive_ciso_role_is_hidden_and_rejected_for_threat_assignment(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    threat = Threat(name="Existing steward assignment", threat_steward_user_id=ciso_user.id)
    db_session.add(threat)
    await db_session.commit()

    ciso_user.role.is_active = False
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        picker = await client.get("/api/v1/users/lookup/threat-stewards")
        created = await client.post(
            "/api/v1/threats",
            json={"name": "Hidden role assignment", "threat_steward_user_id": ciso_user.id},
        )
        reassigned = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"threat_steward_user_id": ciso_user.id},
        )

    assert picker.status_code == 200, picker.text
    assert picker.json() == []
    assert created.status_code == 400
    assert created.json()["detail"] == "Threat steward must be an active CISO"
    assert reassigned.status_code == 200
    assert reassigned.json()["threat_steward_user_id"] == ciso_user.id


@pytest.mark.asyncio
async def test_ciso_has_threat_lifecycle_but_no_approval_or_platform_authority(
    client_factory,
    db_session: AsyncSession,
    seed_risk_types,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    async with client_factory(user=test_user_cro) as cro_client:
        risk = await cro_client.post(
            "/api/v1/risks",
            json={
                "name": "CISO link target",
                "process": "Security operations",
                "description": "Risk visible to the Threat Steward.",
            },
        )
    assert risk.status_code == 201, risk.text

    approval = ApprovalRequest(
        resource_type=ApprovalResourceType.RISK,
        resource_id=risk.json()["id"],
        resource_name=risk.json()["name"],
        action_type=ApprovalActionType.EDIT,
        requested_by_id=test_user_cro.id,
        reason="CISO must not resolve approval work",
        status=ApprovalStatus.PENDING,
        scenario_key="risk_edit_priority",
        scenario_approver_roles=["risk_manager", "cro"],
    )
    db_session.add(approval)
    await db_session.commit()

    async with client_factory(user=ciso_user) as client:
        capabilities = await client.get("/api/v1/auth/me/capabilities")
        assert capabilities.status_code == 200, capabilities.text
        capability_body = capabilities.json()
        assert capability_body["resource_permissions"]["threats:read"] is True
        assert capability_body["resource_permissions"]["users:read"] is False
        assert capability_body["resource_permissions"]["users:write"] is False
        assert capability_body["can_view_user_directory"] is False
        assert capability_body["can_view_access_users"] is False
        assert capability_body["can_view_users_route"] is False
        assert capability_body["can_manage_access"] is False
        assert capability_body["can_view_approvals"] is True

        me = await client.get("/api/v1/auth/me")
        assert me.status_code == 200, me.text
        assert me.json()["me_capabilities"]["can_view_approvals"] is True

        created = await client.post(
            "/api/v1/threats",
            json={"name": "CISO-owned threat", "threat_steward_user_id": ciso_user.id},
        )
        assert created.status_code == 201, created.text
        threat_id = created.json()["id"]
        assert created.json()["capabilities"] == {
            "can_read": True,
            "can_update": True,
            "can_archive": True,
            "can_restore": False,
            "has_pending_change": False,
            "business_edit_blocked": False,
            "can_cancel_pending_change": False,
        }
        assert (
            await client.patch(
                f"/api/v1/threats/{threat_id}", json={"notes": "reviewed"}
            )
        ).status_code == 200
        linked = await client.post(
            f"/api/v1/threats/{threat_id}/risk-links",
            json={"risk_id": risk.json()["id"]},
        )
        assert linked.status_code == 201, linked.text
        assert linked.json()["capabilities"]["can_delete"] is True
        assert (
            await client.delete(
                f"/api/v1/threats/{threat_id}/risk-links/{linked.json()['id']}"
            )
        ).status_code == 204
        assert (await client.delete(f"/api/v1/threats/{threat_id}")).status_code == 204
        assert (
            await client.post(f"/api/v1/threats/{threat_id}/restore")
        ).status_code == 200
        assert not check_permission(ciso_user, "approvals", "write")
        assert (
            await client.post(
                f"/api/v1/approvals/{approval.id}/approve",
                json={"resolution_notes": "CISO must not approve"},
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/api/v1/approvals/{approval.id}/reject",
                json={"resolution_notes": "CISO must not reject"},
            )
        ).status_code == 403
        assert (await client.get("/api/v1/users")).status_code == 403
        assert (await client.get("/api/v1/access/users")).status_code == 403
        assert (await client.get("/api/v1/access/roles")).status_code == 403
        assert (
            await client.get("/api/v1/access/users/my-department")
        ).status_code == 403


@pytest.mark.asyncio
async def test_ciso_deactivation_and_role_loss_flag_stewarded_threats(
    auth_client,
    db_session: AsyncSession,
    test_role_employee: Role,
    ciso_user: User,
) -> None:
    first = Threat(name="Deactivation orphan", threat_steward_user_id=ciso_user.id)
    second = Threat(name="Role-loss orphan", threat_steward_user_id=ciso_user.id)
    db_session.add_all([first, second])
    await db_session.commit()

    deactivated = await auth_client.patch(
        f"/api/v1/users/{ciso_user.id}", json={"is_active": False}
    )
    assert deactivated.status_code == 200, deactivated.text
    ciso_user.is_active = True
    await db_session.commit()
    role_changed = await auth_client.patch(
        f"/api/v1/users/{ciso_user.id}",
        json={"role_id": test_role_employee.id},
    )
    assert role_changed.status_code == 200, role_changed.text

    orphans = (
        (
            await db_session.execute(
                select(OrphanedItem).where(
                    OrphanedItem.item_type == "threat",
                    OrphanedItem.previous_owner_id == ciso_user.id,
                    OrphanedItem.status == "pending",
                )
            )
        )
        .scalars()
        .all()
    )
    assert {(item.item_type, item.item_id) for item in orphans} == {
        ("threat", first.id),
        ("threat", second.id),
    }
    assert first.threat_steward_user_id == ciso_user.id
    assert second.threat_steward_user_id == ciso_user.id


@pytest.mark.asyncio
async def test_access_management_role_loss_flags_stewarded_threats(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_role_employee: Role,
    test_department: Department,
    ciso_user: User,
    monkeypatch,
) -> None:
    import app.services._identity_authority_lock as identity_lock

    lock_calls: list[int] = []
    original_lock = identity_lock.acquire_threat_steward_identity_lock

    async def capture_lock(db: AsyncSession, *, user_id: int) -> None:
        lock_calls.append(user_id)
        await original_lock(db, user_id=user_id)

    monkeypatch.setattr(
        identity_lock,
        "acquire_threat_steward_identity_lock",
        capture_lock,
    )
    threat = Threat(
        name="Access-management role-loss orphan", threat_steward_user_id=ciso_user.id
    )
    risk = Risk(
        risk_id_code="R-CISO-ROLE-LOSS",
        name="Role-loss owned Risk",
        process="Security operations",
        description="Must remain non-orphaned while the owner stays active.",
        category="Operational",
        department_id=test_department.id,
        owner_id=ciso_user.id,
        risk_type="operational",
    )
    control = Control(
        name="Role-loss owned Control",
        description="Must remain non-orphaned while the owner stays active.",
        department_id=test_department.id,
        control_owner_id=ciso_user.id,
        frequency="monthly",
        status="active",
    )
    db_session.add_all([threat, risk, control])
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        response = await client.patch(
            f"/api/v1/access/users/{ciso_user.id}",
            json={"role_id": test_role_employee.id},
        )

    assert response.status_code == 200, response.text
    assert lock_calls == [ciso_user.id]
    orphans = (
        (
            await db_session.execute(
                select(OrphanedItem).where(
                    OrphanedItem.previous_owner_id == ciso_user.id,
                    OrphanedItem.status == "pending",
                )
            )
        )
        .scalars()
        .all()
    )
    await db_session.refresh(threat)
    await db_session.refresh(ciso_user)
    assert {(orphan.item_type, orphan.item_id) for orphan in orphans} == {
        ("threat", threat.id)
    }
    assert ciso_user.is_active is True
    assert threat.threat_steward_user_id == ciso_user.id


@pytest.mark.asyncio
async def test_access_management_deactivation_flags_all_owned_items_under_shared_lock(
    client_factory,
    db_session: AsyncSession,
    test_user_platform_admin: User,
    test_department: Department,
    ciso_user: User,
    monkeypatch,
) -> None:
    import app.services._identity_authority_lock as identity_lock

    lock_calls: list[int] = []
    original_lock = identity_lock.acquire_threat_steward_identity_lock

    async def capture_lock(db: AsyncSession, *, user_id: int) -> None:
        lock_calls.append(user_id)
        await original_lock(db, user_id=user_id)

    monkeypatch.setattr(
        identity_lock,
        "acquire_threat_steward_identity_lock",
        capture_lock,
    )
    threat = Threat(
        name="Access deactivation Threat",
        threat_steward_user_id=ciso_user.id,
    )
    risk = Risk(
        risk_id_code="R-CISO-DEACTIVATE",
        name="Access deactivation Risk",
        process="Security operations",
        description="Must be flagged by full identity deactivation.",
        category="Operational",
        department_id=test_department.id,
        owner_id=ciso_user.id,
        risk_type="operational",
    )
    control = Control(
        name="Access deactivation Control",
        description="Must be flagged by full identity deactivation.",
        department_id=test_department.id,
        control_owner_id=ciso_user.id,
        frequency="monthly",
        status="active",
    )
    db_session.add_all([threat, risk, control])
    await db_session.commit()

    async with client_factory(user=test_user_platform_admin) as client:
        response = await client.patch(
            f"/api/v1/access/users/{ciso_user.id}",
            json={"is_active": False},
        )

    assert response.status_code == 200, response.text
    assert lock_calls == [ciso_user.id]
    orphans = (
        (
            await db_session.execute(
                select(OrphanedItem).where(
                    OrphanedItem.previous_owner_id == ciso_user.id,
                    OrphanedItem.status == "pending",
                )
            )
        )
        .scalars()
        .all()
    )
    await db_session.refresh(ciso_user)
    assert ciso_user.is_active is False
    assert {(orphan.item_type, orphan.item_id) for orphan in orphans} == {
        ("risk", risk.id),
        ("control", control.id),
        ("threat", threat.id),
    }


@pytest.mark.asyncio
async def test_pending_orphan_threat_cannot_bypass_governance_reassignment(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    replacement = User(
        name="Governance Replacement CISO",
        email="governance.replacement.ciso@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    threat = Threat(
        name="Governance-only reassignment",
        threat_steward_user_id=ciso_user.id,
    )
    db_session.add_all([replacement, threat])
    await db_session.commit()
    orphan = (await flag_orphaned_items(db_session, ciso_user.id))[0]
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        response = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"threat_steward_user_id": replacement.id},
        )

    assert response.status_code == 409, response.text
    assert "governance workflow" in response.json()["detail"]
    await db_session.refresh(threat)
    await db_session.refresh(orphan)
    assert threat.threat_steward_user_id == ciso_user.id
    assert orphan.status == "pending"


@pytest.mark.asyncio
async def test_orphaned_threat_requires_explicit_active_ciso_reassignment(
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_employee: User,
    ciso_user: User,
) -> None:
    threat = Threat(name="Explicit reassignment", threat_steward_user_id=ciso_user.id)
    db_session.add(threat)
    await db_session.commit()
    orphan = (await flag_orphaned_items(db_session, ciso_user.id))[0]
    await db_session.commit()
    orphan_id = orphan.id
    ciso_role_id = ciso_user.role_id
    cro_id = test_user_cro.id
    employee_id = test_user_employee.id

    with pytest.raises(ValueError, match="active CISO"):
        await resolve_orphan(
            db_session,
            orphan_id,
            resolved_by_id=cro_id,
            new_owner_id=employee_id,
        )
    await db_session.rollback()

    replacement = User(
        name="Replacement CISO",
        email="replacement.ciso@test.local",
        role_id=ciso_role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    db_session.add(replacement)
    await db_session.commit()
    resolved = await resolve_orphan(
        db_session,
        orphan_id,
        resolved_by_id=cro_id,
        new_owner_id=replacement.id,
    )
    await db_session.refresh(threat)

    assert resolved.status == "resolved"
    assert resolved.new_owner_id == replacement.id
    assert threat.threat_steward_user_id == replacement.id


@pytest.mark.asyncio
async def test_inactive_ciso_role_is_rejected_for_orphan_resolution(
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    threat = Threat(name="Inactive-role orphan", threat_steward_user_id=ciso_user.id)
    db_session.add(threat)
    await db_session.commit()
    orphan = (await flag_orphaned_items(db_session, ciso_user.id))[0]
    await db_session.commit()

    ciso_user.role.is_active = False
    await db_session.commit()

    with pytest.raises(ValueError, match="Threat steward must be an active CISO"):
        await resolve_orphan(
            db_session,
            orphan.id,
            resolved_by_id=test_user_cro.id,
            new_owner_id=ciso_user.id,
        )


@pytest.mark.asyncio
async def test_threat_orphan_resolution_honors_impact_lock_and_governance_version(
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    """Threat orphan repair mirrors the Process/Asset impact-lock safeguards."""
    replacement = User(
        name="Impact-lock replacement CISO",
        email="impact.lock.replacement.ciso@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    threat = Threat(
        name="Impact-locked orphan Threat",
        threat_steward_user_id=ciso_user.id,
    )
    db_session.add_all([replacement, threat])
    await db_session.commit()
    threat_id = threat.id
    initial_governance_version = threat.governance_version
    previous_steward_id = ciso_user.id
    replacement_id = replacement.id
    cro_id = test_user_cro.id
    orphan = (await flag_orphaned_items(db_session, ciso_user.id))[0]
    await db_session.commit()
    orphan_id = orphan.id

    approval = ApprovalRequest(
        resource_type=ApprovalResourceType.THREAT,
        resource_id=threat_id,
        resource_name="Impact-locked orphan Threat",
        action_type=ApprovalActionType.EDIT,
        pending_changes={"threat_steward": {"old": "a", "new": "b"}},
        requested_by_id=cro_id,
        reason="Lock orphan reassignment",
        status=ApprovalStatus.PENDING,
    )
    db_session.add(approval)
    await db_session.flush()
    proposal = GovernedMutationProposal(
        proposal_id=str(uuid4()),
        proposal_version=1,
        schema_version=1,
        approval_request_id=approval.id,
        mutation_kind="threat.edit",
        primary_resource_type="threat",
        primary_resource_id=threat_id,
        primary_resource_name="Impact-locked orphan Threat",
        scenario_snapshot={},
        base_versions={"threat": initial_governance_version},
        before_snapshot={},
        after_snapshot={},
        derived_impact_snapshot={},
        proposed_changes={},
        impacted_resources_snapshot=[],
        requested_by_id=cro_id,
    )
    db_session.add(proposal)
    await db_session.flush()
    impact_lock = GovernedMutationImpactLock(
        proposal_id=proposal.id,
        resource_type="threat",
        resource_id=threat_id,
        base_governance_version=initial_governance_version,
    )
    db_session.add(impact_lock)
    await db_session.commit()
    impact_lock_id = impact_lock.id
    approval_id = approval.id

    with pytest.raises(ConflictError, match="governed Threat change is already pending"):
        await resolve_orphan(
            db_session,
            orphan_id,
            resolved_by_id=cro_id,
            new_owner_id=replacement_id,
        )
    await db_session.rollback()

    threat = await db_session.get(Threat, threat_id)
    assert threat is not None
    assert threat.threat_steward_user_id == previous_steward_id
    assert threat.governance_version == initial_governance_version
    assert (
        await db_session.scalar(
            select(OrphanedItem.status).where(OrphanedItem.id == orphan_id)
        )
        == "pending"
    )

    impact_lock = await db_session.get(GovernedMutationImpactLock, impact_lock_id)
    assert impact_lock is not None
    impact_lock.released_at = utc_now()
    impact_lock.release_reason = "test_continue_orphan_resolution"
    approval = await db_session.get(ApprovalRequest, approval_id)
    assert approval is not None
    approval.status = ApprovalStatus.CANCELLED
    await db_session.commit()

    resolved = await resolve_orphan(
        db_session,
        orphan_id,
        resolved_by_id=cro_id,
        new_owner_id=replacement_id,
    )
    assert resolved.status == "resolved"
    db_session.expire_all()
    threat = await db_session.get(Threat, threat_id)
    assert threat is not None
    assert threat.threat_steward_user_id == replacement_id
    assert threat.governance_version == initial_governance_version + 1


@pytest.mark.asyncio
async def test_threat_orphan_same_steward_repick_is_noop_for_governance_version(
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    """Re-picking the restored previous CISO must not advance governance_version."""
    threat = Threat(
        name="No-op repair Threat",
        threat_steward_user_id=ciso_user.id,
    )
    db_session.add(threat)
    await db_session.commit()
    threat_id = threat.id
    initial_governance_version = threat.governance_version
    previous_steward_id = ciso_user.id
    cro_id = test_user_cro.id

    ciso_user.is_active = False
    await db_session.flush()
    created_orphans = await flag_orphaned_items(db_session, previous_steward_id)
    await db_session.commit()
    orphan = next(item for item in created_orphans if item.item_type == "threat")
    orphan_id = orphan.id

    ciso_user.is_active = True
    await db_session.commit()

    resolved = await resolve_orphan(
        db_session,
        orphan_id,
        resolved_by_id=cro_id,
        new_owner_id=previous_steward_id,
    )
    assert resolved.status == "resolved"
    db_session.expire_all()
    threat = await db_session.get(Threat, threat_id)
    assert threat is not None
    assert threat.threat_steward_user_id == previous_steward_id
    assert threat.governance_version == initial_governance_version
    assert (
        await db_session.scalar(
            select(OrphanedItem.status).where(OrphanedItem.id == orphan_id)
        )
        == "resolved"
    )


@pytest.mark.asyncio
async def test_legacy_null_steward_is_assignable_without_phantom_governance_orphan(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
    ciso_user: User,
) -> None:
    db_session.add(
        ApprovalScenario(
            key="accountability_reassignment",
            display_name="Accountability reassignments",
            description="Independent approval for accountability reassignments",
            requires_approval=True,
            approver_roles=["risk_manager", "cro"],
        )
    )
    legacy_threat = Threat(name="Migrated stewardship gap", threat_steward_user_id=None)
    db_session.add(legacy_threat)
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        detail = await client.get(f"/api/v1/threats/{legacy_threat.id}")
        listed = await client.get("/api/v1/threats?offset=0&limit=100")
        assigned = await client.patch(
            f"/api/v1/threats/{legacy_threat.id}",
            json={
                "threat_steward_user_id": ciso_user.id,
                "request_reason": "Assign the legacy Threat Steward",
            },
        )

    assert detail.status_code == 200, detail.text
    assert detail.json()["steward_orphaned"] is False
    assert detail.json()["stewardship_status"] == "legacy_unassigned"
    assert detail.json()["capabilities"]["can_update"] is True
    listed_row = next(item for item in listed.json()["items"] if item["id"] == legacy_threat.id)
    assert listed_row["steward_orphaned"] is False
    assert listed_row["stewardship_status"] == "legacy_unassigned"
    assert listed_row["capabilities"]["can_update"] is True
    pending_orphan = (
        await db_session.execute(
            select(OrphanedItem.id).where(
                OrphanedItem.item_type == "threat",
                OrphanedItem.item_id == legacy_threat.id,
                OrphanedItem.status == "pending",
            )
        )
    ).scalar_one_or_none()
    assert pending_orphan is None
    assert assigned.status_code == 202, assigned.text
    await db_session.refresh(legacy_threat)
    assert legacy_threat.threat_steward_user_id is None

    async with client_factory(user=test_user_risk_manager) as approver:
        approved = await approver.post(
            f"/api/v1/approvals/{assigned.json()['approval_id']}/approve",
            json={"resolution_notes": "Legacy Threat Steward assignment approved"},
        )

    assert approved.status_code == 200, approved.text
    await db_session.refresh(legacy_threat)
    assert legacy_threat.threat_steward_user_id == ciso_user.id
    assert legacy_threat.governance_version == 2


@pytest.mark.asyncio
async def test_pending_governance_orphan_is_authoritative_after_ciso_restoration(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    threat = Threat(name="Restored CISO remains pending", threat_steward_user_id=ciso_user.id)
    db_session.add(threat)
    await db_session.commit()
    orphan = (await flag_orphaned_items(db_session, ciso_user.id))[0]
    await db_session.commit()

    # The former steward is eligible again, but the pending evidence record is
    # deliberately not auto-resolved.
    ciso_user.is_active = True
    ciso_user.role.is_active = True
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        detail = await client.get(f"/api/v1/threats/{threat.id}")
        listed = await client.get("/api/v1/threats?offset=0&limit=100")
        ordinary_field_patch = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"notes": "must not bypass Governance"},
        )
        empty_patch = await client.patch(f"/api/v1/threats/{threat.id}", json={})

    assert detail.status_code == 200, detail.text
    assert detail.json()["steward_orphaned"] is True
    assert detail.json()["stewardship_status"] == "pending_governance"
    assert detail.json()["capabilities"]["can_update"] is False
    listed_row = next(item for item in listed.json()["items"] if item["id"] == threat.id)
    assert listed_row["steward_orphaned"] is True
    assert listed_row["stewardship_status"] == "pending_governance"
    assert listed_row["capabilities"]["can_update"] is False
    assert ordinary_field_patch.status_code == 409, ordinary_field_patch.text
    assert empty_patch.status_code == 409, empty_patch.text
    # The handled 409 must still release locks and restore the shared session's
    # identity-mapped Threat rather than leaving a failed PATCH mutation behind.
    assert threat.notes is None
    await db_session.refresh(orphan)
    assert orphan.status == "pending"


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_pending_orphan_patch_releases_preflight_locks(
    async_engine,
    db_session: AsyncSession,
    client_factory,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    if async_engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL row and transaction-scoped advisory locks")

    replacement = User(
        name="Blocked Replacement CISO",
        email="blocked.replacement.ciso@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    threat = Threat(
        name="Pending stewardship releases locks",
        threat_steward_user_id=ciso_user.id,
    )
    db_session.add_all([replacement, threat])
    await db_session.commit()
    await flag_orphaned_items(db_session, ciso_user.id)

    async with client_factory(user=test_user_cro) as client:
        blocked = await client.patch(
            f"/api/v1/threats/{threat.id}",
            json={"threat_steward_user_id": replacement.id},
        )

    assert blocked.status_code == 409, blocked.text
    assert threat.threat_steward_user_id == ciso_user.id

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_maker() as competing_session:
        locked_threat_id = (
            await competing_session.execute(
                select(Threat.id)
                .where(Threat.id == threat.id)
                .with_for_update(nowait=True)
            )
        ).scalar_one()
        advisory_lock_available = (
            await competing_session.execute(
                text("SELECT pg_try_advisory_xact_lock(:namespace, :user_id)"),
                {"namespace": 0x5249, "user_id": replacement.id},
            )
        ).scalar_one()

    assert locked_threat_id == threat.id
    assert advisory_lock_available is True


@pytest.mark.asyncio
async def test_inactive_ciso_role_is_reflected_in_stewardship_projection(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    ciso_user: User,
) -> None:
    threat = Threat(name="Inactive role projection", threat_steward_user_id=ciso_user.id)
    db_session.add(threat)
    await db_session.commit()
    ciso_user.role.is_active = False
    await db_session.commit()

    async with client_factory(user=test_user_cro) as client:
        response = await client.get(f"/api/v1/threats/{threat.id}")

    assert response.status_code == 200, response.text
    assert response.json()["stewardship_status"] == "invalid_assignment"
    assert response.json()["steward_orphaned"] is False


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_create_and_ciso_deactivation_preserve_stewardship_invariant(
    async_engine,
    client_factory,
    test_user: User,
    ciso_user: User,
) -> None:
    if async_engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL transaction-scoped advisory locks")

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    settings = Settings(mock_auth_enabled=True, debug=True)
    async with client_factory(
        user=test_user,
        settings=settings,
        db_override=override_get_db,
    ) as client:
        created, deactivated = await asyncio.gather(
            client.post(
                "/api/v1/threats",
                json={
                    "name": "Concurrent steward assignment",
                    "threat_steward_user_id": ciso_user.id,
                },
            ),
            client.patch(
                f"/api/v1/users/{ciso_user.id}",
                json={"is_active": False},
            ),
        )

    assert deactivated.status_code == 200, deactivated.text
    assert created.status_code in {201, 400}, created.text

    async with session_maker() as session:
        persisted_ciso = await session.get(User, ciso_user.id)
        threat = (
            await session.execute(
                select(Threat).where(Threat.name == "Concurrent steward assignment")
            )
        ).scalar_one_or_none()
        assert persisted_ciso is not None and persisted_ciso.is_active is False
        if threat is None:
            assert created.status_code == 400
        else:
            assert created.status_code == 201
            pending_orphan = (
                await session.execute(
                    select(OrphanedItem).where(
                        OrphanedItem.item_type == "threat",
                        OrphanedItem.item_id == threat.id,
                        OrphanedItem.previous_owner_id == ciso_user.id,
                        OrphanedItem.status == "pending",
                    )
                )
            ).scalar_one()
            assert pending_orphan.item_id == threat.id


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_reassignment_and_role_loss_cannot_leave_stale_orphan(
    async_engine,
    db_session: AsyncSession,
    client_factory,
    test_user: User,
    test_user_risk_manager: User,
    test_role_employee: Role,
    ciso_user: User,
) -> None:
    if async_engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL transaction-scoped advisory locks")

    replacement = User(
        name="Concurrent Replacement CISO",
        email="concurrent.replacement.ciso@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    threat = Threat(
        name="Concurrent steward reassignment",
        threat_steward_user_id=ciso_user.id,
    )
    db_session.add_all(
        [
            replacement,
            threat,
            ApprovalScenario(
                key="accountability_reassignment",
                display_name="Accountability reassignments",
                description="Independent approval for accountability reassignments",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    settings = Settings(mock_auth_enabled=True, debug=True)
    async with client_factory(
        user=test_user,
        settings=settings,
        db_override=override_get_db,
    ) as client:
        reassigned, role_lost = await asyncio.gather(
            client.patch(
                f"/api/v1/threats/{threat.id}",
                json={
                    "threat_steward_user_id": replacement.id,
                    "request_reason": "Exercise reassignment versus role loss",
                },
            ),
            client.patch(
                f"/api/v1/users/{ciso_user.id}",
                json={"role_id": test_role_employee.id},
            ),
        )

    assert role_lost.status_code == 200, role_lost.text
    assert reassigned.status_code in {200, 202, 409}, reassigned.text

    async with session_maker() as session:
        persisted_threat = await session.get(Threat, threat.id)
        pending_orphan = (
            await session.execute(
                select(OrphanedItem).where(
                    OrphanedItem.item_type == "threat",
                    OrphanedItem.item_id == threat.id,
                    OrphanedItem.status == "pending",
                )
            )
        ).scalar_one_or_none()
        assert persisted_threat is not None
        if reassigned.status_code == 200:
            assert persisted_threat.threat_steward_user_id == replacement.id
            assert pending_orphan is None
        else:
            assert persisted_threat.threat_steward_user_id == ciso_user.id
            assert pending_orphan is not None
            assert pending_orphan.previous_owner_id == ciso_user.id


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_overlapping_threat_reassignments_serialize_without_deadlock(
    async_engine,
    db_session: AsyncSession,
    client_factory,
    test_user: User,
    ciso_user: User,
    test_user_risk_manager: User,
) -> None:
    if async_engine.dialect.name != "postgresql":
        pytest.skip("Requires PostgreSQL row and transaction-scoped advisory locks")

    replacement_b = User(
        name="Overlapping Replacement B",
        email="overlapping.replacement.b@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    replacement_c = User(
        name="Overlapping Replacement C",
        email="overlapping.replacement.c@test.local",
        role_id=ciso_user.role_id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    threat = Threat(
        name="Overlapping steward reassignment",
        threat_steward_user_id=ciso_user.id,
    )
    del test_user_risk_manager
    db_session.add_all(
        [
            replacement_b,
            replacement_c,
            threat,
            ApprovalScenario(
                key="accountability_reassignment",
                display_name="Accountability reassignments",
                description="Independent approval for accountability reassignments",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    settings = Settings(mock_auth_enabled=True, debug=True)
    async with client_factory(
        user=test_user,
        settings=settings,
        db_override=override_get_db,
    ) as client:
        responses = await asyncio.wait_for(
            asyncio.gather(
                client.patch(
                    f"/api/v1/threats/{threat.id}",
                    json={
                        "threat_steward_user_id": replacement_b.id,
                        "request_reason": "Concurrent Threat transfer B",
                    },
                ),
                client.patch(
                    f"/api/v1/threats/{threat.id}",
                    json={
                        "threat_steward_user_id": replacement_c.id,
                        "request_reason": "Concurrent Threat transfer C",
                    },
                ),
            ),
            timeout=10,
        )

    assert sorted(response.status_code for response in responses) == [202, 409]
    async with session_maker() as session:
        persisted = await session.get(Threat, threat.id)
        assert persisted is not None
        assert persisted.threat_steward_user_id == ciso_user.id
        pending_orphan = (
            await session.execute(
                select(OrphanedItem.id).where(
                    OrphanedItem.item_type == "threat",
                    OrphanedItem.item_id == threat.id,
                    OrphanedItem.status == "pending",
                )
            )
        ).scalar_one_or_none()
        assert pending_orphan is None
