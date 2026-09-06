import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.vendors import crud as vendor_crud
from app.core.user_query_options import user_selectinload_options
from app.models import (
    Asset,
    Department,
    Permission,
    Process,
    Risk,
    Role,
    RolePermission,
    User,
    Vendor,
    VendorRiskLink,
)
from app.models.activity_log import ActivityLog
from app.models.user import AccessScope
from app.schemas.vendor import VendorCreate, VendorUpdate
from app.services._register_listings import vendors as vendor_listing
from app.services._vendor_governance.lifecycle import (
    archive_vendor_detail,
    create_vendor_detail,
    restore_vendor_detail,
    update_vendor_detail,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("restore", [False, True])
async def test_vendor_archive_restore_commit_failure_rolls_back_before_returning(
    db_session,
    test_department,
    test_user,
    monkeypatch,
    restore,
):
    vendor = Vendor(
        name="Commit failure vendor",
        process="IT",
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
        is_archived=restore,
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)
    audit_count = await db_session.scalar(select(func.count()).select_from(ActivityLog))
    original_version = vendor.governance_version
    failure = RuntimeError("commit unavailable")
    rollback_calls = 0
    original_rollback = db_session.rollback

    async def fail_commit():
        raise failure

    async def rollback():
        nonlocal rollback_calls
        rollback_calls += 1
        await original_rollback()

    monkeypatch.setattr(db_session, "commit", fail_commit)
    monkeypatch.setattr(db_session, "rollback", rollback)
    mutation = restore_vendor_detail if restore else archive_vendor_detail
    with pytest.raises(RuntimeError) as raised:
        await mutation(db=db_session, vendor_id=vendor.id, current_user=test_user)
    assert raised.value is failure
    assert rollback_calls == 1
    await db_session.refresh(vendor)
    assert vendor.is_archived is restore
    assert vendor.governance_version == original_version
    assert await db_session.scalar(select(func.count()).select_from(ActivityLog)) == audit_count


async def _grant(db_session: AsyncSession, role: Role, resource: str, action: str) -> None:
    perm = Permission(resource=resource, action=action, description=f"{resource}:{action}")
    db_session.add(perm)
    await db_session.commit()
    await db_session.refresh(perm)

    db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    await db_session.commit()
    # Ensure subsequent request-scoped loads see updated role->permissions in the same session.
    db_session.expire(role, ["permissions"])


def _make_risk(*, name: str, risk_id_code: str, department_id: int | None) -> Risk:
    return Risk(
        risk_id_code=risk_id_code,
        name=name,
        process="Operations",
        subprocess=None,
        category="Third Party",
        description="Test risk",
        department_id=department_id,
        owner_id=None,
        gross_probability=3,
        gross_impact=3,
        gross_score=9,
        net_probability=2,
        net_impact=2,
        net_score=4,
        status="active",
        is_priority=False,
    )


@pytest.mark.asyncio
async def test_vendors_requires_read_permission(client_department_head: AsyncClient):
    resp = await client_department_head.get("/api/v1/vendors")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_vendors_list_scoping_includes_cross_department_owner(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_employee, "vendors", "read")

    other_dept = Department(name="Other Department", code="OTHR", description="Other")
    db_session.add(other_dept)
    await db_session.commit()
    await db_session.refresh(other_dept)

    v_in_dept = Vendor(
        name="Dept Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    v_cross_dept_owned = Vendor(
        name="Cross Dept Owned",
        process="IT",
        subprocess=None,
        department_id=other_dept.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=4,
        supports_important_core_insurance_function=True,
        dora_relevant=True,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    v_cross_dept_not_owned = Vendor(
        name="Other Dept Vendor",
        process="IT",
        subprocess=None,
        department_id=other_dept.id,
        outsourcing_owner_user_id=test_user_employee.id + 999,
        vendor_type="ict",
        risk_score_1_5=2,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    db_session.add_all([v_in_dept, v_cross_dept_owned, v_cross_dept_not_owned])
    await db_session.commit()

    resp = await client_employee.get("/api/v1/vendors")
    assert resp.status_code == 200
    data = resp.json()
    names = {v["name"] for v in data["items"]}
    assert "Dept Vendor" in names
    assert "Cross Dept Owned" in names
    assert "Other Dept Vendor" not in names

    dept_resp = await client_employee.get(f"/api/v1/vendors?department_id={test_department.id}")
    assert dept_resp.status_code == 200
    dept_names = {v["name"] for v in dept_resp.json()["items"]}
    assert "Dept Vendor" in dept_names
    assert "Cross Dept Owned" not in dept_names


@pytest.mark.asyncio
async def test_vendor_owner_can_update_without_vendors_write(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_employee, "vendors", "read")

    vendor = Vendor(
        name="Owned Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)

    resp = await client_employee.patch(f"/api/v1/vendors/{vendor.id}", json={"name": "Owned Vendor Updated"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Owned Vendor Updated"
    assert resp.json()["capabilities"]["can_update"] is True
    assert resp.json()["capabilities"]["can_archive"] is False

    resp = await client_employee.patch(f"/api/v1/vendors/{vendor.id}", json={"department_id": None})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_inactive_vendor_rejects_patch_and_suppresses_mutation_capabilities(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_employee, "vendors", "read")
    await _grant(db_session, test_role_employee, "vendors", "write")
    await _grant(db_session, test_role_employee, "vendors", "delete")
    await _grant(db_session, test_role_employee, "risks", "read")
    await _grant(db_session, test_role_employee, "risks", "write")
    await _grant(db_session, test_role_employee, "controls", "read")
    await _grant(db_session, test_role_employee, "controls", "write")
    await _grant(db_session, test_role_employee, "issues", "write")
    await _grant(db_session, test_role_employee, "assets", "read")
    await _grant(db_session, test_role_employee, "assets", "write")
    await _grant(db_session, test_role_employee, "processes", "read")
    await _grant(db_session, test_role_employee, "processes", "write")

    vendor = Vendor(
        name="Inactive Mutation Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
        is_archived=True,
    )
    process = Process(
        f_code="F-VENDOR-CAPABILITY",
        l0_area="Operations",
        l1_process="Editable Process for Vendor capability",
        process_owner_user_id=test_user_employee.id,
        owning_department_id=test_department.id,
    )
    asset = Asset(
        name="Editable Asset for Vendor capability",
        business_owner_user_id=test_user_employee.id,
        ict_owner_user_id=test_user_employee.id,
        owning_department_id=test_department.id,
    )
    db_session.add_all([vendor, process, asset])
    await db_session.commit()
    await db_session.refresh(vendor)

    patch_resp = await client_employee.patch(f"/api/v1/vendors/{vendor.id}", json={"name": "Should Not Update"})
    assert patch_resp.status_code == 409

    detail_resp = await client_employee.get(f"/api/v1/vendors/{vendor.id}")
    assert detail_resp.status_code == 200
    capabilities = detail_resp.json()["capabilities"]
    assert capabilities["can_update"] is False
    assert capabilities["can_create_linked_risk"] is False
    assert capabilities["can_create_linked_control"] is False
    assert capabilities["can_create_linked_kri"] is False
    assert capabilities["can_link_risk"] is False
    assert capabilities["can_link_control"] is False
    assert capabilities["can_link_kri"] is False
    assert capabilities["can_create_issue"] is False
    assert capabilities["can_view_asset_links"] is True
    assert capabilities["can_manage_asset_links"] is False
    assert capabilities["can_manage_process_links"] is False
    assert capabilities["can_restore"] is True

    restore_resp = await client_employee.post(f"/api/v1/vendors/{vendor.id}/restore")
    assert restore_resp.status_code == 200
    restored_capabilities = restore_resp.json()["capabilities"]
    assert restored_capabilities["can_update"] is True
    assert restored_capabilities["can_create_issue"] is True
    assert restored_capabilities["can_view_asset_links"] is True
    assert restored_capabilities["can_manage_asset_links"] is True
    assert restored_capabilities["can_manage_process_links"] is True


@pytest.mark.asyncio
async def test_vendor_governance_owner_can_be_cross_department_for_scoped_writer(
    db_session: AsyncSession,
    client_department_head: AsyncClient,
    test_department: Department,
    test_role_department_head: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_department_head, "vendors", "write")

    other_dept = Department(name="Owner Other Department", code="OOWN", description="Other")
    db_session.add(other_dept)
    await db_session.commit()
    await db_session.refresh(other_dept)

    other_owner = User(
        email="vendor-owner-other@example.com",
        name="Vendor Owner Other",
        hashed_password="x",
        role_id=test_role_department_head.id,
        department_id=other_dept.id,
        access_scope=AccessScope.DEPARTMENT,
        is_active=True,
    )
    db_session.add(other_owner)
    await db_session.commit()
    await db_session.refresh(other_owner)

    resp = await client_department_head.post(
        "/api/v1/vendors",
        json={
            "name": "Mismatch Owner Vendor",
            "process": "IT",
            "department_id": test_department.id,
            "outsourcing_owner_user_id": other_owner.id,
            "vendor_type": "ict",
            "risk_score_1_5": 3,
            "supports_important_core_insurance_function": False,
            "dora_relevant": False,
            "is_significant_vendor": False,
            "has_alternative_providers": False,
            "status": "active",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["outsourcing_owner_user_id"] == other_owner.id


@pytest.mark.asyncio
async def test_vendor_create_requires_vendors_write(
    db_session: AsyncSession,
    client_department_head: AsyncClient,
    test_department: Department,
    test_role_department_head: Role,
    test_user_employee: User,
):
    # no permissions => forbidden
    resp = await client_department_head.post(
        "/api/v1/vendors",
        json={
            "name": "New Vendor",
            "process": "IT",
            "department_id": test_department.id,
            "outsourcing_owner_user_id": test_user_employee.id,
            "vendor_type": "ict",
            "risk_score_1_5": 3,
            "supports_important_core_insurance_function": False,
            "dora_relevant": False,
            "is_significant_vendor": False,
            "has_alternative_providers": False,
            "status": "active",
        },
    )
    assert resp.status_code == 403

    await _grant(db_session, test_role_department_head, "vendors", "write")

    resp = await client_department_head.post(
        "/api/v1/vendors",
        json={
            "name": "New Vendor",
            "process": "IT",
            "department_id": test_department.id,
            "outsourcing_owner_user_id": test_user_employee.id,
            "vendor_type": "ict",
            "risk_score_1_5": 3,
            "supports_important_core_insurance_function": False,
            "dora_relevant": False,
            "is_significant_vendor": False,
            "has_alternative_providers": False,
            "status": "active",
        },
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_vendor_create_rolls_back_when_audit_logging_fails(
    db_session: AsyncSession,
    test_department: Department,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
):
    async def fail_log_activity(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("app.services._vendor_governance.lifecycle.log_activity", fail_log_activity)

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await create_vendor_detail(
            db=db_session,
            payload=VendorCreate(
                name="Audit Rollback Create Vendor",
                process="IT",
                department_id=test_department.id,
                outsourcing_owner_user_id=test_user.id,
                vendor_type="ict",
                risk_score_1_5=3,
                supports_important_core_insurance_function=False,
                dora_relevant=False,
                is_significant_vendor=False,
                has_alternative_providers=False,
                status="active",
            ),
            current_user=test_user,
        )

    await db_session.rollback()
    vendor = await db_session.scalar(select(Vendor).where(Vendor.name == "Audit Rollback Create Vendor"))
    assert vendor is None


@pytest.mark.asyncio
async def test_vendor_update_rolls_back_when_audit_logging_fails(
    db_session: AsyncSession,
    test_department: Department,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
):
    vendor = Vendor(
        name="Audit Rollback Update Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)

    async def fail_log_activity(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("app.services._vendor_governance.lifecycle.log_activity", fail_log_activity)

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await update_vendor_detail(
            db=db_session,
            vendor_id=vendor.id,
            payload=VendorUpdate(name="Audit Rollback Updated Vendor"),
            current_user=test_user,
        )

    await db_session.rollback()
    await db_session.refresh(vendor)
    assert vendor.name == "Audit Rollback Update Vendor"


@pytest.mark.asyncio
async def test_vendor_archive_rolls_back_when_audit_logging_fails(
    db_session: AsyncSession,
    test_department: Department,
    test_user: User,
    monkeypatch: pytest.MonkeyPatch,
):
    vendor = Vendor(
        name="Audit Rollback Archive Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)

    async def fail_log_activity(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("app.services._vendor_governance.lifecycle.log_activity", fail_log_activity)

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await archive_vendor_detail(db=db_session, vendor_id=vendor.id, current_user=test_user)

    await db_session.rollback()
    await db_session.refresh(vendor)
    assert vendor.is_archived is False


@pytest.mark.asyncio
async def test_vendors_include_archived_toggle(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    """Inactive vendors are hidden by default and shown when include_archived=true."""
    await _grant(db_session, test_role_employee, "vendors", "read")

    active_vendor = Vendor(
        name="Active Toggle Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    inactive_vendor = Vendor(
        name="Inactive Toggle Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
        is_archived=True,
    )
    db_session.add_all([active_vendor, inactive_vendor])
    await db_session.commit()

    default_resp = await client_employee.get("/api/v1/vendors")
    assert default_resp.status_code == 200
    default_names = {v["name"] for v in default_resp.json()["items"]}
    assert "Active Toggle Vendor" in default_names
    assert "Inactive Toggle Vendor" not in default_names

    include_resp = await client_employee.get("/api/v1/vendors?include_archived=true")
    assert include_resp.status_code == 200
    include_names = {v["name"] for v in include_resp.json()["items"]}
    assert "Inactive Toggle Vendor" in include_names


@pytest.mark.asyncio
async def test_vendors_scoped_users_do_not_see_unassigned_vendors(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_role_employee: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_employee, "vendors", "read")

    vendor = Vendor(
        name="Unassigned Scoped Hidden Vendor",
        process="IT",
        subprocess=None,
        department_id=None,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    db_session.add(vendor)
    await db_session.commit()

    response = await client_employee.get("/api/v1/vendors")
    assert response.status_code == 200
    assert "Unassigned Scoped Hidden Vendor" not in {item["name"] for item in response.json()["items"]}


@pytest.mark.asyncio
async def test_vendors_list_includes_visible_linked_risks_and_empty_arrays(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
    monkeypatch: pytest.MonkeyPatch,
):
    await _grant(db_session, test_role_employee, "vendors", "read")
    await _grant(db_session, test_role_employee, "risks", "read")

    async def fail_scalar_risk_visibility(*args, **kwargs) -> bool:
        raise AssertionError("vendor list linked-risk serialization must use set-based visibility")

    monkeypatch.setattr(vendor_listing, "can_read_risk_id", fail_scalar_risk_visibility, raising=False)

    vendor_with_links = Vendor(
        name="Linked Vendor",
        process="Claims",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=4,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    vendor_without_links = Vendor(
        name="Unlinked Vendor",
        process="Finance",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="partner",
        risk_score_1_5=2,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    risk_one = _make_risk(name="Cyber Exposure", risk_id_code="R-001", department_id=test_department.id)
    risk_two = _make_risk(name="Concentration Risk", risk_id_code="R-002", department_id=test_department.id)
    db_session.add_all([vendor_with_links, vendor_without_links, risk_one, risk_two])
    await db_session.commit()
    await db_session.refresh(vendor_with_links)
    await db_session.refresh(risk_one)
    await db_session.refresh(risk_two)

    db_session.add_all(
        [
            VendorRiskLink(vendor_id=vendor_with_links.id, risk_id=risk_one.id),
            VendorRiskLink(vendor_id=vendor_with_links.id, risk_id=risk_two.id),
        ]
    )
    await db_session.commit()

    response = await client_employee.get("/api/v1/vendors")
    assert response.status_code == 200

    items = {item["name"]: item for item in response.json()["items"]}
    assert items["Linked Vendor"]["linked_risks"] == [
        {
            "risk_id": risk_one.id,
            "risk_id_code": "R-001",
            "risk_name": "Cyber Exposure",
        },
        {
            "risk_id": risk_two.id,
            "risk_id_code": "R-002",
            "risk_name": "Concentration Risk",
        },
    ]
    assert items["Unlinked Vendor"]["linked_risks"] == []


@pytest.mark.asyncio
async def test_vendors_list_linked_risks_supports_manager_derived_scope(
    db_session: AsyncSession,
    test_department: Department,
    test_role_employee: Role,
    test_user_cro: User,
) -> None:
    await _grant(db_session, test_role_employee, "vendors", "read")
    await _grant(db_session, test_role_employee, "risks", "read")
    manager_scoped_user = User(
        name="Manager Scoped Vendor Reader",
        email="manager.scoped.vendor.reader@test.com",
        department_id=None,
        manager_id=test_user_cro.id,
        role_id=test_role_employee.id,
        is_active=True,
        access_scope=AccessScope.MANAGER,
    )
    vendor = Vendor(
        name="Manager Scope Linked Vendor",
        process="Claims",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_cro.id,
        vendor_type="ict",
        risk_score_1_5=4,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    risk = _make_risk(name="Manager Visible Risk", risk_id_code="R-MGR-001", department_id=test_department.id)
    db_session.add_all([manager_scoped_user, vendor, risk])
    await db_session.commit()
    await db_session.refresh(manager_scoped_user)
    await db_session.refresh(vendor)
    await db_session.refresh(risk)

    db_session.add(VendorRiskLink(vendor_id=vendor.id, risk_id=risk.id))
    await db_session.commit()

    loaded_user = (
        await db_session.execute(
            select(User)
            .options(*user_selectinload_options(include_permissions=True))
            .where(User.id == manager_scoped_user.id)
        )
    ).scalar_one()

    visible_risk_ids = await vendor_listing.get_visible_vendor_risk_ids(
        db_session,
        current_user=loaded_user,
        vendors=[vendor],
    )

    assert visible_risk_ids == {risk.id}


@pytest.mark.asyncio
async def test_vendors_list_filters_out_invisible_linked_risks(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    await _grant(db_session, test_role_employee, "vendors", "read")
    await _grant(db_session, test_role_employee, "risks", "read")

    other_department = Department(name="Other Department", code="OTHR", description="Other")
    db_session.add(other_department)
    await db_session.commit()
    await db_session.refresh(other_department)

    vendor = Vendor(
        name="Scoped Vendor",
        process="Operations",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="outsourcing",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    visible_risk = _make_risk(name="Visible Risk", risk_id_code="R-101", department_id=test_department.id)
    invisible_risk = _make_risk(name="Hidden Risk", risk_id_code="R-999", department_id=other_department.id)
    db_session.add_all([vendor, visible_risk, invisible_risk])
    await db_session.commit()
    await db_session.refresh(vendor)
    await db_session.refresh(visible_risk)
    await db_session.refresh(invisible_risk)

    db_session.add_all(
        [
            VendorRiskLink(vendor_id=vendor.id, risk_id=visible_risk.id),
            VendorRiskLink(vendor_id=vendor.id, risk_id=invisible_risk.id),
        ]
    )
    await db_session.commit()

    response = await client_employee.get("/api/v1/vendors")
    assert response.status_code == 200

    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["linked_risks"] == [
        {
            "risk_id": visible_risk.id,
            "risk_id_code": "R-101",
            "risk_name": "Visible Risk",
        }
    ]


@pytest.mark.asyncio
async def test_vendors_list_hides_linked_risks_without_risks_read(
    db_session: AsyncSession,
    client_department_head: AsyncClient,
    test_department: Department,
    test_role_department_head: Role,
    test_user_employee: User,
    monkeypatch: pytest.MonkeyPatch,
):
    await _grant(db_session, test_role_department_head, "vendors", "read")

    original_check_permission = vendor_crud.check_permission

    def deny_risk_read(current_user: User, resource: str, action: str) -> bool:
        if resource == "risks" and action == "read":
            return False
        return original_check_permission(current_user, resource, action)

    monkeypatch.setattr(vendor_crud, "check_permission", deny_risk_read)

    async def no_visible_risks(*args, **kwargs) -> set[int]:
        return set()

    monkeypatch.setattr(vendor_crud, "_get_visible_risk_ids", no_visible_risks)

    vendor = Vendor(
        name="No Risk Permission Vendor",
        process="Operations",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
    )
    risk = _make_risk(name="Should Stay Hidden", risk_id_code="R-777", department_id=test_department.id)
    db_session.add_all([vendor, risk])
    await db_session.commit()
    await db_session.refresh(vendor)
    await db_session.refresh(risk)

    db_session.add(VendorRiskLink(vendor_id=vendor.id, risk_id=risk.id))
    await db_session.commit()

    response = await client_department_head.get("/api/v1/vendors")
    assert response.status_code == 200

    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["linked_risks"] == []


@pytest.mark.asyncio
async def test_vendor_restore_requires_vendors_delete(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    """Users without vendors:delete cannot restore vendors."""
    await _grant(db_session, test_role_employee, "vendors", "read")

    vendor = Vendor(
        name="Restore Forbidden Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        status="active",
        is_archived=True,
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)

    forbidden = await client_employee.post(f"/api/v1/vendors/{vendor.id}/restore")
    assert forbidden.status_code == 403


@pytest.mark.asyncio
async def test_vendor_restore_reactivates_inactive_vendor(
    db_session: AsyncSession,
    client_employee: AsyncClient,
    test_department: Department,
    test_role_employee: Role,
    test_user_employee: User,
):
    """Restore endpoint clears the vendor archive flag."""
    await _grant(db_session, test_role_employee, "vendors", "read")
    await _grant(db_session, test_role_employee, "vendors", "delete")

    vendor = Vendor(
        name="Restore Active Vendor",
        process="IT",
        subprocess=None,
        department_id=test_department.id,
        outsourcing_owner_user_id=test_user_employee.id,
        vendor_type="ict",
        risk_score_1_5=3,
        supports_important_core_insurance_function=False,
        dora_relevant=False,
        is_significant_vendor=False,
        has_alternative_providers=False,
        is_archived=True,
    )
    db_session.add(vendor)
    await db_session.commit()
    await db_session.refresh(vendor)

    restored = await client_employee.post(f"/api/v1/vendors/{vendor.id}/restore")
    assert restored.status_code == 200
    assert restored.json()["is_archived"] is False


@pytest.mark.asyncio
async def test_list_vendors_rejects_invalid_sort_by(auth_client: AsyncClient):
    response = await auth_client.get("/api/v1/vendors", params={"sort_by": "unknown_field"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid sort_by value"


@pytest.mark.asyncio
async def test_vendor_sort_ties_use_id_as_deterministic_secondary_key(
    auth_client: AsyncClient,
    db_session: AsyncSession,
    test_department: Department,
    test_user: User,
):
    vendors = [
        Vendor(
            name="Stable tie vendor",
            process="IT",
            department_id=test_department.id,
            outsourcing_owner_user_id=test_user.id,
            vendor_type="ict",
            risk_score_1_5=3,
            supports_important_core_insurance_function=False,
            dora_relevant=False,
            is_significant_vendor=False,
            has_alternative_providers=False,
            status="active",
        )
        for _ in range(3)
    ]
    db_session.add_all(vendors)
    await db_session.commit()

    response = await auth_client.get(
        "/api/v1/vendors",
        params={"search": "Stable tie vendor", "sort_by": "name", "sort_order": "desc"},
    )

    assert response.status_code == 200
    assert [row["id"] for row in response.json()["items"]] == sorted(
        (vendor.id for vendor in vendors), reverse=True
    )
