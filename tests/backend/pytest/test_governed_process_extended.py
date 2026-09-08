"""Protected Process create/archive proposal behavior for ICT-GOV #85."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from app.core.user_query_options import user_selectinload_options
from app.models import (
    ApprovalActionType,
    ApprovalRequest,
    ApprovalScenario,
    ApprovalStatus,
    Asset,
    AssetVendorLink,
    Department,
    GlobalConfig,
    GovernedMutationImpactLock,
    GovernedMutationProposal,
    Notification,
    NotificationType,
    OrphanedItem,
    OutboxEvent,
    Process,
    ProcessAssetLink,
    User,
    Vendor,
)
from app.models.activity_log import ActivityAction, ActivityEntityType, ActivityLog
from app.models.user import AccessScope
from app.services._governed_mutations.process_mutations import (
    strict_extended_process_identity,
    valid_extended_process_approval_ids,
)


async def _scenario(db: AsyncSession) -> None:
    db.add(
        ApprovalScenario(
            key="protected_process_edit",
            display_name="Protected Process mutations",
            description="Independent approval for CIF Process mutations",
            requires_approval=True,
            approver_roles=["risk_manager", "cro"],
        )
    )
    db.add(
        ApprovalScenario(
            key="protected_asset_edit",
            display_name="Protected Asset mutations",
            description="Independent approval for protected Asset mutations",
            requires_approval=True,
            approver_roles=["risk_manager", "cro"],
        )
    )
    db.add(
        ApprovalScenario(
            key="protected_vendor_edit",
            display_name="Protected Vendor mutations",
            description="Independent approval for protected Vendor mutations",
            requires_approval=True,
            approver_roles=["risk_manager", "cro"],
        )
    )
    await db.commit()


async def _scoped_cro_reviewer(db: AsyncSession, source: User) -> User:
    reviewer = User(
        name="Scoped CRO reviewer",
        email="scoped.cro.reviewer@test.com",
        department_id=source.department_id,
        role_id=source.role_id,
        is_active=True,
        access_scope=AccessScope.DEPARTMENT,
    )
    db.add(reviewer)
    await db.commit()
    return (
        await db.execute(
            select(User)
            .options(*user_selectinload_options(include_permissions=True))
            .where(User.id == reviewer.id)
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_composite_process_edit_projects_valid_pending_detail(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    del test_user_risk_manager
    other_department = Department(
        name="Composite pending restricted department",
        code="W4-PENDING-RESTRICTED",
    )
    db_session.add(other_department)
    await db_session.flush()
    process = Process(
        f_code="F-W4-PENDING",
        l0_area="Operations",
        l1_process="Composite pending projection",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        preliminary_criticality="low",
        cif_override="no",
    )
    asset = Asset(
        name="Composite pending Asset",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=other_department.id,
        preliminary_criticality="low",
    )
    vendor = Vendor(
        name="Composite pending Vendor",
        process="Operations",
        outsourcing_owner_user_id=test_user_cro.id,
        department_id=other_department.id,
        replaceability="easily_substitutable",
    )
    db_session.add_all([process, asset, vendor])
    await db_session.flush()
    db_session.add_all(
        [
            ProcessAssetLink(process_id=process.id, asset_id=asset.id, is_primary=True),
            AssetVendorLink(asset_id=asset.id, vendor_id=vendor.id, ict_service_code="S01"),
        ]
    )
    await db_session.commit()
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.patch(
            f"/api/v1/processes/{process.id}",
            json={
                "preliminary_criticality": "critical",
                "cif_override": "yes",
                "request_reason": "Review composite pending projection",
            },
        )
        detail = await requester.get(f"/api/v1/processes/{process.id}")

    assert submitted.status_code == 202, submitted.text
    assert detail.status_code == 200, detail.text
    pending = detail.json()["pending_change"]
    assert pending["derived_impact"]["processes"] == [
        {
            "resource_name": "F-W4-PENDING — Composite pending projection",
            "before": {"cif": "no", "criticality_class": "low"},
            "after": {"cif": "yes", "criticality_class": "critical"},
        }
    ]
    assert pending["derived_impact"]["assets"] == [
        {
            "resource_name": "Composite pending Asset",
            "before": {"cif": "no", "resulting_criticality": "low"},
            "after": {"cif": "yes", "resulting_criticality": "critical"},
        }
    ]
    assert pending["derived_impact"]["vendors"] == [
        {
            "resource_name": "Composite pending Vendor",
            "before": {"tier": "standard"},
            "after": {"tier": "critical"},
        }
    ]
    assert "resource_id" not in json.dumps(pending["derived_impact"])

    scoped_reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    async with client_factory(user=scoped_reviewer) as reviewer:
        scoped_detail = await reviewer.get(f"/api/v1/processes/{process.id}")
    assert scoped_detail.status_code == 200, scoped_detail.text
    scoped_impact = scoped_detail.json()["pending_change"]["derived_impact"]
    assert scoped_impact["processes"][0]["resource_name"] == (
        "F-W4-PENDING — Composite pending projection"
    )
    assert scoped_impact["assets"][0]["resource_name"] == "Restricted Asset"
    assert scoped_impact["vendors"][0]["resource_name"] == "Restricted Vendor"
    assert "resource_id" not in json.dumps(scoped_impact)


def _payload(owner: User, department_id: int, **extra):
    return {
        "l0_area": "Operations",
        "l1_process": "Protected creation",
        "process_owner_user_id": owner.id,
        "owning_department_id": department_id,
        "cif_override": "yes",
        "request_reason": "Create independently reviewed Process",
        **extra,
    }


@pytest.mark.asyncio
async def test_protected_creation_has_no_operational_identity_until_approval(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    test_user_employee: User,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
        duplicate = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
        requester_list = await requester.get("/api/v1/processes")

    assert submitted.status_code == 202, submitted.text
    assert duplicate.status_code == 409, duplicate.text
    approval_id = submitted.json()["approval_id"]
    approval = await db_session.get(ApprovalRequest, approval_id)
    assert approval is not None
    assert approval.action_type == ApprovalActionType.CREATE
    assert approval.resource_id is None
    proposal = (
        await db_session.execute(
            select(GovernedMutationProposal).where(
                GovernedMutationProposal.approval_request_id == approval_id
            )
        )
    ).scalar_one()
    assert proposal.mutation_kind == "process.create"
    assert proposal.primary_resource_id is None
    assert proposal.impacted_resources_snapshot == []
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0
    assert (
        await db_session.scalar(
            select(func.count()).select_from(GovernedMutationImpactLock)
        )
        == 0
    )

    pending = requester_list.json()["pending_creations"]
    assert requester_list.json()["items"] == []
    assert requester_list.json()["total"] == 0
    assert len(pending) == 1
    assert pending[0]["approval_id"] == approval_id
    assert pending[0]["proposed"]["process_owner"] == test_user_cro.name
    assert "process_owner_user_id" not in pending[0]["proposed"]
    assert pending[0]["capabilities"]["can_cancel"] is True
    assert pending[0]["capabilities"]["is_requester"] is True
    assert pending[0]["capabilities"]["can_resolve"] is False

    async with client_factory(user=test_user_employee) as other:
        hidden = await other.get("/api/v1/processes")
    assert hidden.json()["pending_creations"] == []

    async with client_factory(user=test_user_risk_manager) as approver:
        visible = await approver.get("/api/v1/processes")
        approved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Approved protected creation"},
        )
    assert [row["approval_id"] for row in visible.json()["pending_creations"]] == [
        approval_id
    ]
    assert (
        visible.json()["pending_creations"][0]["capabilities"]["is_requester"] is False
    )
    assert visible.json()["pending_creations"][0]["capabilities"]["can_resolve"] is True
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    created = (await db_session.execute(select(Process))).scalar_one()
    assert created.f_code == f"F{created.id}"
    assert created.l1_process == "Protected creation"


@pytest.mark.asyncio
async def test_pending_process_creations_follow_the_collection_department_scope(
    client_factory,
    db_session: AsyncSession,
    test_department: Department,
    test_user_cro: User,
    test_user_risk_manager: User,
):
    await _scenario(db_session)
    other_department = Department(
        name="Other proposed Process department",
        code="OTHER-PROCESS",
        description="Second proposed owning department",
    )
    db_session.add(other_department)
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        first = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="First scoped pending creation",
            ),
        )
        second = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                other_department.id,
                l1_process="Second scoped pending creation",
            ),
        )
        requester_scoped = await requester.get(
            "/api/v1/processes",
            params={"filters": json.dumps({"department_ids": [test_department.id]})},
        )

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    assert requester_scoped.status_code == 200, requester_scoped.text
    assert [
        row["approval_id"] for row in requester_scoped.json()["pending_creations"]
    ] == [first.json()["approval_id"]]

    async with client_factory(user=test_user_risk_manager) as approver:
        approver_scoped = await approver.get(
            "/api/v1/processes",
            params={"filters": json.dumps({"department_ids": [other_department.id]})},
        )
        approver_unscoped = await approver.get("/api/v1/processes")

    assert approver_scoped.status_code == 200, approver_scoped.text
    assert [
        row["approval_id"] for row in approver_scoped.json()["pending_creations"]
    ] == [second.json()["approval_id"]]
    assert {
        row["approval_id"] for row in approver_unscoped.json()["pending_creations"]
    } == {first.json()["approval_id"], second.json()["approval_id"]}


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["safe_snapshot", "proposed_payload"])
async def test_creation_resolution_expires_snapshot_or_payload_corruption(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    corruption: str,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
    approval_id = submitted.json()["approval_id"]
    proposal = (
        await db_session.execute(
            select(GovernedMutationProposal).where(
                GovernedMutationProposal.approval_request_id == approval_id
            )
        )
    ).scalar_one()
    values = (
        {"after_snapshot": {**proposal.after_snapshot, "l1_process": "Tampered label"}}
        if corruption == "safe_snapshot"
        else {
            "proposed_changes": {
                "after": {
                    **proposal.proposed_changes["after"],
                    "notes": "non-canonical",
                }
            }
        }
    )
    await db_session.execute(
        update(GovernedMutationProposal)
        .where(GovernedMutationProposal.id == proposal.id)
        .values(**values)
    )
    await db_session.commit()

    async with client_factory(user=test_user_risk_manager) as approver:
        resolved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Corruption must fail closed"},
        )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0


@pytest.mark.asyncio
async def test_scoped_configured_reviewer_can_see_and_resolve_protected_creation(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_employee: User,
):
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    async with client_factory(user=test_user_employee) as unrelated:
        unrelated_queue = await unrelated.get("/api/v1/approvals/my-approvals")
        unrelated_detail = await unrelated.get(f"/api/v1/approvals/{approval_id}")
    assert unrelated_queue.json()["items"] == []
    assert unrelated_detail.status_code == 403

    async with client_factory(user=reviewer) as scoped:
        queue = await scoped.get("/api/v1/approvals/my-approvals")
        detail = await scoped.get(f"/api/v1/approvals/{approval_id}")
        approved = await scoped.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Scoped Process visibility reviewed"},
        )
    assert [item["id"] for item in queue.json()["items"]] == [approval_id]
    assert detail.status_code == 200, detail.text
    assert detail.json()["capabilities"]["can_approve"] is True
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"


@pytest.mark.asyncio
async def test_fresh_reload_preserves_valid_classifier_and_scoped_queue(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
) -> None:
    """Persisted SQLite timestamps remain valid strict-envelope evidence."""
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    reviewer_id = reviewer.id
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Fresh classifier reload",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    db_session.expire_all()
    assert await valid_extended_process_approval_ids(
        db_session,
        approval_ids=(approval_id,),
    ) == frozenset({approval_id})

    async with client_factory(headers={"X-Mock-User-Id": str(reviewer_id)}) as scoped:
        queue = await scoped.get("/api/v1/approvals/my-approvals")

    assert queue.status_code == 200, queue.text
    assert [item["id"] for item in queue.json()["items"]] == [approval_id]
    created_at = datetime.fromisoformat(
        queue.json()["items"][0]["created_at"].replace("Z", "+00:00")
    )
    assert created_at.tzinfo is not None
    assert created_at.utcoffset() is not None


@pytest.mark.asyncio
async def test_fresh_reload_preserves_scoped_creation_resolution(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
) -> None:
    """A fresh strict-envelope reload must not turn a valid resolve into 500."""
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    reviewer_id = reviewer.id
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Fresh resolution reload",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    db_session.expire_all()
    async with client_factory(headers={"X-Mock-User-Id": str(reviewer_id)}) as scoped:
        resolved = await scoped.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Approve after a fresh reload"},
        )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "approved"
    resolved_at = datetime.fromisoformat(
        resolved.json()["resolved_at"].replace("Z", "+00:00")
    )
    assert resolved_at.tzinfo is not None
    assert resolved_at.utcoffset() is not None
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 1


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_fresh_reload_preserves_scoped_queue_and_resolution(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
) -> None:
    """The authoritative PostgreSQL lane exercises the same strict boundary."""
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL timestamp round-trip coverage")
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    reviewer_id = reviewer.id
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="PostgreSQL timestamp reload",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    db_session.expire_all()
    assert await valid_extended_process_approval_ids(
        db_session,
        approval_ids=(approval_id,),
    ) == frozenset({approval_id})
    async with client_factory(headers={"X-Mock-User-Id": str(reviewer_id)}) as scoped:
        queue = await scoped.get("/api/v1/approvals/my-approvals")
        resolved = await scoped.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Approve PostgreSQL timestamp evidence"},
        )

    assert queue.status_code == 200, queue.text
    assert [item["id"] for item in queue.json()["items"]] == [approval_id]
    assert (
        datetime.fromisoformat(
            queue.json()["items"][0]["created_at"].replace("Z", "+00:00")
        ).utcoffset()
        is not None
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "approved"
    assert (
        datetime.fromisoformat(
            resolved.json()["resolved_at"].replace("Z", "+00:00")
        ).utcoffset()
        is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("timestamp_owner", ["approval", "proposal"])
async def test_strict_extended_identity_rejects_malformed_created_timestamp(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    timestamp_owner: str,
) -> None:
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process=f"Malformed {timestamp_owner} timestamp",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    proposal = await db_session.scalar(
        select(GovernedMutationProposal)
        .options(selectinload(GovernedMutationProposal.approval_request))
        .where(
            GovernedMutationProposal.approval_request_id
            == submitted.json()["approval_id"]
        )
    )
    assert proposal is not None
    target = proposal.approval_request if timestamp_owner == "approval" else proposal
    target.created_at = "2026-07-18T12:00:00Z"  # type: ignore[assignment]

    with pytest.raises(
        ValueError,
        match="Malformed extended governed Process",
    ):
        strict_extended_process_identity(proposal)


@pytest.mark.asyncio
async def test_extended_process_parser_totalizes_deep_json_before_semantic_descent(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Bounded parser topology",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    proposal = await db_session.scalar(
        select(GovernedMutationProposal)
        .options(selectinload(GovernedMutationProposal.approval_request))
        .where(
            GovernedMutationProposal.approval_request_id
            == submitted.json()["approval_id"]
        )
    )
    assert proposal is not None
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(2_000):
        nested: dict[str, object] = {}
        cursor["nested"] = nested
        cursor = nested
    proposal.proposed_changes = {"after": deep}

    with pytest.raises(
        ValueError,
        match="Malformed extended governed Process identity",
    ):
        strict_extended_process_identity(proposal)


@pytest.mark.asyncio
async def test_strict_extended_identity_rejects_inverted_terminal_timestamps(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Inverted terminal timestamp",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    proposal = await db_session.scalar(
        select(GovernedMutationProposal)
        .options(selectinload(GovernedMutationProposal.approval_request))
        .where(
            GovernedMutationProposal.approval_request_id
            == submitted.json()["approval_id"]
        )
    )
    assert proposal is not None
    approval = proposal.approval_request
    approval.status = ApprovalStatus.APPROVED
    approval.resolved_by_id = test_user_risk_manager.id
    approval.resolved_at = approval.created_at - timedelta(seconds=1)
    approval.resolution_notes = "Invalid chronology"

    with pytest.raises(
        ValueError,
        match="Malformed extended governed Process approval envelope",
    ):
        strict_extended_process_identity(proposal)


@pytest.mark.asyncio
async def test_scoped_configured_reviewer_can_see_and_resolve_protected_archive(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
):
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    process = Process(
        f_code="F9050",
        l0_area="Operations",
        l1_process="Scoped archive",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    db_session.add(process)
    await db_session.commit()
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.request(
            "DELETE",
            f"/api/v1/processes/{process.id}",
            json={"request_reason": "Scoped archive review"},
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    async with client_factory(user=reviewer) as scoped:
        queue = await scoped.get("/api/v1/approvals/my-approvals")
        detail = await scoped.get(f"/api/v1/approvals/{approval_id}")
        approved = await scoped.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Scoped archive approved"},
        )
    assert [item["id"] for item in queue.json()["items"]] == [approval_id]
    assert detail.json()["capabilities"]["can_approve"] is True
    assert approved.status_code == 200, approved.text
    await db_session.refresh(process)
    assert process.is_archived is True


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_process_asset_resolution_waits_for_asset_before_parameters(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    """Process Composite resolution cannot invert Asset -> parameter intake locks."""
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL Process/Asset lock ordering is authoritative")
    process = Process(
        f_code="F9062A",
        l0_area="Operations",
        l1_process="Composite Asset lock race",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Composite lock-race Asset",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        preliminary_criticality="critical",
    )
    db_session.add_all([process, asset])
    await db_session.commit()
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Canonical Composite lock order",
            },
        )
    assert submitted.status_code == 202, submitted.text

    from app.services._governed_mutations import resolution_lock_plan
    from app.services._ict_register_reference.parameters import (
        load_ict_workbook_parameter_set_for_update,
    )

    session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '3s'"))
            yield session

    asset_locked = asyncio.Event()
    resolution_asset_attempted = asyncio.Event()
    original_asset_lock = resolution_lock_plan.lock_governed_assets_for_resolution

    async def observed_asset_lock(*args, **kwargs):
        resolution_asset_attempted.set()
        return await original_asset_lock(*args, **kwargs)

    monkeypatch.setattr(
        resolution_lock_plan,
        "lock_governed_assets_for_resolution",
        observed_asset_lock,
    )

    async def asset_then_parameters() -> None:
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '3s'"))
            locked = await session.scalar(
                select(Asset).where(Asset.id == asset.id).with_for_update()
            )
            assert locked is not None
            asset_locked.set()
            await asyncio.wait_for(resolution_asset_attempted.wait(), timeout=5)
            await load_ict_workbook_parameter_set_for_update(session)
            await session.commit()

    async with client_factory(
        user=test_user_risk_manager,
        db_override=independent_db_session,
    ) as approver:
        holder = asyncio.create_task(
            asset_then_parameters(), name="asset-then-parameters"
        )
        await asyncio.wait_for(asset_locked.wait(), timeout=5)
        resolution = asyncio.create_task(
            approver.post(
                f"/api/v1/approvals/{submitted.json()['approval_id']}/approve",
                json={"resolution_notes": "Canonical Composite order approved"},
            ),
            name="composite-resolution",
        )
        _, result = await asyncio.wait_for(
            asyncio.gather(holder, resolution),
            timeout=10,
        )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "approved"


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_generic_edit_and_archive_resolutions_share_lock_order(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL cross-kind lock ordering is authoritative")
    edit_process, archive_process = [
        Process(
            f_code=f"F906{index}",
            l0_area="Operations",
            l1_process=label,
            process_owner_user_id=test_user_cro.id,
            owning_department_id=test_user_cro.department_id,
            cif_override="yes",
        )
        for index, label in enumerate(
            ("Concurrent edit", "Concurrent archive"), start=1
        )
    ]
    db_session.add_all([edit_process, archive_process])
    await db_session.commit()
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        edit = await requester.patch(
            f"/api/v1/processes/{edit_process.id}",
            json={
                "notes": "Approved concurrently",
                "request_reason": "Cross-kind edit",
            },
        )
        archive = await requester.request(
            "DELETE",
            f"/api/v1/processes/{archive_process.id}",
            json={"request_reason": "Cross-kind archive"},
        )
    assert edit.status_code == 202, edit.text
    assert archive.status_code == 202, archive.text

    session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '2s'"))
            yield session

    async with (
        client_factory(
            user=test_user_risk_manager, db_override=independent_db_session
        ) as edit_approver,
        client_factory(
            user=test_user_risk_manager, db_override=independent_db_session
        ) as archive_approver,
    ):
        edit_result, archive_result = await asyncio.wait_for(
            asyncio.gather(
                edit_approver.post(
                    f"/api/v1/approvals/{edit.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent edit approved"},
                ),
                archive_approver.post(
                    f"/api/v1/approvals/{archive.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent archive approved"},
                ),
            ),
            timeout=5,
        )
    assert edit_result.status_code == 200, edit_result.text
    assert archive_result.status_code == 200, archive_result.text
    assert edit_result.json()["status"] == "approved"
    assert archive_result.json()["status"] == "approved"


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_generic_edit_and_creation_lock_department_first(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL Department row-lock ordering is authoritative")
    process = Process(
        f_code="F9063",
        l0_area="Operations",
        l1_process="Department-order edit",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_department.id,
        cif_override="yes",
    )
    db_session.add(process)
    await db_session.commit()
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        edit = await requester.patch(
            f"/api/v1/processes/{process.id}",
            json={
                "notes": "Department lock order",
                "request_reason": "Concurrent edit",
            },
        )
        creation = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Concurrent creation lock order",
                request_reason="Concurrent creation",
            ),
        )
    assert edit.status_code == 202, edit.text
    assert creation.status_code == 202, creation.text

    session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '2s'"))
            yield session

    async with (
        client_factory(
            user=test_user_risk_manager, db_override=independent_db_session
        ) as edit_approver,
        client_factory(
            user=test_user_risk_manager, db_override=independent_db_session
        ) as create_approver,
    ):
        edit_result, create_result = await asyncio.wait_for(
            asyncio.gather(
                edit_approver.post(
                    f"/api/v1/approvals/{edit.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent edit approved"},
                ),
                create_approver.post(
                    f"/api/v1/approvals/{creation.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent creation approved"},
                ),
            ),
            timeout=5,
        )
    assert edit_result.status_code == 200, edit_result.text
    assert create_result.status_code == 200, create_result.text
    assert edit_result.json()["status"] == "approved"
    assert create_result.json()["status"] == "approved"


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_malformed_expiry_serializes_after_parameter_before_scenario(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    """A malformed terminal path must not invert parameter -> scenario locks."""
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL forced row-lock ordering is authoritative")
    parameter_key = "ict_register_verze"
    parameter = await db_session.scalar(
        select(GlobalConfig).where(GlobalConfig.key == parameter_key)
    )
    if parameter is None:
        parameter = GlobalConfig(
            key=parameter_key,
            value="1.0",
            value_type="string",
            category="ict_register_parameters",
            display_name="ICT workbook version",
            is_editable=True,
        )
        db_session.add(parameter)
    process = Process(
        f_code="F9064",
        l0_area="Operations",
        l1_process="Malformed canonical lock suffix",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    db_session.add(process)
    await db_session.commit()
    await _scenario(db_session)
    process_id = process.id

    async with client_factory(user=test_user_cro) as requester:
        queued = await requester.request(
            "DELETE",
            f"/api/v1/processes/{process_id}",
            json={"request_reason": "Force malformed lock ordering"},
        )
    assert queued.status_code == 202, queued.text
    approval_id = queued.json()["approval_id"]
    await db_session.execute(
        update(ApprovalRequest)
        .where(ApprovalRequest.id == approval_id)
        .values(reason="   ")
    )
    await db_session.commit()

    from app.services._governed_mutations import resolution_lock_plan
    from app.services._governed_mutations.fixed_policy import (
        load_fixed_process_scenario_for_update,
    )

    session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '3s'"))
            yield session

    parameter_locked = asyncio.Event()
    resolution_reached_parameters = asyncio.Event()
    original_parameter_lock = (
        resolution_lock_plan.load_ict_workbook_parameter_set_for_update
    )

    async def observed_parameter_lock(*args, **kwargs):
        resolution_reached_parameters.set()
        return await original_parameter_lock(*args, **kwargs)

    monkeypatch.setattr(
        resolution_lock_plan,
        "load_ict_workbook_parameter_set_for_update",
        observed_parameter_lock,
    )

    async def update_parameter_then_scenario() -> None:
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '3s'"))
            locked_parameter = await session.scalar(
                select(GlobalConfig)
                .where(GlobalConfig.key == parameter_key)
                .with_for_update()
            )
            assert locked_parameter is not None
            parameter_locked.set()
            await asyncio.wait_for(resolution_reached_parameters.wait(), timeout=5)
            scenario = await load_fixed_process_scenario_for_update(session)
            scenario.description = "Scenario updated in canonical parameter-first order"
            await session.commit()

    async with client_factory(
        user=test_user_risk_manager,
        db_override=independent_db_session,
    ) as approver:
        config_task = asyncio.create_task(
            update_parameter_then_scenario(), name="parameter-scenario-update"
        )
        await asyncio.wait_for(parameter_locked.wait(), timeout=5)
        resolution_task = asyncio.create_task(
            approver.post(
                f"/api/v1/approvals/{approval_id}/approve",
                json={"resolution_notes": "Expire malformed envelope"},
            ),
            name="malformed-resolution",
        )
        config_result, resolution = await asyncio.wait_for(
            asyncio.gather(config_task, resolution_task),
            timeout=10,
        )
    assert config_result is None
    assert resolution.status_code == 200, resolution.text
    assert resolution.json()["status"] == "expired"
    db_session.expire_all()
    unchanged = await db_session.get(Process, process_id)
    approval = await db_session.get(ApprovalRequest, approval_id)
    assert unchanged is not None and unchanged.is_archived is False
    assert unchanged.governance_version == 1
    assert approval is not None and approval.status == ApprovalStatus.EXPIRED


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_identical_rowless_creations_serialize_to_one_pending_proposal(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    """Two independent intake transactions cannot both pass the rowless check."""
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL Process-owner advisory locks are authoritative")
    del test_user_risk_manager  # fixture guarantees an independent configured reviewer
    await _scenario(db_session)

    from app.services._governed_mutations import process_mutations
    from app.services._ict_register_lifecycle import policy as process_policy

    session_maker = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '3s'"))
            yield session

    first_checked = asyncio.Event()
    release_first = asyncio.Event()
    second_lock_attempted = asyncio.Event()
    original_duplicate_check = process_mutations._assert_no_duplicate_creation
    original_owner_lock = process_policy.acquire_process_owner_identity_lock
    check_calls = 0
    owner_lock_attempts = 0

    async def observed_owner_lock(*args, **kwargs):
        nonlocal owner_lock_attempts
        owner_lock_attempts += 1
        if owner_lock_attempts == 2:
            second_lock_attempted.set()
        return await original_owner_lock(*args, **kwargs)

    async def paused_first_duplicate_check(*args, **kwargs):
        nonlocal check_calls
        await original_duplicate_check(*args, **kwargs)
        check_calls += 1
        if check_calls == 1:
            first_checked.set()
            await release_first.wait()

    monkeypatch.setattr(
        process_mutations,
        "_assert_no_duplicate_creation",
        paused_first_duplicate_check,
    )
    monkeypatch.setattr(
        process_policy,
        "acquire_process_owner_identity_lock",
        observed_owner_lock,
    )
    payload = _payload(
        test_user_cro,
        test_department.id,
        l1_process="Concurrent identical rowless creation",
    )
    async with (
        client_factory(
            user=test_user_cro, db_override=independent_db_session
        ) as first_client,
        client_factory(
            user=test_user_cro, db_override=independent_db_session
        ) as second_client,
    ):
        first = asyncio.create_task(
            first_client.post("/api/v1/processes", json=payload)
        )
        first_checked_wait = asyncio.create_task(first_checked.wait())
        completed, _ = await asyncio.wait(
            {first, first_checked_wait},
            timeout=5,
            return_when=asyncio.FIRST_COMPLETED,
        )
        assert first_checked_wait in completed, (
            f"first request terminated before the duplicate-check barrier: "
            f"{first.result().status_code} {first.result().text}"
            if first in completed
            else "first request did not reach the duplicate-check barrier"
        )
        second = asyncio.create_task(
            second_client.post("/api/v1/processes", json=payload)
        )
        await asyncio.wait_for(second_lock_attempted.wait(), timeout=5)
        assert owner_lock_attempts == 2
        assert not second.done()
        assert check_calls == 1
        release_first.set()
        first_result, second_result = await asyncio.wait_for(
            asyncio.gather(first, second),
            timeout=10,
        )

    assert first_result.status_code == 202, first_result.text
    assert second_result.status_code == 409, second_result.text
    assert second_result.json()["detail"]["code"] == "process_pending_mutation"
    approvals = list(
        (
            await db_session.execute(
                select(ApprovalRequest).where(
                    ApprovalRequest.resource_type == "process",
                    ApprovalRequest.resource_name
                    == "Concurrent identical rowless creation",
                    ApprovalRequest.status == ApprovalStatus.PENDING,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(approvals) == 1
    proposals = list(
        (
            await db_session.execute(
                select(GovernedMutationProposal).where(
                    GovernedMutationProposal.approval_request_id == approvals[0].id,
                    GovernedMutationProposal.mutation_kind == "process.create",
                    GovernedMutationProposal.primary_resource_id.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(proposals) == 1
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0
    assert (
        await db_session.scalar(
            select(func.count()).select_from(GovernedMutationImpactLock)
        )
        == 0
    )


@pytest.mark.asyncio
async def test_scoped_configured_reviewer_can_see_and_resolve_protected_link(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
):
    reviewer = await _scoped_cro_reviewer(db_session, test_user_cro)
    process = Process(
        f_code="F9051",
        l0_area="Operations",
        l1_process="Scoped link",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Scoped platform",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    hidden_department = Department(
        name="Hidden relationship scope",
        code="HRS",
        is_active=True,
    )
    db_session.add(hidden_department)
    await db_session.flush()
    hidden_process = Process(
        f_code="F9050",
        l0_area="Operations",
        l1_process="Hidden old primary",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=hidden_department.id,
        cif_override="yes",
    )
    asset.owning_department_id = hidden_department.id
    db_session.add_all([process, hidden_process, asset])
    await db_session.flush()
    db_session.add(
        ProcessAssetLink(
            process_id=hidden_process.id,
            asset_id=asset.id,
            is_primary=True,
        )
    )
    await db_session.commit()
    await _scenario(db_session)

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "is_primary": True,
                "request_reason": "Scoped link review",
            },
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    async with client_factory(user=reviewer) as scoped:
        queue = await scoped.get("/api/v1/approvals/my-approvals")
        detail = await scoped.get(f"/api/v1/approvals/{approval_id}")
        process_detail = await scoped.get(f"/api/v1/processes/{process.id}")
        approved = await scoped.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Scoped link approved"},
        )
    assert [item["id"] for item in queue.json()["items"]] == [approval_id]
    assert detail.json()["capabilities"]["can_approve"] is True
    governed = detail.json()["governed_mutation"]
    assert governed["relationship_change"]["target_resource_name"] == "Restricted Asset"
    impacted_names = [item["resource_name"] for item in governed["impacted_resources"]]
    assert f"{process.f_code} — {process.l1_process}" in impacted_names
    assert "Restricted Process" in impacted_names
    derived_names = [
        item["resource_name"] for item in governed["derived_impact"]["processes"]
    ]
    assert f"{process.f_code} — {process.l1_process}" in derived_names
    assert "Restricted Process" in derived_names
    assert hidden_process.l1_process not in detail.text
    assert asset.name not in detail.text
    assert process_detail.status_code == 200, process_detail.text
    pending_derived = process_detail.json()["pending_change"]["derived_impact"][
        "processes"
    ]
    assert [row["resource_name"] for row in pending_derived] == [
        f"{process.f_code} — {process.l1_process}",
        "Restricted Process",
    ]
    assert all("resource_id" not in row for row in pending_derived)
    assert hidden_process.l1_process not in process_detail.text
    assert asset.name not in process_detail.text
    assert (
        process_detail.json()["pending_change"]["capabilities"]["can_cancel"] is False
    )
    assert process_detail.json()["capabilities"]["has_pending_change"] is True
    assert process_detail.json()["capabilities"]["business_edit_blocked"] is True
    assert process_detail.json()["capabilities"]["can_cancel_pending_change"] is False
    assert approved.status_code == 200, approved.text


@pytest.mark.asyncio
async def test_process_asset_link_uses_asset_policy_when_process_policy_is_disabled(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    del test_user_risk_manager
    process = Process(
        f_code="F9051A",
        l0_area="Operations",
        l1_process="Non-CIF Asset-only link",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="no",
    )
    asset = Asset(
        name="Asset-only protected link",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        preliminary_criticality="critical",
    )
    db_session.add_all([process, asset])
    await db_session.commit()
    await _scenario(db_session)
    process_scenario = await db_session.scalar(
        select(ApprovalScenario).where(ApprovalScenario.key == "protected_process_edit")
    )
    assert process_scenario is not None
    process_scenario.requires_approval = False
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Asset-only policy must govern",
            },
        )

    assert submitted.status_code == 202, submitted.text
    approval = await db_session.get(ApprovalRequest, submitted.json()["approval_id"])
    assert approval is not None
    assert approval.scenario_key == "protected_asset_edit"
    proposal = approval.governed_mutation_proposal
    assert proposal is not None
    assert proposal.proposed_changes["triggered_scenarios"] == ["protected_asset_edit"]


@pytest.mark.asyncio
async def test_protected_archive_preserves_live_row_until_approval(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        created_request = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
    async with client_factory(user=test_user_risk_manager) as approver:
        await approver.post(
            f"/api/v1/approvals/{created_request.json()['approval_id']}/approve",
            json={"resolution_notes": "Approve setup creation"},
        )
    process = (await db_session.execute(select(Process))).scalar_one()

    async with client_factory(user=test_user_cro) as requester:
        queued = await requester.request(
            "DELETE",
            f"/api/v1/processes/{process.id}",
            json={"request_reason": "Retire approved Process"},
        )
        pending_detail = await requester.get(f"/api/v1/processes/{process.id}")
    assert queued.status_code == 202, queued.text
    assert pending_detail.status_code == 200, pending_detail.text
    pending = pending_detail.json()["pending_change"]
    assert pending["approval_id"] == queued.json()["approval_id"]
    assert pending["before"] == {"is_archived": False}
    assert pending["after"] == {"is_archived": True}
    assert pending["derived_impact"] == {
        "before": {"cif": "yes", "criticality_class": None},
        "after": {"cif": "yes", "criticality_class": None},
    }
    assert pending["capabilities"] == {"can_view_diff": True, "can_cancel": True}
    assert pending_detail.json()["capabilities"]["has_pending_change"] is True
    assert pending_detail.json()["capabilities"]["business_edit_blocked"] is True
    assert pending_detail.json()["capabilities"]["can_cancel_pending_change"] is True
    assert pending_detail.json()["capabilities"]["can_update"] is False
    assert pending_detail.json()["capabilities"]["can_archive"] is False
    await db_session.refresh(process)
    assert process.is_archived is False
    assert process.governance_version == 1

    async with client_factory(user=test_user_risk_manager) as approver:
        approved = await approver.post(
            f"/api/v1/approvals/{queued.json()['approval_id']}/approve",
            json={"resolution_notes": "Approve retirement"},
        )
    assert approved.status_code == 200, approved.text
    await db_session.refresh(process)
    assert process.is_archived is True
    assert process.governance_version == 2
    approval = await db_session.get(ApprovalRequest, queued.json()["approval_id"])
    assert approval is not None and approval.status == ApprovalStatus.APPROVED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("terminal_action", "expected_status", "event_type"),
    [
        ("cancel", ApprovalStatus.CANCELLED, "approval.request_cancelled"),
        ("reject", ApprovalStatus.REJECTED, "approval.request_resolved"),
    ],
)
async def test_protected_archive_terminal_without_approval_preserves_row_and_releases_lock(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    terminal_action: str,
    expected_status: ApprovalStatus,
    event_type: str,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        creation = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
    async with client_factory(user=test_user_risk_manager) as approver:
        await approver.post(
            f"/api/v1/approvals/{creation.json()['approval_id']}/approve",
            json={"resolution_notes": "Approve setup creation"},
        )
    process = (await db_session.execute(select(Process))).scalar_one()
    async with client_factory(user=test_user_cro) as requester:
        queued = await requester.request(
            "DELETE",
            f"/api/v1/processes/{process.id}",
            json={"request_reason": "Exercise terminal proposal behavior"},
        )
    approval_id = queued.json()["approval_id"]
    async with client_factory(user=test_user_cro) as requester:
        pending_detail = await requester.get(f"/api/v1/processes/{process.id}")
    assert pending_detail.status_code == 200, pending_detail.text
    assert pending_detail.json()["pending_change"]["approval_id"] == approval_id
    assert pending_detail.json()["pending_change"]["capabilities"]["can_cancel"] is True
    assert pending_detail.json()["capabilities"]["can_cancel_pending_change"] is True
    if terminal_action == "cancel":
        async with client_factory(user=test_user_cro) as actor:
            terminal = await actor.post(f"/api/v1/approvals/{approval_id}/cancel")
    else:
        async with client_factory(user=test_user_risk_manager) as actor:
            terminal = await actor.post(
                f"/api/v1/approvals/{approval_id}/reject",
                json={"resolution_notes": "Reject retirement"},
            )

    async with client_factory(user=test_user_cro) as requester:
        released_detail = await requester.get(f"/api/v1/processes/{process.id}")

    assert terminal.status_code == 200, terminal.text
    assert released_detail.status_code == 200, released_detail.text
    assert released_detail.json()["pending_change"] is None
    assert released_detail.json()["capabilities"]["has_pending_change"] is False
    assert released_detail.json()["capabilities"]["business_edit_blocked"] is False
    assert released_detail.json()["capabilities"]["can_cancel_pending_change"] is False
    await db_session.refresh(process)
    approval = await db_session.get(ApprovalRequest, approval_id)
    lock = await db_session.scalar(
        select(GovernedMutationImpactLock).where(
            GovernedMutationImpactLock.proposal_id
            == select(GovernedMutationProposal.id)
            .where(GovernedMutationProposal.approval_request_id == approval_id)
            .scalar_subquery()
        )
    )
    assert process.is_archived is False
    assert process.governance_version == 1
    assert approval is not None and approval.status == expected_status
    assert lock is not None and lock.released_at is not None
    assert lock.release_reason == expected_status.value.lower()
    assert (
        await db_session.scalar(
            select(OutboxEvent.id).where(
                OutboxEvent.event_type == event_type,
                OutboxEvent.aggregate_id == approval_id,
            )
        )
        is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dialect_lane",
    [
        pytest.param("sqlite", id="sqlite"),
        pytest.param("postgresql", marks=pytest.mark.postgres, id="postgres"),
    ],
)
@pytest.mark.parametrize("terminal_action", ["approve", "reject", "cancel"])
@pytest.mark.parametrize(
    "corruption",
    [
        "proposal_predates_approval",
        "approval_postdates_proposal",
        "blank_reason",
        "pending_privileged_status",
    ],
)
async def test_corrupt_extended_envelope_direct_terminalization_expires_safely(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
    dialect_lane: str,
    terminal_action: str,
    corruption: str,
) -> None:
    if db_session.bind.dialect.name != dialect_lane:
        pytest.skip(f"{dialect_lane} direct-terminalization coverage")
    process = Process(
        f_code="F9054",
        l0_area="Operations",
        l1_process=f"Corrupt envelope {terminal_action} {corruption}",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    db_session.add(process)
    await db_session.commit()
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        queued = await requester.request(
            "DELETE",
            f"/api/v1/processes/{process.id}",
            json={"request_reason": "Exercise corrupt direct terminalization"},
        )
    assert queued.status_code == 202, queued.text
    approval_id = queued.json()["approval_id"]
    approval = await db_session.get(ApprovalRequest, approval_id)
    proposal = await db_session.scalar(
        select(GovernedMutationProposal).where(
            GovernedMutationProposal.approval_request_id == approval_id
        )
    )
    assert approval is not None and proposal is not None
    approval_created_at = approval.created_at
    proposal_created_at = proposal.created_at
    if corruption == "proposal_predates_approval":
        if db_session.bind.dialect.name == "postgresql":
            await db_session.execute(
                text("SET LOCAL session_replication_role = replica")
            )
        await db_session.execute(
            update(GovernedMutationProposal)
            .where(GovernedMutationProposal.id == proposal.id)
            .values(created_at=approval_created_at - timedelta(seconds=1))
        )
        if db_session.bind.dialect.name == "postgresql":
            await db_session.execute(
                text("SET LOCAL session_replication_role = origin")
            )
    elif corruption == "approval_postdates_proposal":
        await db_session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(created_at=proposal_created_at + timedelta(seconds=1))
        )
    elif corruption == "blank_reason":
        await db_session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(reason="   ")
        )
    else:
        await db_session.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(status=ApprovalStatus.PENDING_PRIVILEGED)
        )
    await db_session.commit()
    actor_id = (
        test_user_cro.id if terminal_action == "cancel" else test_user_risk_manager.id
    )
    process_id = process.id
    proposal_id = proposal.id
    db_session.expire_all()

    request_kwargs = (
        {}
        if terminal_action == "cancel"
        else {"json": {"resolution_notes": f"Attempt corrupt {terminal_action}"}}
    )
    async with client_factory(headers={"X-Mock-User-Id": str(actor_id)}) as client:
        terminal = await client.post(
            f"/api/v1/approvals/{approval_id}/{terminal_action}",
            **request_kwargs,
        )

    assert terminal.status_code == 200, terminal.text
    assert terminal.json()["status"] == "expired"
    refreshed_process = await db_session.get(Process, process_id)
    refreshed_approval = await db_session.get(ApprovalRequest, approval_id)
    lock = await db_session.scalar(
        select(GovernedMutationImpactLock).where(
            GovernedMutationImpactLock.proposal_id == proposal_id
        )
    )
    assert refreshed_process is not None
    assert refreshed_process.is_archived is False
    assert refreshed_process.governance_version == 1
    assert refreshed_approval is not None
    assert refreshed_approval.status == ApprovalStatus.EXPIRED
    assert lock is not None and lock.released_at is not None
    assert lock.release_reason == "expired"
    audit_rows = list(
        (
            await db_session.execute(
                select(ActivityLog)
                .where(
                    ActivityLog.entity_type == ActivityEntityType.APPROVAL,
                    ActivityLog.entity_id == approval_id,
                )
                .order_by(ActivityLog.id)
            )
        )
        .scalars()
        .all()
    )
    assert audit_rows[-1].action == ActivityAction.STATUS_CHANGE
    assert audit_rows[-1].changes == {
        "status": {
            "old": (
                "pending_privileged"
                if corruption == "pending_privileged_status"
                else "pending"
            ),
            "new": "expired",
        }
    }
    assert not any(
        row.action
        in {ActivityAction.APPROVE, ActivityAction.REJECT, ActivityAction.CANCEL}
        for row in audit_rows
    )


@pytest.mark.asyncio
async def test_protected_creation_expires_if_requester_becomes_ineligible(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_cro, test_department.id),
        )
    approval_id = submitted.json()["approval_id"]
    test_user_cro.is_active = False
    await db_session.commit()

    async with client_factory(user=test_user_risk_manager) as approver:
        resolved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Must revalidate requester"},
        )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0
    approval = await db_session.get(ApprovalRequest, approval_id)
    assert approval is not None and approval.status == ApprovalStatus.EXPIRED
    assert (
        await db_session.scalar(
            select(OutboxEvent.id).where(
                OutboxEvent.event_type == "approval.request_expired",
                OutboxEvent.aggregate_id == approval_id,
            )
        )
        is not None
    )


@pytest.mark.asyncio
async def test_protected_creation_expires_if_proposed_owner_becomes_platform_admin(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    test_user_employee: User,
    test_user_platform_admin: User,
):
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(test_user_employee, test_department.id),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    test_user_employee.role_id = test_user_platform_admin.role_id
    await db_session.commit()

    async with client_factory(user=test_user_risk_manager) as approver:
        resolved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Owner eligibility must be revalidated"},
        )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"
    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0
    approval = await db_session.get(ApprovalRequest, approval_id)
    assert approval is not None and approval.status == ApprovalStatus.EXPIRED


@pytest.mark.asyncio
async def test_malformed_extended_rows_do_not_consume_pages_counts_or_notifications(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    """The strict parser is the iff membership source on SQLite and Postgres."""
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        valid = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Valid older creation",
            ),
        )
        corrupt = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_cro,
                test_department.id,
                l1_process="Malformed newer creation",
            ),
        )
    assert valid.status_code == 202, valid.text
    assert corrupt.status_code == 202, corrupt.text
    valid_id = valid.json()["approval_id"]
    corrupt_id = corrupt.json()["approval_id"]
    proposal = await db_session.scalar(
        select(GovernedMutationProposal).where(
            GovernedMutationProposal.approval_request_id == corrupt_id
        )
    )
    assert proposal is not None
    if db_session.bind.dialect.name == "postgresql":
        await db_session.execute(text("SET LOCAL session_replication_role = replica"))
    await db_session.execute(
        update(GovernedMutationProposal)
        .where(GovernedMutationProposal.id == proposal.id)
        .values(
            after_snapshot={
                **proposal.after_snapshot,
                "process_owner_user_id": test_user_cro.id,
            }
        )
    )
    if db_session.bind.dialect.name == "postgresql":
        await db_session.execute(text("SET LOCAL session_replication_role = origin"))
    notifications = [
        Notification(
            user_id=test_user_risk_manager.id,
            type=NotificationType.GOVERNED_APPROVAL_ACTION_REQUIRED,
            title=f"Approval {approval_id}",
            message="Governed Process approval",
            resource_type="approval",
            resource_id=approval_id,
            is_read=False,
        )
        for approval_id in (valid_id, corrupt_id)
    ]
    db_session.add_all(notifications)
    await db_session.commit()

    async with client_factory(user=test_user_risk_manager) as reviewer:
        page = await reviewer.get(
            "/api/v1/approvals",
            params={"status": "pending", "skip": 0, "limit": 1},
        )
        pending_count = await reviewer.get("/api/v1/approvals/pending/count")
        corrupt_detail = await reviewer.get(f"/api/v1/approvals/{corrupt_id}")
        inbox = await reviewer.get(
            "/api/v1/notifications",
            params={"skip": 0, "limit": 1},
        )
        unread = await reviewer.get("/api/v1/notifications/unread/count")
        corrupt_read = await reviewer.post(
            f"/api/v1/notifications/{notifications[1].id}/read"
        )
        read_all = await reviewer.post("/api/v1/notifications/read-all")

    assert page.status_code == 200, page.text
    assert page.json()["total"] == 1
    assert [item["id"] for item in page.json()["items"]] == [valid_id]
    assert pending_count.json() == {"count": 1}
    assert corrupt_detail.status_code == 403
    assert inbox.status_code == 200, inbox.text
    assert inbox.json()["total"] == 1
    assert [item["resource_id"] for item in inbox.json()["items"]] == [valid_id]
    assert unread.json() == {"count": 1}
    assert corrupt_read.status_code == 404
    assert read_all.status_code == 204
    await db_session.refresh(notifications[1])
    assert notifications[1].is_read is False


@pytest.mark.postgres
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("deactivation_first", "expected_status"),
    [(True, "expired"), (False, "approved")],
)
async def test_postgres_creation_owner_deactivation_serializes_in_both_orders(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_department,
    test_user: User,
    test_user_cro: User,
    test_user_employee: User,
    test_user_risk_manager: User,
    deactivation_first: bool,
    expected_status: str,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL Process-owner advisory locks are authoritative")
    await _scenario(db_session)
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            "/api/v1/processes",
            json=_payload(
                test_user_employee,
                test_department.id,
                l1_process=f"Owner race {deactivation_first}",
            ),
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]
    owner_id = test_user_employee.id
    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '2s'"))
            yield session

    first_locked = asyncio.Event()
    release_first = asyncio.Event()
    if deactivation_first:
        from app.services import _identity_authority_lock

        original = _identity_authority_lock.acquire_process_owner_identity_lock

        async def paused_deactivation_lock(*args, **kwargs):
            await original(*args, **kwargs)
            first_locked.set()
            await release_first.wait()

        monkeypatch.setattr(
            _identity_authority_lock,
            "acquire_process_owner_identity_lock",
            paused_deactivation_lock,
        )
    else:
        from app.services._governed_mutations import resolution_extensions

        original_many = resolution_extensions.acquire_process_owner_identity_locks

        async def paused_approval_lock(*args, **kwargs):
            await original_many(*args, **kwargs)
            first_locked.set()
            await release_first.wait()

        monkeypatch.setattr(
            resolution_extensions,
            "acquire_process_owner_identity_locks",
            paused_approval_lock,
        )

    async with (
        client_factory(user=test_user, db_override=independent_db_session) as admin,
        client_factory(
            user=test_user_risk_manager,
            db_override=independent_db_session,
        ) as approver,
    ):
        if deactivation_first:
            first = asyncio.create_task(
                admin.patch(f"/api/v1/users/{owner_id}", json={"is_active": False})
            )
        else:
            first = asyncio.create_task(
                approver.post(
                    f"/api/v1/approvals/{approval_id}/approve",
                    json={"resolution_notes": "Approval lock wins"},
                )
            )
        await asyncio.wait_for(first_locked.wait(), timeout=2)
        if deactivation_first:
            second = asyncio.create_task(
                approver.post(
                    f"/api/v1/approvals/{approval_id}/approve",
                    json={"resolution_notes": "Deactivation lock wins"},
                )
            )
        else:
            second = asyncio.create_task(
                admin.patch(f"/api/v1/users/{owner_id}", json={"is_active": False})
            )
        release_first.set()
        first_result, second_result = await asyncio.wait_for(
            asyncio.gather(first, second),
            timeout=10,
        )
    approval_result = second_result if deactivation_first else first_result
    deactivation_result = first_result if deactivation_first else second_result
    assert approval_result.status_code == 200, approval_result.text
    assert approval_result.json()["status"] == expected_status
    assert deactivation_result.status_code == 200, deactivation_result.text
    async with session_maker() as session:
        created = await session.scalar(
            select(Process).where(
                Process.l1_process == f"Owner race {deactivation_first}"
            )
        )
        if deactivation_first:
            assert created is None
        else:
            assert created is not None
            orphan = await session.scalar(
                select(OrphanedItem.id).where(
                    OrphanedItem.item_type == "process",
                    OrphanedItem.item_id == created.id,
                    OrphanedItem.previous_owner_id == owner_id,
                    OrphanedItem.status == "pending",
                )
            )
            assert orphan is not None
