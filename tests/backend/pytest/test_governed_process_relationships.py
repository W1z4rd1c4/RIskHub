"""Governed Process relationship operation contracts for issue #85."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.exceptions import ValidationError
from app.models import (
    ActivityLog,
    ApprovalActionType,
    ApprovalRequest,
    ApprovalResourceType,
    ApprovalScenario,
    ApprovalStatus,
    Asset,
    AssetVendorLink,
    GovernedMutationImpactLock,
    GovernedMutationProposal,
    OrphanedItem,
    Process,
    ProcessAssetLink,
    ProcessVendorLink,
    Risk,
    RiskProcessLink,
    User,
    Vendor,
)
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.services._governed_mutations.process_mutations import (
    is_extended_process_kind,
    strict_extended_process_identity,
)
from app.services._governed_mutations.process_relationships import (
    apply_process_relationship_operation,
    validate_process_relationship_operation,
)


def _assert_no_raw_relationship_id(changes: dict[str, object] | None) -> None:
    """User-facing Activity Log relationship metadata must use safe labels."""
    assert changes is not None
    assert "target_id" not in changes
    assert "process_id" not in changes
    assert "asset_id" not in changes
    assert "risk_id" not in changes


def _asset_operation(**overrides: object) -> dict[str, object]:
    operation: dict[str, object] = {
        "relationship_type": "asset",
        "action": "add",
        "kind": "process.link.asset.add",
        "process_id": 1,
        "related_resource_id": 2,
        "related_resource_name": "Core platform",
        "before": {},
        "after": {
            "significance": "high",
            "spof": "yes",
            "is_primary": False,
            "note": None,
        },
    }
    operation.update(overrides)
    return operation


def _relationship_proposal(
    *,
    mutation_kind: str,
    operation: dict[str, object],
) -> GovernedMutationProposal:
    created_at = datetime(2026, 7, 18, 12, tzinfo=UTC)
    approval = ApprovalRequest(
        id=1,
        resource_type=ApprovalResourceType.PROCESS,
        resource_id=1,
        resource_name="F1 — Claims",
        action_type=ApprovalActionType.EDIT,
        pending_changes={
            "relationship": {
                "old": operation.get("before"),
                "new": operation.get("after"),
            }
        },
        scenario_key="protected_process_edit",
        scenario_approver_roles=["risk_manager"],
        requested_by_id=7,
        reason="Independent relationship review",
        status=ApprovalStatus.PENDING,
        requires_privileged_approval=False,
        created_at=created_at,
    )
    proposal = GovernedMutationProposal(
        proposal_id="123e4567-e89b-42d3-a456-426614174000",
        proposal_version=1,
        schema_version=1,
        approval_request_id=1,
        mutation_kind=mutation_kind,
        primary_resource_type="process",
        primary_resource_id=1,
        primary_resource_name="F1 — Claims",
        scenario_snapshot={
            "key": "protected_process_edit",
            "requires_approval": True,
            "approver_roles": ["risk_manager"],
            "triggered_policies": [
                {
                    "key": "protected_process_edit",
                    "enabled": True,
                    "policy_version": 1,
                    "configured_roles": ["risk_manager"],
                    "invariants": {
                        "independent": True,
                        "allow_self_approval": False,
                    },
                }
            ],
        },
        base_versions={"process": 1},
        before_snapshot={"relationship": operation.get("before")},
        after_snapshot={"relationship": operation.get("after")},
        derived_impact_snapshot={},
        proposed_changes={"operation": operation},
        impacted_resources_snapshot=[
            {
                "resource_type": "process",
                "resource_id": 1,
                "resource_name": "F1 — Claims",
                "base_governance_version": 1,
            }
        ],
        requested_by_id=7,
        created_at=created_at,
    )
    proposal.approval_request = approval
    return proposal


def test_extended_identity_rejects_unknown_relationship_kind() -> None:
    mutation_kind = "process.link.unknown.execute"
    operation = {
        "kind": mutation_kind,
        "process_id": 1,
        "before": {},
        "after": {},
    }

    assert is_extended_process_kind(mutation_kind) is False
    assert (
        strict_extended_process_identity(
            _relationship_proposal(
                mutation_kind=mutation_kind,
                operation=operation,
            )
        )
        is None
    )


def test_extended_identity_rejects_contradictory_relationship_operation() -> None:
    operation = _asset_operation(
        relationship_type="vendor",
        kind="process.link.asset.add",
        after={"direct_service_description": "Claims platform", "note": None},
    )

    with pytest.raises(ValueError, match="Malformed governed Process relationship"):
        strict_extended_process_identity(
            _relationship_proposal(
                mutation_kind="process.link.asset.add",
                operation=operation,
            )
        )


@pytest.mark.parametrize(
    "override",
    [
        {"process_id": True},
        {"related_resource_id": 2.0},
        {"related_resource_name": "123"},
        {"unknown": "field"},
        {"action": "remove", "link_id": None},
        {
            "relationship_type": "risk",
            "kind": "process.link.risk.add",
            "after": {"note": "leak"},
        },
        {"demoted_process_id": 1, "after": {"is_primary": True}},
    ],
)
def test_relationship_operation_validation_fails_closed(
    override: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        validate_process_relationship_operation(_asset_operation(**override))


@pytest.mark.asyncio
async def test_asset_primary_swap_applies_atomically_and_versions_both_processes(
    db_session: AsyncSession,
    test_user_cro: User,
) -> None:
    old_primary = Process(
        f_code="F9001",
        l0_area="Operations",
        l1_process="Old primary",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    new_primary = Process(
        f_code="F9002",
        l0_area="Operations",
        l1_process="New primary",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    asset = Asset(name="Core platform")
    db_session.add_all([old_primary, new_primary, asset])
    await db_session.flush()
    old_link = ProcessAssetLink(
        process_id=old_primary.id,
        asset_id=asset.id,
        significance="high",
        spof="yes",
        is_primary=True,
        note="Current",
    )
    db_session.add(old_link)
    await db_session.flush()

    changes = await apply_process_relationship_operation(
        db_session,
        process=new_primary,
        operation=_asset_operation(
            process_id=new_primary.id,
            related_resource_id=asset.id,
            demoted_process_id=old_primary.id,
            after={
                "significance": "Kritická podpora procesu",
                "spof": "yes",
                "is_primary": True,
                "note": "Replacement",
            },
        ),
        current_user=test_user_cro,
    )

    links = list(
        (
            await db_session.execute(
                select(ProcessAssetLink)
                .where(ProcessAssetLink.asset_id == asset.id)
                .order_by(ProcessAssetLink.process_id)
            )
        )
        .scalars()
        .all()
    )
    assert [(link.process_id, link.is_primary) for link in links] == [
        (old_primary.id, False),
        (new_primary.id, True),
    ]
    assert old_primary.governance_version == 2
    assert new_primary.governance_version == 2
    assert changes == {"asset_relationship": {"old": None, "new": "Core platform"}}
    domain_audits = list(
        (
            await db_session.execute(
                select(ActivityLog)
                .where(
                    ActivityLog.entity_type == ActivityEntityType.ASSET_LINK,
                    ActivityLog.entity_id == asset.id,
                    ActivityLog.actor_id == test_user_cro.id,
                )
                .order_by(ActivityLog.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(domain_audits) == 2
    promoted_audit, demoted_audit = domain_audits
    assert promoted_audit.action == ActivityAction.CREATE
    assert promoted_audit.changes == {
        "relationship_type": {"old": None, "new": "process"},
        "relationship_target": {"old": None, "new": "F9002 — New primary"},
    }
    assert demoted_audit.action == ActivityAction.UPDATE
    assert demoted_audit.changes == {
        "relationship_type": {"old": "process", "new": "process"},
        "relationship_target": {
            "old": "F9001 — Old primary",
            "new": "F9001 — Old primary",
        },
        "is_primary": {"old": True, "new": False},
        "process_governance_version": {"old": 1, "new": 2},
        "replacement_primary_process": {
            "old": None,
            "new": "F9002 — New primary",
        },
    }
    _assert_no_raw_relationship_id(promoted_audit.changes)
    _assert_no_raw_relationship_id(demoted_audit.changes)


@pytest.mark.asyncio
async def test_governed_risk_and_vendor_audits_project_labels_not_target_ids(
    db_session: AsyncSession,
    test_user_cro: User,
) -> None:
    process = Process(
        f_code="F9003",
        l0_area="Operations",
        l1_process="Safe relationship audit",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    risk = Risk(
        risk_id_code="R-9003",
        name="Service interruption",
        process="Operations",
        description="Safe governed relationship audit",
        owner_id=test_user_cro.id,
        department_id=test_user_cro.department_id,
    )
    vendor = Vendor(
        name="Continuity supplier",
        process="Operations",
        outsourcing_owner_user_id=test_user_cro.id,
        department_id=test_user_cro.department_id,
    )
    db_session.add_all([process, risk, vendor])
    await db_session.flush()

    await apply_process_relationship_operation(
        db_session,
        process=process,
        operation={
            "relationship_type": "risk",
            "action": "add",
            "kind": "process.link.risk.add",
            "process_id": process.id,
            "related_resource_id": risk.id,
            "related_resource_name": "R-9003 — Service interruption",
            "before": {"linked": False},
            "after": {"linked": True},
        },
        current_user=test_user_cro,
    )
    await apply_process_relationship_operation(
        db_session,
        process=process,
        operation={
            "relationship_type": "vendor",
            "action": "add",
            "kind": "process.link.vendor.add",
            "process_id": process.id,
            "related_resource_id": vendor.id,
            "related_resource_name": "Continuity supplier",
            "before": {},
            "after": {"direct_service_description": "Claims platform", "note": None},
        },
        current_user=test_user_cro,
    )

    audits = list(
        (
            await db_session.execute(
                select(ActivityLog)
                .where(
                    ActivityLog.actor_id == test_user_cro.id,
                    ActivityLog.entity_type.in_(
                        (ActivityEntityType.RISK_LINK, ActivityEntityType.PROCESS_LINK)
                    ),
                )
                .order_by(ActivityLog.id)
            )
        )
        .scalars()
        .all()
    )
    assert [audit.changes for audit in audits] == [
        {
            "relationship_type": {"old": None, "new": "process"},
            "relationship_target": {
                "old": None,
                "new": "F9003 — Safe relationship audit",
            },
        },
        {
            "relationship_type": {"old": None, "new": "vendor"},
            "relationship_target": {"old": None, "new": "Continuity supplier"},
        },
    ]
    for audit in audits:
        _assert_no_raw_relationship_id(audit.changes)


@pytest.mark.asyncio
async def test_risk_link_revalidation_rejects_changed_state(
    db_session: AsyncSession,
    test_user_cro: User,
) -> None:
    process = Process(
        f_code="F9010",
        l0_area="Operations",
        l1_process="Claims",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    risk = Risk(
        risk_id_code="R-9010",
        name="Operational interruption",
        process="Claims",
        description="Interruption",
    )
    db_session.add_all([process, risk])
    await db_session.flush()
    link = RiskProcessLink(risk_id=risk.id, process_id=process.id)
    db_session.add(link)
    await db_session.flush()

    with pytest.raises(ValidationError):
        await apply_process_relationship_operation(
            db_session,
            process=process,
            operation={
                "relationship_type": "risk",
                "action": "remove",
                "kind": "process.link.risk.remove",
                "process_id": process.id,
                "related_resource_id": risk.id,
                "related_resource_name": "R-9010 — Operational interruption",
                "link_id": True,
                "before": {"linked": True},
                "after": {"linked": False},
            },
            current_user=test_user_cro,
        )


@pytest.mark.asyncio
async def test_protected_asset_link_stays_pending_until_independent_approval(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
    test_user_employee: User,
) -> None:
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    process = Process(
        f_code="F9020",
        l0_area="Operations",
        l1_process="Policy administration",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Policy platform",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    db_session.add_all([process, asset])
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        missing_reason = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={"process_id": process.id},
        )
        assert missing_reason.status_code == 422, missing_reason.text
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Critical supporting relationship",
            },
        )
        assert submitted.status_code == 202, submitted.text
        approval_id = submitted.json()["approval_id"]
        assert (
            await db_session.scalar(
                select(ProcessAssetLink.id).where(
                    ProcessAssetLink.asset_id == asset.id,
                    ProcessAssetLink.process_id == process.id,
                )
            )
            is None
        )
        await db_session.refresh(process)
        assert process.governance_version == 1

        requester_queue = await requester.get("/api/v1/approvals?status=pending")
        requester_detail = await requester.get(f"/api/v1/approvals/{approval_id}")
        process_detail = await requester.get(f"/api/v1/processes/{process.id}")

    assert requester_queue.status_code == 200, requester_queue.text
    assert [item["id"] for item in requester_queue.json()["items"]] == [approval_id]
    assert requester_detail.status_code == 200, requester_detail.text
    assert process_detail.status_code == 200, process_detail.text
    process_pending = process_detail.json()["pending_change"]
    assert process_pending["approval_id"] == approval_id
    assert process_pending["before"] == {"relationship": {}}
    assert process_pending["after"] == {
        "relationship": {
            "significance": "Kritická podpora procesu",
            "spof": None,
            "is_primary": False,
            "note": None,
        }
    }
    assert process_pending["derived_impact"] == {
        "processes": [
            {
                "resource_name": "F9020 — Policy administration",
                "before": {"cif": "yes", "criticality_class": None},
                "after": {"cif": "yes", "criticality_class": None},
            }
        ],
    }
    assert process_pending["capabilities"] == {
        "can_view_diff": True,
        "can_cancel": True,
    }
    assert process_detail.json()["capabilities"]["has_pending_change"] is True
    assert process_detail.json()["capabilities"]["business_edit_blocked"] is True
    assert process_detail.json()["capabilities"]["can_cancel_pending_change"] is True
    assert process_detail.json()["capabilities"]["can_update"] is False
    requester_body = requester_detail.json()
    assert requester_body["pending_changes"] == {
        "relationship": {
            "old": {},
            "new": {
                "significance": "Kritická podpora procesu",
                "spof": None,
                "is_primary": False,
                "note": None,
            },
        }
    }
    assert requester_body["governed_mutation"]["before"] == {"relationship": {}}
    assert requester_body["governed_mutation"]["after"] == {
        "relationship": requester_body["pending_changes"]["relationship"]["new"]
    }
    assert requester_body["governed_mutation"]["impacted_resources"] == [
        {
            "resource_type": "asset",
            "resource_name": "Policy platform",
        },
        {
            "resource_type": "process",
            "resource_name": "F9020 — Policy administration",
        },
    ]
    assert all(
        "resource_id" not in item
        for item in requester_body["governed_mutation"]["impacted_resources"]
    )
    assert all(
        "resource_id" not in item
        for item in requester_body["governed_mutation"]["derived_impact"]["processes"]
    )
    assert all(
        "resource_id" not in item
        for item in requester_body["governed_mutation"]["derived_impact"]["assets"]
    )
    assert requester_body["governed_mutation"]["derived_impact"]["assets"] == [
        {
            "resource_name": "Policy platform",
            "before": {"cif": "no", "resulting_criticality": None},
            "after": {"cif": "yes", "resulting_criticality": "medium"},
        }
    ]
    assert requester_body["governed_mutation"]["derived_impact"]["processes"] == [
        {
            "resource_name": "F9020 — Policy administration",
            "before": {"cif": "yes", "criticality_class": None},
            "after": {"cif": "yes", "criticality_class": None},
        }
    ]
    assert requester_body["governed_mutation"]["relationship_change"] == {
        "target_resource_type": "asset",
        "target_resource_name": "Policy platform",
        "action": "add",
        "before": {},
        "after": requester_body["pending_changes"]["relationship"]["new"],
    }

    async with client_factory(user=test_user_employee) as unrelated:
        hidden_queue = await unrelated.get("/api/v1/approvals?status=pending")
        hidden_count = await unrelated.get("/api/v1/approvals/pending/count")
        hidden_detail = await unrelated.get(f"/api/v1/approvals/{approval_id}")
    assert hidden_queue.status_code == 200, hidden_queue.text
    assert hidden_queue.json()["total"] == 0
    assert hidden_queue.json()["items"] == []
    assert hidden_count.json() == {"count": 0}
    assert hidden_detail.status_code == 403

    async with client_factory(user=test_user_risk_manager) as approver:
        approver_queue = await approver.get("/api/v1/approvals/my-approvals")
        approver_detail = await approver.get(f"/api/v1/approvals/{approval_id}")
        assert approver_queue.status_code == 200, approver_queue.text
        assert [item["id"] for item in approver_queue.json()["items"]] == [approval_id]
        assert approver_detail.status_code == 200, approver_detail.text
        assert approver_detail.json()["capabilities"]["can_approve"] is True
        approved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Independent relationship review complete"},
        )
        assert approved.status_code == 200, approved.text

    link = await db_session.scalar(
        select(ProcessAssetLink).where(
            ProcessAssetLink.asset_id == asset.id,
            ProcessAssetLink.process_id == process.id,
        )
    )
    await db_session.refresh(process)
    assert link is not None
    assert link.significance == "Kritická podpora procesu"
    assert process.governance_version == 2
    domain_audit = (
        await db_session.execute(
            select(ActivityLog).where(
                ActivityLog.entity_type == ActivityEntityType.ASSET_LINK,
                ActivityLog.action == ActivityAction.CREATE,
                ActivityLog.entity_id == asset.id,
                ActivityLog.actor_id == test_user_risk_manager.id,
            )
        )
    ).scalar_one()
    proposal_audit = (
        await db_session.execute(
            select(ActivityLog).where(
                ActivityLog.entity_type == ActivityEntityType.APPROVAL,
                ActivityLog.action == ActivityAction.APPROVE,
                ActivityLog.entity_id == approval_id,
                ActivityLog.actor_id == test_user_risk_manager.id,
            )
        )
    ).scalar_one()
    assert domain_audit.changes == {
        "relationship_type": {"old": None, "new": "process"},
        "relationship_target": {
            "old": None,
            "new": "F9020 — Policy administration",
        },
    }
    _assert_no_raw_relationship_id(domain_audit.changes)
    assert proposal_audit.changes == {
        "asset_relationship": {"old": None, "new": "[REDACTED]"}
    }


@pytest.mark.asyncio
async def test_all_process_link_rows_project_authoritative_pending_lock_state(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    process = Process(
        f_code="F9029",
        l0_area="Operations",
        l1_process="Locked relationship projection",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Locked projection asset",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    risk = Risk(
        risk_id_code="LOCK-R1",
        name="Locked projection risk",
        process="Operations",
        description="Relationship lock projection",
        department_id=test_user_cro.department_id,
        owner_id=test_user_cro.id,
    )
    vendor = Vendor(
        name="Locked projection vendor",
        process="Operations",
        department_id=test_user_cro.department_id,
        outsourcing_owner_user_id=test_user_cro.id,
    )
    db_session.add_all([process, asset, risk, vendor])
    await db_session.flush()
    db_session.add_all(
        [
            ProcessAssetLink(process_id=process.id, asset_id=asset.id),
            AssetVendorLink(asset_id=asset.id, vendor_id=vendor.id, ict_service_code="S01"),
            RiskProcessLink(process_id=process.id, risk_id=risk.id),
            ProcessVendorLink(process_id=process.id, vendor_id=vendor.id),
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_vendor_edit",
                display_name="Protected Vendor mutation",
                description="Independent approval for protected Vendor mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()

    paths = (
        f"/api/v1/assets/{asset.id}/process-links",
        f"/api/v1/risks/{risk.id}/process-links",
        f"/api/v1/processes/{process.id}/vendor-links",
    )
    async with client_factory(user=test_user_cro) as requester:
        before = [await requester.get(path) for path in paths]
        queued = await requester.request(
            "DELETE",
            f"/api/v1/assets/{asset.id}/process-links/{process.id}",
            json={"request_reason": "Lock all Process relationship controls"},
        )
        after = [await requester.get(path) for path in paths]
        asset_detail = await requester.get(f"/api/v1/assets/{asset.id}")

    assert queued.status_code == 202, queued.text
    assert all(response.status_code == 200 for response in (*before, *after))
    assert asset_detail.status_code == 200, asset_detail.text
    derived_impact = asset_detail.json()["pending_change"]["derived_impact"]
    assert derived_impact["processes"][0]["resource_name"] == (
        "F9029 — Locked relationship projection"
    )
    assert derived_impact["vendors"][0]["resource_name"] == "Locked projection vendor"
    assert "resource_id" not in str(derived_impact)
    assert [
        response.json()[0]["process_business_edit_blocked"] for response in before
    ] == [
        False,
        False,
        False,
    ]
    assert [
        response.json()[0]["process_business_edit_blocked"] for response in after
    ] == [
        True,
        True,
        True,
    ]


@pytest.mark.asyncio
async def test_vendor_link_intake_refreshes_process_authority_after_target_lock(
    client_factory,
    db_session: AsyncSession,
    monkeypatch,
    test_user_employee: User,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    """A stale ORM Process must not preserve ownership-based write authority."""
    process = Process(
        f_code="F929",
        l0_area="Operations",
        l1_process="Vendor intake authority refresh",
        process_owner_user_id=test_user_employee.id,
        owning_department_id=test_user_employee.department_id,
        cif_override="yes",
    )
    vendor = Vendor(
        name="Vendor intake authority refresh",
        process="Operations",
        department_id=test_user_employee.department_id,
        outsourcing_owner_user_id=test_user_cro.id,
    )
    db_session.add_all(
        [
            process,
            vendor,
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()

    from app.services._ict_register_lifecycle import vendor_links

    original_lock = vendor_links.lock_vendor_ordinary_mutation

    async def reassign_process_after_preflight(*args, **kwargs):
        locked_vendor = await original_lock(*args, **kwargs)
        session = args[0] if args else kwargs["db"]
        await session.execute(
            update(Process)
            .where(Process.id == process.id)
            .values(process_owner_user_id=test_user_cro.id)
            .execution_options(synchronize_session=False)
        )
        return locked_vendor

    monkeypatch.setattr(
        vendor_links,
        "lock_vendor_ordinary_mutation",
        reassign_process_after_preflight,
    )

    async with client_factory(user=test_user_employee) as requester:
        response = await requester.post(
            f"/api/v1/processes/{process.id}/vendor-links",
            json={
                "vendor_id": vendor.id,
                "direct_service_description": "Must not be queued with stale authority",
                "request_reason": "Revalidate current Process ownership",
            },
        )

    assert response.status_code == 403, response.text
    assert (
        await db_session.scalar(
            select(ApprovalRequest.id).where(ApprovalRequest.resource_id == process.id)
        )
        is None
    )
    assert (
        await db_session.scalar(
            select(ProcessVendorLink.id).where(
                ProcessVendorLink.process_id == process.id,
                ProcessVendorLink.vendor_id == vendor.id,
            )
        )
        is None
    )


@pytest.mark.asyncio
async def test_protected_risk_process_add_returns_typed_approval_response(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    process = Process(
        f_code="F9030",
        l0_area="Operations",
        l1_process="Risk link response",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    risk = Risk(
        risk_id_code="LOCK-R2",
        name="Typed response risk",
        process="Operations",
        description="Typed 202 response",
        department_id=test_user_cro.department_id,
        owner_id=test_user_cro.id,
    )
    db_session.add_all(
        [
            process,
            risk,
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        response = await requester.post(
            f"/api/v1/risks/{risk.id}/process-links",
            json={
                "process_id": process.id,
                "request_reason": "Independent Risk relationship review",
            },
        )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "approval_required"
    assert body["action_type"] == "edit"
    assert body["approval_id"] > 0
    assert body["proposal_id"]


@pytest.mark.asyncio
async def test_relationship_reference_drift_expires_and_releases_all_locks(
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    process = Process(
        f_code="F9021",
        l0_area="Operations",
        l1_process="Claims administration",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Claims platform",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    db_session.add_all([process, asset])
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Protected relationship review",
            },
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    drifted_link = ProcessAssetLink(
        process_id=process.id,
        asset_id=asset.id,
        significance="medium",
        spof="no",
        is_primary=False,
        note="Concurrent reference drift",
    )
    db_session.add(drifted_link)
    await db_session.commit()

    async with client_factory(user=test_user_risk_manager) as approver:
        resolved = await approver.post(
            f"/api/v1/approvals/{approval_id}/approve",
            json={"resolution_notes": "Revalidate the exact relationship"},
        )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"
    await db_session.refresh(process)
    assert process.governance_version == 1
    links = list(
        (
            await db_session.execute(
                select(ProcessAssetLink).where(ProcessAssetLink.asset_id == asset.id)
            )
        )
        .scalars()
        .all()
    )
    assert [link.id for link in links] == [drifted_link.id]
    active_locks = list(
        (
            await db_session.execute(
                select(GovernedMutationImpactLock).where(
                    GovernedMutationImpactLock.proposal_id
                    == select(GovernedMutationProposal.id)
                    .where(GovernedMutationProposal.approval_request_id == approval_id)
                    .scalar_subquery(),
                    GovernedMutationImpactLock.released_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    assert active_locks == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    [
        "derived_boolean_id",
        "derived_extra_key",
        "derived_bad_cif",
        "descriptor_base_mismatch",
    ],
)
async def test_composite_process_asset_parser_rejects_every_malformed_asset_row_and_expires(
    corruption: str,
    client_factory,
    db_session: AsyncSession,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name == "postgresql":
        pytest.skip("PostgreSQL insert-only trigger forbids corruption fixtures")
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    process = Process(
        f_code=f"F-CORRUPT-{corruption}",
        l0_area="Operations",
        l1_process="Composite parser corruption",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name=f"Composite parser Asset {corruption}",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        preliminary_criticality="low",
    )
    db_session.add_all([process, asset])
    await db_session.commit()
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "request_reason": "Exercise exact composite Asset identity",
            },
        )
    assert submitted.status_code == 202, submitted.text
    proposal = await db_session.scalar(
        select(GovernedMutationProposal).where(
            GovernedMutationProposal.approval_request_id
            == submitted.json()["approval_id"]
        )
    )
    assert proposal is not None
    derived = dict(proposal.derived_impact_snapshot)
    derived["assets"] = [dict(row) for row in derived["assets"]]
    impacts = [dict(row) for row in proposal.impacted_resources_snapshot]
    asset_row = derived["assets"][0]
    if corruption == "derived_boolean_id":
        asset_row["resource_id"] = True
    elif corruption == "derived_extra_key":
        asset_row["unexpected"] = "field"
    elif corruption == "derived_bad_cif":
        asset_row["after"] = {**asset_row["after"], "cif": True}
    else:
        asset_impact = next(row for row in impacts if row["resource_type"] == "asset")
        asset_impact["base_governance_version"] += 1

    proposal.derived_impact_snapshot = derived
    proposal.impacted_resources_snapshot = impacts
    with pytest.raises(ValueError, match="Malformed extended governed Process"):
        strict_extended_process_identity(proposal)

    db_session.expunge(proposal)
    await db_session.execute(
        update(GovernedMutationProposal)
        .where(GovernedMutationProposal.id == proposal.id)
        .values(
            derived_impact_snapshot=derived,
            impacted_resources_snapshot=impacts,
        )
    )
    await db_session.commit()
    async with client_factory(user=test_user_risk_manager) as approver:
        resolved = await approver.post(
            f"/api/v1/approvals/{submitted.json()['approval_id']}/approve",
            json={"resolution_notes": "Malformed composite identity must expire"},
        )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"


@pytest.mark.asyncio
async def test_pending_process_creation_queue_is_private_and_uses_safe_labels(
    client_factory,
    db_session: AsyncSession,
    test_department,
    test_user_cro: User,
    test_user_risk_manager: User,
    test_user_employee: User,
) -> None:
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()
    payload = {
        "l0_area": "Operations",
        "l1_process": "Pending claims workflow",
        "process_owner_user_id": test_user_cro.id,
        "owning_department_id": test_department.id,
        "cif_override": "yes",
        "request_reason": "Independent review before operational creation",
    }

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post("/api/v1/processes", json=payload)
        assert submitted.status_code == 202, submitted.text
        approval_id = submitted.json()["approval_id"]
        requester_queue = await requester.get("/api/v1/approvals?status=pending")
        requester_detail = await requester.get(f"/api/v1/approvals/{approval_id}")
        operational = await requester.get("/api/v1/processes")

    assert await db_session.scalar(select(func.count()).select_from(Process)) == 0
    assert operational.status_code == 200, operational.text
    assert operational.json()["items"] == []
    assert operational.json()["total"] == 0
    assert [item["id"] for item in requester_queue.json()["items"]] == [approval_id]
    body = requester_detail.json()
    assert body["resource_id"] is None
    assert body["resource_name"] == "Pending claims workflow"
    assert body["action_type"] == "create"
    assert body["pending_changes"]["process_owner"]["new"] == test_user_cro.name
    assert body["pending_changes"]["owning_department"]["new"] == (
        f"{test_department.code} — {test_department.name}"
    )
    assert "process_owner_user_id" not in body["pending_changes"]
    assert "owning_department_id" not in body["pending_changes"]
    assert body["governed_mutation"]["impacted_resources"] == []

    async with client_factory(user=test_user_employee) as unrelated:
        hidden_queue = await unrelated.get("/api/v1/approvals?status=pending")
        hidden_detail = await unrelated.get(f"/api/v1/approvals/{approval_id}")
    assert hidden_queue.json()["total"] == 0
    assert hidden_queue.json()["items"] == []
    assert hidden_detail.status_code == 403

    async with client_factory(user=test_user_risk_manager) as approver:
        visible_queue = await approver.get("/api/v1/approvals/my-approvals")
        visible_detail = await approver.get(f"/api/v1/approvals/{approval_id}")
    assert [item["id"] for item in visible_queue.json()["items"]] == [approval_id]
    assert visible_detail.status_code == 200, visible_detail.text
    assert visible_detail.json()["capabilities"]["can_approve"] is True


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_overlapping_primary_swaps_lock_every_impacted_process(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL multi-resource row/unique lock semantics required")
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    processes = [
        Process(
            f_code=f"F91{index}",
            l0_area="Operations",
            l1_process=label,
            process_owner_user_id=test_user_cro.id,
            owning_department_id=test_user_cro.department_id,
            cif_override="yes",
        )
        for index, label in enumerate(
            ("Shared old primary", "First replacement", "Second replacement"),
            start=1,
        )
    ]
    assets = [
        Asset(
            name=label,
            business_owner_user_id=test_user_cro.id,
            ict_owner_user_id=test_user_cro.id,
            owning_department_id=test_user_cro.department_id,
        )
        for label in ("First platform", "Second platform")
    ]
    db_session.add_all([*processes, *assets])
    await db_session.flush()
    db_session.add_all(
        [
            ProcessAssetLink(
                process_id=processes[0].id,
                asset_id=asset.id,
                significance="Kritická podpora procesu",
                spof="yes",
                is_primary=True,
            )
            for asset in assets
        ]
    )
    await db_session.commit()

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def independent_db_session():
        async with session_maker() as session:
            yield session

    async with (
        client_factory(user=test_user_cro, db_override=independent_db_session) as first,
        client_factory(
            user=test_user_cro, db_override=independent_db_session
        ) as second,
    ):
        first_result, second_result = await asyncio.gather(
            first.post(
                f"/api/v1/assets/{assets[0].id}/process-links",
                json={
                    "process_id": processes[1].id,
                    "significance": "Kritická podpora procesu",
                    "is_primary": True,
                    "request_reason": "First overlapping primary swap",
                },
            ),
            second.post(
                f"/api/v1/assets/{assets[1].id}/process-links",
                json={
                    "process_id": processes[2].id,
                    "significance": "Kritická podpora procesu",
                    "is_primary": True,
                    "request_reason": "Second overlapping primary swap",
                },
            ),
        )

    assert sorted((first_result.status_code, second_result.status_code)) == [202, 409]
    winner = first_result if first_result.status_code == 202 else second_result
    winning_new_process_id = (
        processes[1].id if first_result.status_code == 202 else processes[2].id
    )
    winning_asset_id = assets[0].id if first_result.status_code == 202 else assets[1].id
    async with session_maker() as verification:
        approval = await verification.get(ApprovalRequest, winner.json()["approval_id"])
        active_locks = list(
            (
                await verification.execute(
                    select(GovernedMutationImpactLock)
                    .where(GovernedMutationImpactLock.released_at.is_(None))
                    .order_by(GovernedMutationImpactLock.resource_id)
                )
            )
            .scalars()
            .all()
        )
        live_links = list(
            (
                await verification.execute(
                    select(ProcessAssetLink).order_by(ProcessAssetLink.asset_id)
                )
            )
            .scalars()
            .all()
        )
    assert approval is not None and approval.status == ApprovalStatus.PENDING
    assert sorted(
        (lock.resource_type, lock.resource_id) for lock in active_locks
    ) == sorted(
        [
            ("asset", winning_asset_id),
            ("process", processes[0].id),
            ("process", winning_new_process_id),
        ]
    )
    assert [(link.process_id, link.is_primary) for link in live_links] == [
        (processes[0].id, True),
        (processes[0].id, True),
    ]


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_generic_edit_and_link_resolutions_share_lock_order(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL cross-kind lock ordering is authoritative")
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    edit_process, link_process = [
        Process(
            f_code=f"F930{index}",
            l0_area="Operations",
            l1_process=label,
            process_owner_user_id=test_user_cro.id,
            owning_department_id=test_user_cro.department_id,
            cif_override="yes",
        )
        for index, label in enumerate(
            ("Concurrent generic edit", "Concurrent link"), start=1
        )
    ]
    asset = Asset(
        name="Concurrent lock-order platform",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    db_session.add_all([edit_process, link_process, asset])
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        edit = await requester.patch(
            f"/api/v1/processes/{edit_process.id}",
            json={
                "notes": "Approved concurrently",
                "request_reason": "Cross-kind edit",
            },
        )
        link = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": link_process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Cross-kind link",
            },
        )
    assert edit.status_code == 202, edit.text
    assert link.status_code == 202, link.text

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
        ) as link_approver,
    ):
        edit_result, link_result = await asyncio.wait_for(
            asyncio.gather(
                edit_approver.post(
                    f"/api/v1/approvals/{edit.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent edit approved"},
                ),
                link_approver.post(
                    f"/api/v1/approvals/{link.json()['approval_id']}/approve",
                    json={"resolution_notes": "Concurrent link approved"},
                ),
            ),
            timeout=5,
        )
    assert edit_result.status_code == 200, edit_result.text
    assert link_result.status_code == 200, link_result.text
    assert edit_result.json()["status"] == "approved"
    assert link_result.json()["status"] == "approved"


@pytest.mark.postgres
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("authorization_change_first", "expected_status"),
    [(False, "approved"), (True, "expired")],
)
async def test_postgres_relationship_authority_change_serializes_in_both_orders(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_user_employee: User,
    test_user_cro: User,
    test_user_risk_manager: User,
    authorization_change_first: bool,
    expected_status: str,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL relationship authorization row locks are authoritative")
    process = Process(
        f_code="F9310" if authorization_change_first else "F9311",
        l0_area="Operations",
        l1_process="Relationship authority race",
        process_owner_user_id=test_user_employee.id,
        owning_department_id=test_user_employee.department_id,
        cif_override="yes",
    )
    asset = Asset(
        name="Authority race asset",
        business_owner_user_id=test_user_employee.id,
        ict_owner_user_id=test_user_employee.id,
        owning_department_id=test_user_employee.department_id,
    )
    db_session.add_all(
        [
            process,
            asset,
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()
    async with client_factory(user=test_user_employee) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": process.id,
                "significance": "Kritická podpora procesu",
                "request_reason": "Serialize requester authority",
            },
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def independent_db_session():
        async with session_maker() as session:
            await session.execute(text("SET LOCAL lock_timeout = '2s'"))
            yield session

    from app.services._governed_mutations import process_relationships

    resolution_locked = asyncio.Event()
    allow_resolution = asyncio.Event()
    snapshot_complete = asyncio.Event()
    original_lock = process_relationships.lock_process_relationship_authorization_rows
    original_snapshot = (
        process_relationships.snapshot_process_relationship_authorization
    )

    async def paused_lock(*args, **kwargs):
        result = await original_lock(*args, **kwargs)
        resolution_locked.set()
        await allow_resolution.wait()
        return result

    async def observed_snapshot(*args, **kwargs):
        result = await original_snapshot(*args, **kwargs)
        snapshot_complete.set()
        return result

    if authorization_change_first:
        monkeypatch.setattr(
            process_relationships,
            "snapshot_process_relationship_authorization",
            observed_snapshot,
        )
    else:
        monkeypatch.setattr(
            process_relationships,
            "lock_process_relationship_authorization_rows",
            paused_lock,
        )

    updater_locked = asyncio.Event()
    allow_updater = asyncio.Event()

    async def change_asset_authority() -> None:
        async with session_maker() as session:
            locked_asset = (
                await session.execute(
                    select(Asset).where(Asset.id == asset.id).with_for_update()
                )
            ).scalar_one()
            updater_locked.set()
            if authorization_change_first:
                await allow_updater.wait()
            locked_asset.business_owner_user_id = test_user_cro.id
            locked_asset.ict_owner_user_id = test_user_cro.id
            await session.commit()

    async with client_factory(
        user=test_user_risk_manager,
        db_override=independent_db_session,
    ) as approver:
        if authorization_change_first:
            updater_task = asyncio.create_task(change_asset_authority())
            await asyncio.wait_for(updater_locked.wait(), timeout=2)
            approval_task = asyncio.create_task(
                approver.post(
                    f"/api/v1/approvals/{approval_id}/approve",
                    json={"resolution_notes": "Authority change wins"},
                )
            )
            await asyncio.wait_for(snapshot_complete.wait(), timeout=2)
            allow_updater.set()
        else:
            approval_task = asyncio.create_task(
                approver.post(
                    f"/api/v1/approvals/{approval_id}/approve",
                    json={"resolution_notes": "Approval lock wins"},
                )
            )
            await asyncio.wait_for(resolution_locked.wait(), timeout=2)
            updater_task = asyncio.create_task(change_asset_authority())
            allow_resolution.set()
        resolved, _ = await asyncio.wait_for(
            asyncio.gather(approval_task, updater_task),
            timeout=5,
        )

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == expected_status


@pytest.mark.postgres
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("deactivation_first", "expected_status"),
    [(True, "expired"), (False, "approved")],
)
async def test_postgres_vendor_orphan_and_link_approval_serialize_in_both_orders(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_user: User,
    test_user_cro: User,
    test_user_employee: User,
    test_user_risk_manager: User,
    deactivation_first: bool,
    expected_status: str,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL Vendor-owner advisory locks are authoritative")
    process = Process(
        f_code=f"F94{int(deactivation_first)}",
        l0_area="Operations",
        l1_process=f"Vendor orphan race {deactivation_first}",
        process_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
        cif_override="yes",
    )
    vendor = Vendor(
        name=f"Vendor orphan race {deactivation_first}",
        process="Operations",
        department_id=test_user_employee.department_id,
        outsourcing_owner_user_id=test_user_employee.id,
    )
    db_session.add_all(
        [
            process,
            vendor,
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_vendor_edit",
                display_name="Protected Vendor mutations",
                description="Independent approval for protected Vendor mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    await db_session.commit()
    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/processes/{process.id}/vendor-links",
            json={
                "vendor_id": vendor.id,
                "direct_service_description": "Critical service",
                "request_reason": "Independent vendor-link review",
            },
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

        original = _identity_authority_lock.acquire_vendor_owner_identity_lock

        async def paused_deactivation_lock(*args, **kwargs):
            await original(*args, **kwargs)
            first_locked.set()
            await release_first.wait()

        monkeypatch.setattr(
            _identity_authority_lock,
            "acquire_vendor_owner_identity_lock",
            paused_deactivation_lock,
        )
    else:
        from app.services._governed_mutations import process_relationships

        original_many = process_relationships.acquire_vendor_owner_identity_locks

        async def paused_approval_lock(*args, **kwargs):
            await original_many(*args, **kwargs)
            first_locked.set()
            await release_first.wait()

        monkeypatch.setattr(
            process_relationships,
            "acquire_vendor_owner_identity_locks",
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
                    json={"resolution_notes": "Vendor deactivation wins"},
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
        link = await session.scalar(
            select(ProcessVendorLink.id).where(
                ProcessVendorLink.process_id == process.id,
                ProcessVendorLink.vendor_id == vendor.id,
            )
        )
        orphan = await session.scalar(
            select(OrphanedItem.id).where(
                OrphanedItem.item_type == "vendor",
                OrphanedItem.item_id == vendor.id,
                OrphanedItem.previous_owner_id == owner_id,
                OrphanedItem.status == "pending",
            )
        )
        assert orphan is not None
        assert (link is not None) is (not deactivation_first)


@pytest.mark.postgres
@pytest.mark.asyncio
async def test_postgres_primary_swap_reference_drift_expires_without_partial_apply(
    client_factory,
    db_session: AsyncSession,
    async_engine,
    monkeypatch,
    test_user_cro: User,
    test_user_risk_manager: User,
) -> None:
    if db_session.bind.dialect.name != "postgresql":
        pytest.skip("PostgreSQL relationship row-lock and atomicity semantics required")
    db_session.add_all(
        [
            ApprovalScenario(
                key="protected_process_edit",
                display_name="Protected Process mutation",
                description="Independent approval for CIF Process mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
            ApprovalScenario(
                key="protected_asset_edit",
                display_name="Protected Asset mutation",
                description="Independent approval for protected Asset mutations",
                requires_approval=True,
                approver_roles=["risk_manager", "cro"],
            ),
        ]
    )
    old_primary, proposed_primary, concurrent_primary = [
        Process(
            f_code=f"F92{index}",
            l0_area="Operations",
            l1_process=label,
            process_owner_user_id=test_user_cro.id,
            owning_department_id=test_user_cro.department_id,
            cif_override="yes",
        )
        for index, label in enumerate(
            ("Old primary", "Proposed primary", "Concurrent primary"),
            start=1,
        )
    ]
    asset = Asset(
        name="Atomic platform",
        business_owner_user_id=test_user_cro.id,
        ict_owner_user_id=test_user_cro.id,
        owning_department_id=test_user_cro.department_id,
    )
    db_session.add_all([old_primary, proposed_primary, concurrent_primary, asset])
    await db_session.flush()
    old_link = ProcessAssetLink(
        process_id=old_primary.id,
        asset_id=asset.id,
        significance="Kritická podpora procesu",
        spof="yes",
        is_primary=True,
    )
    concurrent_link = ProcessAssetLink(
        process_id=concurrent_primary.id,
        asset_id=asset.id,
        significance="standard",
        spof="no",
        is_primary=False,
    )
    db_session.add_all([old_link, concurrent_link])
    await db_session.commit()

    async with client_factory(user=test_user_cro) as requester:
        submitted = await requester.post(
            f"/api/v1/assets/{asset.id}/process-links",
            json={
                "process_id": proposed_primary.id,
                "significance": "Kritická podpora procesu",
                "is_primary": True,
                "request_reason": "Atomic primary replacement",
            },
        )
    assert submitted.status_code == 202, submitted.text
    approval_id = submitted.json()["approval_id"]

    session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def independent_db_session():
        async with session_maker() as session:
            yield session

    from app.services._governed_mutations import process_relationships

    original_apply = process_relationships.apply_process_relationship_operation
    approval_reached_apply = asyncio.Event()
    allow_approval = asyncio.Event()

    async def paused_apply(*args, **kwargs):
        approval_reached_apply.set()
        await allow_approval.wait()
        return await original_apply(*args, **kwargs)

    monkeypatch.setattr(
        process_relationships,
        "apply_process_relationship_operation",
        paused_apply,
    )

    async with client_factory(
        user=test_user_risk_manager,
        db_override=independent_db_session,
    ) as approver:
        approval_task = asyncio.create_task(
            approver.post(
                f"/api/v1/approvals/{approval_id}/approve",
                json={"resolution_notes": "Revalidate under relationship drift"},
            )
        )
        await asyncio.wait_for(approval_reached_apply.wait(), timeout=2)
        async with session_maker() as drift:
            locked_links = list(
                (
                    await drift.execute(
                        select(ProcessAssetLink)
                        .where(ProcessAssetLink.asset_id == asset.id)
                        .order_by(ProcessAssetLink.id)
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            by_id = {link.id: link for link in locked_links}
            by_id[old_link.id].is_primary = False
            by_id[concurrent_link.id].is_primary = True
            await drift.commit()
        allow_approval.set()
        resolved = await asyncio.wait_for(approval_task, timeout=2)

    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "expired"
    async with session_maker() as verification:
        approval = await verification.get(ApprovalRequest, approval_id)
        verified_processes = list(
            (
                await verification.execute(
                    select(Process).where(
                        Process.id.in_(
                            [old_primary.id, proposed_primary.id, concurrent_primary.id]
                        )
                    )
                )
            )
            .scalars()
            .all()
        )
        verified_links = list(
            (
                await verification.execute(
                    select(ProcessAssetLink)
                    .where(ProcessAssetLink.asset_id == asset.id)
                    .order_by(ProcessAssetLink.id)
                )
            )
            .scalars()
            .all()
        )
        active_locks = list(
            (
                await verification.execute(
                    select(GovernedMutationImpactLock).where(
                        GovernedMutationImpactLock.proposal_id
                        == select(GovernedMutationProposal.id)
                        .where(
                            GovernedMutationProposal.approval_request_id == approval_id
                        )
                        .scalar_subquery(),
                        GovernedMutationImpactLock.released_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
    assert approval is not None and approval.status == ApprovalStatus.EXPIRED
    assert all(process.governance_version == 1 for process in verified_processes)
    assert [(link.process_id, link.is_primary) for link in verified_links] == [
        (old_primary.id, False),
        (concurrent_primary.id, True),
    ]
    assert active_locks == []
