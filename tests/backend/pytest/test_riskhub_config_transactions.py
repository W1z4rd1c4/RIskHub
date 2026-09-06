import pytest
from httpx import AsyncClient
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApprovalScenario, GlobalConfig
from app.models.activity_log import ActivityAction, ActivityEntityType, ActivityLog
from app.services._riskhub_config.approval_scenario_roles import (
    get_approval_scenario_roles,
    set_approval_scenario_roles,
)
from app.services._riskhub_config.global_config import ensure_total_assets_value_config
from app.services._riskhub_config.lifecycle import (
    ConfigAuditPlan,
    run_config_noop_update,
    run_config_update,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("noop", [False, True])
async def test_config_commit_failure_rolls_back_before_returning(
    db_session, test_user, monkeypatch, noop
):
    config = GlobalConfig(
        key="commit_failure",
        value="3",
        value_type="int",
        category="test",
        display_name="Commit failure",
        is_editable=True,
    )
    db_session.add(config)
    await db_session.commit()
    await db_session.refresh(config)
    audit_count = await db_session.scalar(select(func.count()).select_from(ActivityLog))
    config_id = config.id
    config.value = "7"
    failure = RuntimeError("commit unavailable")
    rollback_calls = 0
    original_rollback = db_session.rollback

    async def fail_commit():
        raise failure

    async def rollback():
        nonlocal rollback_calls
        rollback_calls += 1
        await original_rollback()

    def unexpected_cache_clear():
        pytest.fail("Failed config transactions must not invalidate the cache")

    monkeypatch.setattr(db_session, "commit", fail_commit)
    monkeypatch.setattr(db_session, "rollback", rollback)
    monkeypatch.setattr(
        "app.services._riskhub_config.lifecycle.clear_config_cache",
        unexpected_cache_clear,
    )
    with pytest.raises(RuntimeError) as raised:
        if noop:
            await run_config_noop_update(
                db=db_session, entity=config, refresh_entity=True
            )
        else:
            await run_config_update(
                db=db_session,
                actor=test_user,
                entity=config,
                refresh_entity=True,
                audit_plan=ConfigAuditPlan(
                    action=ActivityAction.UPDATE,
                    entity_type=ActivityEntityType.CONFIG,
                    entity_id=config_id,
                    entity_name=config.key,
                    safe_entity_label="Config",
                    description="Update config",
                ),
            )
    assert raised.value is failure
    assert rollback_calls == 1
    await db_session.refresh(config)
    assert config.value == "3"
    assert await db_session.scalar(select(func.count()).select_from(ActivityLog)) == audit_count


@pytest.mark.asyncio
async def test_approval_scenario_update_rolls_back_when_activity_log_fails(
    client_cro: AsyncClient,
    db_session: AsyncSession,
    monkeypatch,
):
    scenario = ApprovalScenario(
        key="rollback_scenario",
        display_name="Rollback Scenario",
        description="Scenario should rollback when logging fails",
        requires_approval=True,
    )
    set_approval_scenario_roles(scenario, ["risk_owner"])
    db_session.add(scenario)
    await db_session.commit()

    async def fail_log_activity(*args, **kwargs):
        raise RuntimeError("simulated activity log failure")

    monkeypatch.setattr("app.api.v1.endpoints.riskhub.approval_scenarios.log_activity", fail_log_activity)

    with pytest.raises(RuntimeError, match="simulated activity log failure"):
        await client_cro.patch(
            "/api/v1/riskhub/approval-scenarios/rollback_scenario",
            json={"requires_approval": False, "approver_roles": []},
        )

    await db_session.rollback()
    persisted = (
        await db_session.execute(select(ApprovalScenario).where(ApprovalScenario.key == "rollback_scenario"))
    ).scalar_one()
    assert persisted.requires_approval is True
    assert get_approval_scenario_roles(persisted) == ["risk_owner"]


@pytest.mark.asyncio
async def test_global_config_update_rolls_back_when_activity_log_fails(
    client_cro: AsyncClient,
    db_session: AsyncSession,
    monkeypatch,
):
    config = GlobalConfig(
        key="rollback_config",
        value="3",
        value_type="int",
        category="test",
        display_name="Rollback Config",
        is_editable=True,
        min_value=1,
        max_value=10,
    )
    db_session.add(config)
    await db_session.commit()

    async def fail_log_activity(*args, **kwargs):
        raise RuntimeError("simulated activity log failure")

    monkeypatch.setattr("app.api.v1.endpoints.riskhub.global_config.log_activity", fail_log_activity)

    with pytest.raises(RuntimeError, match="simulated activity log failure"):
        await client_cro.patch("/api/v1/riskhub/config/rollback_config", json={"value": "7"})

    await db_session.rollback()
    persisted = (
        await db_session.execute(select(GlobalConfig).where(GlobalConfig.key == "rollback_config"))
    ).scalar_one()
    assert persisted.value == "3"


@pytest.mark.asyncio
async def test_ensure_total_assets_value_config_does_not_commit_outer_transaction(
    db_session: AsyncSession,
    monkeypatch,
):
    await db_session.execute(delete(GlobalConfig).where(GlobalConfig.key == "total_assets_value"))
    await db_session.commit()

    commit_calls = 0

    async def fail_commit():
        nonlocal commit_calls
        commit_calls += 1
        raise AssertionError("ensure_total_assets_value_config must not commit caller transaction")

    monkeypatch.setattr(db_session, "commit", fail_commit)

    await ensure_total_assets_value_config(db_session)

    assert commit_calls == 0
    created = (
        await db_session.execute(select(GlobalConfig).where(GlobalConfig.key == "total_assets_value"))
    ).scalar_one()
    assert created.value == "10000000000"
