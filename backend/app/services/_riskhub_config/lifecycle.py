from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import log_activity
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.models.user import User
from app.services._config.lookup import clear_config_cache
from app.services.transaction_boundary import commit_service_boundary

ConfigLifecycleStatus = Literal["created", "updated", "deleted", "restored", "blocked"]
ConfigLogActivity = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class ConfigEntityDefinition:
    entity_name: str
    activity_entity_type: ActivityEntityType


@dataclass(frozen=True)
class ConfigAuditPlan:
    action: ActivityAction
    entity_type: ActivityEntityType
    entity_id: int
    entity_name: str
    safe_entity_label: str
    description: str
    changes: dict[str, dict[str, object]] | None = None
    safe_description: str | None = None
    safe_description_siem: str | None = None

    def as_log_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "safe_entity_label": self.safe_entity_label,
            "description": self.description,
        }
        if self.changes is not None:
            kwargs["changes"] = self.changes
        if self.safe_description is not None:
            kwargs["safe_description"] = self.safe_description
        if self.safe_description_siem is not None:
            kwargs["safe_description_siem"] = self.safe_description_siem
        return kwargs


@dataclass(frozen=True)
class ConfigLifecycleOutcome:
    status: ConfigLifecycleStatus
    entity: object | None = None
    audit_plan: ConfigAuditPlan | None = None
    response_payload: dict[str, object] | None = None


def build_config_audit_plan(
    *,
    action: ActivityAction,
    entity_type: ActivityEntityType,
    entity_id: int,
    entity_name: str,
    safe_entity_label: str,
    description: str,
    changes: dict[str, dict[str, object]] | None = None,
    safe_description: str | None = None,
    safe_description_siem: str | None = None,
) -> ConfigAuditPlan:
    return ConfigAuditPlan(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        safe_entity_label=safe_entity_label,
        description=description,
        changes=changes,
        safe_description=safe_description,
        safe_description_siem=safe_description_siem,
    )


async def _run_config_lifecycle(
    *,
    db: AsyncSession,
    actor: User,
    status: ConfigLifecycleStatus,
    audit_plan: ConfigAuditPlan,
    entity: object | None = None,
    refresh_entity: bool = False,
    response_payload: dict[str, object] | None = None,
    log_activity_func: ConfigLogActivity = log_activity,
) -> ConfigLifecycleOutcome:
    await log_activity_func(
        db=db,
        actor=actor,
        **audit_plan.as_log_kwargs(),
    )
    await commit_service_boundary(db, boundary="riskhub_config_lifecycle")
    clear_config_cache()
    if refresh_entity and entity is not None:
        await db.refresh(entity)
    return ConfigLifecycleOutcome(
        status=status,
        entity=entity,
        audit_plan=audit_plan,
        response_payload=response_payload,
    )


async def run_config_create(
    *,
    db: AsyncSession,
    actor: User,
    audit_plan: ConfigAuditPlan,
    entity: object | None = None,
    refresh_entity: bool = False,
    log_activity_func: ConfigLogActivity = log_activity,
) -> ConfigLifecycleOutcome:
    return await _run_config_lifecycle(
        db=db,
        actor=actor,
        status="created",
        audit_plan=audit_plan,
        entity=entity,
        refresh_entity=refresh_entity,
        log_activity_func=log_activity_func,
    )


async def run_config_update(
    *,
    db: AsyncSession,
    actor: User,
    audit_plan: ConfigAuditPlan,
    entity: object | None = None,
    refresh_entity: bool = False,
    log_activity_func: ConfigLogActivity = log_activity,
) -> ConfigLifecycleOutcome:
    return await _run_config_lifecycle(
        db=db,
        actor=actor,
        status="updated",
        audit_plan=audit_plan,
        entity=entity,
        refresh_entity=refresh_entity,
        log_activity_func=log_activity_func,
    )


async def run_config_noop_update(
    *,
    db: AsyncSession,
    entity: object | None = None,
    refresh_entity: bool = False,
) -> ConfigLifecycleOutcome:
    await commit_service_boundary(db, boundary="riskhub_config_noop_update")
    clear_config_cache()
    if refresh_entity and entity is not None:
        await db.refresh(entity)
    return ConfigLifecycleOutcome(status="updated", entity=entity)


async def run_config_delete(
    *,
    db: AsyncSession,
    actor: User,
    audit_plan: ConfigAuditPlan,
    entity: object | None = None,
    response_payload: dict[str, object] | None = None,
    log_activity_func: ConfigLogActivity = log_activity,
) -> ConfigLifecycleOutcome:
    return await _run_config_lifecycle(
        db=db,
        actor=actor,
        status="deleted",
        audit_plan=audit_plan,
        entity=entity,
        response_payload=response_payload,
        log_activity_func=log_activity_func,
    )


async def run_config_restore(
    *,
    db: AsyncSession,
    actor: User,
    audit_plan: ConfigAuditPlan,
    entity: object | None = None,
    refresh_entity: bool = False,
    log_activity_func: ConfigLogActivity = log_activity,
) -> ConfigLifecycleOutcome:
    return await _run_config_lifecycle(
        db=db,
        actor=actor,
        status="restored",
        audit_plan=audit_plan,
        entity=entity,
        refresh_entity=refresh_entity,
        log_activity_func=log_activity_func,
    )
