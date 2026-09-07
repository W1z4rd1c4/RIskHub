from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.datetime_utils import utc_now
from app.core.logging import get_logger
from app.core.scheduler_locks import PostgresAdvisoryLockProvider, SchedulerLockProvider
from app.core.scheduler_ownership import (
    mark_scheduler_runtime_started,
    mark_scheduler_runtime_stopped,
    release_scheduler_lock,
)
from app.core.scheduler_registry import SCHEDULER_RUNTIME_JOB_NAME
from app.core.scheduler_tracking import execute_tracked_job as _execute_tracked_job
from app.core.scheduler_tracking import execute_tracked_job_with_session as _execute_tracked_job_with_session

logger = get_logger("scheduler")


@dataclass
class SchedulerRuntimeState:
    scheduler: AsyncIOScheduler = field(default_factory=AsyncIOScheduler)
    db_sessionmaker: async_sessionmaker[AsyncSession] | None = None
    db_engine: AsyncEngine | None = None
    lock_provider: SchedulerLockProvider | None = None
    runtime_run_id: str | None = None
    process_instance_id: str = field(default_factory=lambda: str(uuid4()))
    process_started_at: datetime = field(default_factory=utc_now)


runtime_state = SchedulerRuntimeState()

outbox_dispatch_state: dict[str, object | None] = {
    "last_started_at": None,
    "last_finished_at": None,
    "last_status": None,
    "last_processed": None,
    "last_error": None,
}


def configure_scheduler(sessionmaker: async_sessionmaker[AsyncSession], engine: AsyncEngine) -> None:
    runtime_state.db_sessionmaker = sessionmaker
    runtime_state.db_engine = engine


@asynccontextmanager
async def get_db_context():
    if runtime_state.db_sessionmaker is None:
        raise RuntimeError("Scheduler DB sessionmaker not configured")
    async with runtime_state.db_sessionmaker() as session:
        try:
            yield session
        finally:
            await session.close()


def get_scheduler_role_status(
    *,
    scheduler_enabled: bool,
    scheduler_running: bool,
    lock_acquired: bool,
) -> dict[str, str]:
    if not scheduler_enabled:
        return {
            "scheduler_role": "disabled",
            "scheduler_status": "disabled",
        }

    if scheduler_running and lock_acquired:
        return {
            "scheduler_role": "leader",
            "scheduler_status": "leader_running",
        }

    if not scheduler_running and not lock_acquired:
        return {
            "scheduler_role": "follower",
            "scheduler_status": "follower_ready",
        }

    return {
        "scheduler_role": "leader" if lock_acquired else "follower",
        "scheduler_status": "error",
    }


def get_outbox_dispatch_runtime_state() -> dict[str, object | None]:
    return {
        "last_started_at": outbox_dispatch_state["last_started_at"],
        "last_finished_at": outbox_dispatch_state["last_finished_at"],
        "last_status": outbox_dispatch_state["last_status"],
        "last_processed": outbox_dispatch_state["last_processed"],
        "last_error": outbox_dispatch_state["last_error"],
    }


def get_scheduler_runtime_state() -> dict[str, object]:
    lock_provider = runtime_state.lock_provider.provider_name if runtime_state.lock_provider is not None else None
    enable = os.getenv("ENABLE_SCHEDULER", "false").lower() == "true"
    lock_acquired = (
        bool(runtime_state.lock_provider.lock_acquired) if runtime_state.lock_provider is not None else False
    )
    state_details = get_scheduler_role_status(
        scheduler_enabled=enable,
        scheduler_running=runtime_state.scheduler.running,
        lock_acquired=lock_acquired,
    )
    return {
        "process_role": "scheduler" if enable else "api",
        "instance_id": runtime_state.process_instance_id,
        "process_started_at": runtime_state.process_started_at.isoformat(),
        "scheduler_enabled": enable,
        "scheduler_running": runtime_state.scheduler.running,
        "lock_provider": lock_provider,
        "lock_acquired": lock_acquired,
        **state_details,
    }


async def execute_tracked_job(
    job_name: str,
    job_func: Callable[[], Awaitable[object]],
    *,
    trigger_type: str = "scheduled",
) -> dict | None:
    return await _execute_tracked_job(
        job_name,
        job_func,
        db_context=get_db_context,
        instance_id=runtime_state.process_instance_id,
        logger=logger,
        trigger_type=trigger_type,
    )


async def execute_tracked_job_with_session(
    db: AsyncSession,
    job_name: str,
    job_func: Callable[[AsyncSession], Awaitable[object]],
    *,
    trigger_type: str = "manual",
) -> dict | None:
    return await _execute_tracked_job_with_session(
        db,
        job_name,
        job_func,
        instance_id=runtime_state.process_instance_id,
        logger=logger,
        trigger_type=trigger_type,
    )


def resolve_lock_provider() -> SchedulerLockProvider:
    if runtime_state.db_engine is not None and runtime_state.db_engine.dialect.name == "postgresql":
        return PostgresAdvisoryLockProvider(runtime_state.db_engine)
    return SchedulerLockProvider()


async def mark_runtime_started() -> None:
    runtime_state.runtime_run_id = await mark_scheduler_runtime_started(
        db_context=get_db_context,
        instance_id=runtime_state.process_instance_id,
        runtime_job_name=SCHEDULER_RUNTIME_JOB_NAME,
    )


async def mark_runtime_stopped() -> None:
    await mark_scheduler_runtime_stopped(
        db_context=get_db_context,
        runtime_job_name=SCHEDULER_RUNTIME_JOB_NAME,
        runtime_run_id=runtime_state.runtime_run_id,
    )


async def release_lock_provider(*, suppress_exceptions: bool) -> None:
    provider = runtime_state.lock_provider
    try:
        await release_scheduler_lock(
            provider=provider,
            logger=logger,
            instance_id=runtime_state.process_instance_id,
            suppress_exceptions=suppress_exceptions,
        )
    finally:
        runtime_state.lock_provider = None


def setup_scheduler() -> tuple[str, tuple[str, ...]]:
    from app.core import scheduler_jobs
    from app.core.config import get_settings
    from app.core.scheduler_jobs import (
        register_full_scheduler_jobs,
        register_outbox_only_scheduler_jobs,
        resolve_scheduler_job_profile,
        set_db_sessionmaker_ref,
    )

    settings = get_settings()
    runtime_state.scheduler.remove_all_jobs()
    scheduler_jobs.scheduler = runtime_state.scheduler
    set_db_sessionmaker_ref(runtime_state.db_sessionmaker)

    profile = resolve_scheduler_job_profile()
    if profile == "outbox_only":
        registered_job_ids = register_outbox_only_scheduler_jobs()
    else:
        registered_job_ids = register_full_scheduler_jobs(settings)

    logger.info(
        "scheduler_configured",
        scheduler_job_profile=profile,
        registered_job_ids=list(registered_job_ids),
        instance_id=runtime_state.process_instance_id,
    )
    return profile, registered_job_ids


def start_scheduler() -> None:
    raise RuntimeError("start_scheduler is async; call await start_scheduler_async() instead")


def stop_scheduler() -> None:
    raise RuntimeError("stop_scheduler is async; call await stop_scheduler_async() instead")


async def start_scheduler_async() -> None:
    enable = os.getenv("ENABLE_SCHEDULER", "false").lower()
    if enable != "true":
        logger.info("scheduler_disabled", scheduler_enabled=False, instance_id=runtime_state.process_instance_id)
        return
    if runtime_state.db_sessionmaker is None:
        logger.warning(
            "scheduler_not_started",
            reason="db_sessionmaker_not_configured",
            instance_id=runtime_state.process_instance_id,
        )
        return
    if runtime_state.db_engine is None:
        logger.warning(
            "scheduler_not_started",
            reason="db_engine_not_configured",
            instance_id=runtime_state.process_instance_id,
        )
        return

    if runtime_state.scheduler.running:
        return

    from app.core.config import get_settings
    from app.services.identity_installation import validate_installation_binding

    settings = get_settings()
    if not settings.debug:
        async with runtime_state.db_sessionmaker() as db:
            await validate_installation_binding(db, settings=settings)

    # Lazy imports keep this module free of the scheduler_jobs/outbox import cycle.
    from app.core.scheduler_jobs import resolve_process_worker_count
    from app.services.outbox.store import ensure_outbox_runtime_supported

    ensure_outbox_runtime_supported(
        dialect_name=runtime_state.db_engine.dialect.name,
        worker_count=resolve_process_worker_count(),
    )

    provider = resolve_lock_provider()
    runtime_state.lock_provider = provider
    lock_acquired = await provider.acquire()
    logger.info(
        "scheduler_lock_attempt",
        scheduler_enabled=True,
        instance_id=runtime_state.process_instance_id,
        lock_provider=provider.provider_name,
        lock_acquired=lock_acquired,
    )
    if not lock_acquired:
        return

    try:
        profile, registered_job_ids = setup_scheduler()
        runtime_state.scheduler.start()
        await mark_runtime_started()
    except Exception:
        if runtime_state.scheduler.running:
            try:
                runtime_state.scheduler.shutdown(wait=False)
            except Exception:
                logger.exception(
                    "scheduler_shutdown_failed_after_start_error",
                    instance_id=runtime_state.process_instance_id,
                    lock_provider=provider.provider_name,
                )
        runtime_state.runtime_run_id = None
        await release_lock_provider(suppress_exceptions=True)
        raise

    logger.info(
        "scheduler_started",
        scheduler_enabled=True,
        scheduler_job_profile=profile,
        registered_job_ids=list(registered_job_ids),
        instance_id=runtime_state.process_instance_id,
        lock_provider=provider.provider_name,
        lock_acquired=True,
    )


async def stop_scheduler_async() -> None:
    try:
        if runtime_state.scheduler.running:
            try:
                runtime_state.scheduler.shutdown(wait=False)
            except Exception:
                logger.exception("scheduler_shutdown_failed", instance_id=runtime_state.process_instance_id)

            try:
                await mark_runtime_stopped()
            except Exception:
                logger.exception("scheduler_runtime_stop_mark_failed", instance_id=runtime_state.process_instance_id)
            else:
                logger.info("scheduler_stopped", instance_id=runtime_state.process_instance_id)
    finally:
        runtime_state.runtime_run_id = None
        await release_lock_provider(suppress_exceptions=True)
