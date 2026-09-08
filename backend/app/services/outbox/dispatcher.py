"""Dispatch claimed outbox events using isolated transactions."""

from __future__ import annotations

from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.datetime_utils import coerce_utc, utc_now
from app.core.logging import get_logger
from app.core.scheduler_runtime import runtime_state
from app.models import OutboxEvent
from app.models.scheduler_job_run import SchedulerJobRun
from app.services.outbox.errors import FatalOutboxError, RetryableOutboxError
from app.services.outbox.payloads import ValidationError, get_outbox_payload_model
from app.services.outbox.registry import OUTBOX_EVENT_HANDLERS
from app.services.outbox.store import OUTBOX_BATCH_SIZE, OutboxService

logger = get_logger("outbox")


async def _record_dispatch_run_start(sessionmaker: async_sessionmaker[AsyncSession]) -> str:
    async with sessionmaker() as session:
        async with session.begin():
            run = SchedulerJobRun(
                job_name="outbox_dispatch",
                run_id=str(uuid4()),
                status="running",
                trigger_type="dispatch",
                instance_id=runtime_state.process_instance_id,
                started_at=utc_now(),
            )
            session.add(run)
            await session.flush()
            return run.id


async def _record_dispatch_run_finish(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    scheduler_run_id: str,
    status: str,
    events_processed: int | None = None,
    error_message: str | None = None,
) -> None:
    async with sessionmaker() as session:
        async with session.begin():
            run = await session.get(SchedulerJobRun, scheduler_run_id)
            if run is None:
                return

            finished_at = utc_now()
            started_at = coerce_utc(run.started_at) or finished_at
            run.status = status
            run.finished_at = finished_at
            run.duration_ms = int((finished_at - started_at).total_seconds() * 1000)
            run.result_json = {"events_processed": events_processed} if events_processed is not None else None
            run.error_message = error_message


async def dispatch_pending_outbox_events(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    batch_size: int = OUTBOX_BATCH_SIZE,
    lock_owner: str = "scheduler",
) -> int:
    """Claim a batch of outbox events and process them with isolated transactions."""
    scheduler_run_id = await _record_dispatch_run_start(sessionmaker)
    processed = 0
    try:
        async with sessionmaker() as claim_session:
            async with claim_session.begin():
                from app.services._local_auth.delivery import purge_expired_delivery_secrets

                await purge_expired_delivery_secrets(claim_session)
                claimed_ids = await OutboxService.claim_batch(
                    claim_session,
                    batch_size=batch_size,
                    lock_owner=lock_owner,
                )

        for event_id in claimed_ids:
            event_type = "unknown"
            idempotency_key = None
            event_succeeded = False
            try:
                async with sessionmaker() as session:
                    async with session.begin():
                        event = await session.get(OutboxEvent, event_id)
                        if event is None or event.status != "processing":
                            continue

                        event_type = event.event_type
                        idempotency_key = event.idempotency_key
                        payload_model = get_outbox_payload_model(event.event_type)
                        handler = OUTBOX_EVENT_HANDLERS.get(event.event_type)
                        if payload_model is None or handler is None:
                            await OutboxService.mark_dead_letter(
                                session,
                                event_id,
                                error_message=f"Unknown outbox event type: {event.event_type}",
                            )
                            continue

                        try:
                            payload = payload_model.model_validate(event.payload)
                        except ValidationError as exc:
                            await OutboxService.mark_dead_letter(
                                session,
                                event_id,
                                error_message=f"Invalid outbox payload for {event.event_type}: {exc}",
                            )
                            continue

                        await handler(session, payload)
                        await OutboxService.mark_succeeded(session, event_id)
                        event_succeeded = True
                if event_succeeded:
                    processed += 1
            except RetryableOutboxError as exc:
                async with sessionmaker() as retry_session:
                    async with retry_session.begin():
                        await OutboxService.mark_retry(retry_session, event_id, error_message=str(exc))
                logger.exception(
                    "outbox_event_failed",
                    error_category="retryable_handler_execution",
                    outbox_event_id=event_id,
                    event_type=event_type,
                    idempotency_key=idempotency_key,
                    error_message=str(exc),
                )
            except FatalOutboxError as exc:
                async with sessionmaker() as dead_letter_session:
                    async with dead_letter_session.begin():
                        await OutboxService.mark_dead_letter(
                            dead_letter_session,
                            event_id,
                            error_message=str(exc),
                        )
                logger.exception(
                    "outbox_event_failed",
                    error_category="fatal_handler_execution",
                    outbox_event_id=event_id,
                    event_type=event_type,
                    idempotency_key=idempotency_key,
                    error_message=str(exc),
                )
            except Exception as exc:
                async with sessionmaker() as dead_letter_session:
                    async with dead_letter_session.begin():
                        await OutboxService.mark_dead_letter(
                            dead_letter_session,
                            event_id,
                            error_message=str(exc),
                        )
                logger.exception(
                    "outbox_event_failed",
                    error_category="unclassified_handler_execution",
                    outbox_event_id=event_id,
                    event_type=event_type,
                    idempotency_key=idempotency_key,
                    error_message=str(exc),
                )
    except Exception as exc:
        await _record_dispatch_run_finish(
            sessionmaker,
            scheduler_run_id=scheduler_run_id,
            status="failed",
            error_message=str(exc)[:1024],
        )
        raise

    await _record_dispatch_run_finish(
        sessionmaker,
        scheduler_run_id=scheduler_run_id,
        status="succeeded",
        events_processed=processed,
    )

    if processed:
        logger.info("outbox_batch_processed", processed=processed)
    return processed
