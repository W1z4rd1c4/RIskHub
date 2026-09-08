"""Central registry for transactional outbox handlers."""

from __future__ import annotations

from app.services.outbox.handlers.approvals import (
    handle_approval_request_cancelled,
    handle_approval_request_created,
    handle_approval_request_expired,
    handle_approval_request_resolved,
)
from app.services.outbox.handlers.common import OutboxHandler
from app.services.outbox.handlers.issues import (
    handle_issue_assigned,
    handle_issue_exception_approved,
    handle_issue_exception_requested,
)
from app.services.outbox.handlers.kri_notifications import handle_kri_breach_detected
from app.services.outbox.handlers.questionnaires import (
    handle_questionnaire_clarification_requested,
    handle_questionnaire_sent,
    handle_questionnaire_submitted,
)


async def handle_local_auth_delivery(db, payload):
    from app.services._local_auth.delivery import deliver_mail

    await deliver_mail(db, payload.delivery_id)


OUTBOX_EVENT_HANDLERS: dict[str, OutboxHandler] = {
    "local_auth.deliver": handle_local_auth_delivery,
    "approval.request_created": handle_approval_request_created,
    "approval.request_resolved": handle_approval_request_resolved,
    "approval.request_cancelled": handle_approval_request_cancelled,
    "approval.request_expired": handle_approval_request_expired,
    "issue.assigned": handle_issue_assigned,
    "issue.exception_requested": handle_issue_exception_requested,
    "issue.exception_approved": handle_issue_exception_approved,
    "questionnaire.sent": handle_questionnaire_sent,
    "questionnaire.submitted": handle_questionnaire_submitted,
    "questionnaire.clarification_requested": handle_questionnaire_clarification_requested,
    "kri.breach_detected": handle_kri_breach_detected,
}

__all__ = ["OUTBOX_EVENT_HANDLERS"]
