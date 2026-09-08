"""Typed payload models for supported outbox events."""

from __future__ import annotations

from datetime import date
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, ValidationError


class OutboxPayloadModel(BaseModel):
    """Base payload model with strict key validation."""

    model_config = ConfigDict(extra="forbid")


class ActorPayloadModel(OutboxPayloadModel):
    """Shared base for outbox payloads that carry the acting user's id."""

    actor_user_id: int


class ApprovalRequestCreatedPayload(OutboxPayloadModel):
    approval_id: int


class ApprovalRequestResolvedPayload(OutboxPayloadModel):
    approval_id: int
    approved: bool


class ApprovalRequestCancelledPayload(OutboxPayloadModel):
    approval_id: int
    cancelled_by_user_id: int


class ApprovalRequestExpiredPayload(OutboxPayloadModel):
    approval_id: int


class IssueAssignedPayload(ActorPayloadModel):
    issue_id: int
    owner_user_id: int


class IssueExceptionRequestedPayload(ActorPayloadModel):
    issue_id: int


class IssueExceptionApprovedPayload(ActorPayloadModel):
    issue_id: int
    requested_by_id: int | None = None
    owner_user_id: int | None = None


class QuestionnaireSentPayload(ActorPayloadModel):
    questionnaire_id: int


class QuestionnaireSubmittedPayload(ActorPayloadModel):
    questionnaire_id: int


class QuestionnaireClarificationRequestedPayload(ActorPayloadModel):
    clarification_id: int
    questionnaire_id: int


class KriBreachDetectedPayload(OutboxPayloadModel):
    kri_id: int
    recipient_user_id: int
    period_end: date
    breach_transition: Literal["lower", "upper"]
    title: str
    message: str


class LocalAuthDeliveryPayload(OutboxPayloadModel):
    delivery_id: str


OutboxPayload: TypeAlias = (
    LocalAuthDeliveryPayload
    | ApprovalRequestCreatedPayload
    | ApprovalRequestResolvedPayload
    | ApprovalRequestCancelledPayload
    | ApprovalRequestExpiredPayload
    | IssueAssignedPayload
    | IssueExceptionRequestedPayload
    | IssueExceptionApprovedPayload
    | QuestionnaireSentPayload
    | QuestionnaireSubmittedPayload
    | QuestionnaireClarificationRequestedPayload
    | KriBreachDetectedPayload
)


OUTBOX_PAYLOAD_MODELS: dict[str, type[OutboxPayloadModel]] = {
    "local_auth.deliver": LocalAuthDeliveryPayload,
    "approval.request_created": ApprovalRequestCreatedPayload,
    "approval.request_resolved": ApprovalRequestResolvedPayload,
    "approval.request_cancelled": ApprovalRequestCancelledPayload,
    "approval.request_expired": ApprovalRequestExpiredPayload,
    "issue.assigned": IssueAssignedPayload,
    "issue.exception_requested": IssueExceptionRequestedPayload,
    "issue.exception_approved": IssueExceptionApprovedPayload,
    "questionnaire.sent": QuestionnaireSentPayload,
    "questionnaire.submitted": QuestionnaireSubmittedPayload,
    "questionnaire.clarification_requested": QuestionnaireClarificationRequestedPayload,
    "kri.breach_detected": KriBreachDetectedPayload,
}


def get_outbox_payload_model(event_type: str) -> type[OutboxPayloadModel] | None:
    return OUTBOX_PAYLOAD_MODELS.get(event_type)


def validate_outbox_payload(event_type: str, payload: OutboxPayloadModel | dict) -> OutboxPayloadModel:
    model = get_outbox_payload_model(event_type)
    if model is None:
        raise ValueError(f"Unknown outbox event type: {event_type}")
    if isinstance(payload, model):
        return payload
    if isinstance(payload, OutboxPayloadModel):
        payload = payload.model_dump(mode="json")
    return model.model_validate(payload)


__all__ = [
    "OutboxPayload",
    "ActorPayloadModel",
    "OutboxPayloadModel",
    "ApprovalRequestCreatedPayload",
    "ApprovalRequestResolvedPayload",
    "ApprovalRequestCancelledPayload",
    "ApprovalRequestExpiredPayload",
    "IssueAssignedPayload",
    "IssueExceptionRequestedPayload",
    "IssueExceptionApprovedPayload",
    "QuestionnaireSentPayload",
    "QuestionnaireSubmittedPayload",
    "QuestionnaireClarificationRequestedPayload",
    "KriBreachDetectedPayload",
    "OUTBOX_PAYLOAD_MODELS",
    "ValidationError",
    "get_outbox_payload_model",
    "validate_outbox_payload",
]
