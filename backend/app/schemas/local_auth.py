"""Version-one native identity wire contract (handlers ship in groups 2–3).

These schemas reserve no route and grant no authentication authority. Export
with scripts.export_local_auth_contract; existing TokenResponse remains the
only completed-session response. Sensitive request values are repr-redacted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, model_validator

from app.schemas.auth import TokenResponse

UserId = Annotated[int, Field(strict=True, gt=0)]


class LocalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnrollmentStartRequest(LocalRequest):
    grant: SecretStr = Field(min_length=1, max_length=1024)
    password: SecretStr = Field(min_length=1, max_length=128)


class ChallengeRequest(LocalRequest):
    challenge: SecretStr = Field(min_length=1, max_length=1024)


class FactorVerifyRequest(ChallengeRequest):
    code: SecretStr = Field(min_length=1, max_length=1024)
    method: Literal["totp", "recovery_code"] = "totp"


class ResetRequest(LocalRequest):
    email: EmailStr


class ResetCompleteRequest(LocalRequest):
    grant: SecretStr = Field(min_length=1, max_length=1024)
    password: SecretStr = Field(min_length=1, max_length=128)


class RecentAuthenticationRequest(LocalRequest):
    password: SecretStr = Field(min_length=1, max_length=128)
    factor: SecretStr = Field(min_length=1, max_length=1024)
    method: Literal["totp", "recovery_code"] = "totp"
    target_user_id: UserId
    operation: Literal["password_change", "email_change", "factor_replace", "recovery_codes", "assisted_recovery"]
    intended_password: SecretStr | None = Field(default=None, max_length=128)
    intended_email: EmailStr | None = None
    intended_recovery_operation: (
        Literal["factor_recovery", "credential_and_factor_recovery", "verified_address_recovery"] | None
    ) = None

    @model_validator(mode="after")
    def validate_intent(self) -> "RecentAuthenticationRequest":
        required = {
            "password_change": self.intended_password,
            "email_change": self.intended_email,
            "assisted_recovery": self.intended_recovery_operation,
        }
        if self.operation in required and required[self.operation] is None:
            raise ValueError("The exact intended change is required for recent authentication")
        return self


class PasswordChangeRequest(LocalRequest):
    recent_auth_proof: SecretStr = Field(min_length=1, max_length=1024)
    password: SecretStr = Field(min_length=1, max_length=128)


class EmailChangeRequest(LocalRequest):
    recent_auth_proof: SecretStr = Field(min_length=1, max_length=1024)
    new_email: EmailStr


class EmailChangeCompleteRequest(LocalRequest):
    recent_auth_proof: SecretStr = Field(min_length=1, max_length=1024)
    grant: SecretStr = Field(min_length=1, max_length=1024)


class FactorReplacementRequest(LocalRequest):
    recent_auth_proof: SecretStr = Field(min_length=1, max_length=1024)


class InvitationRequest(LocalRequest):
    email: EmailStr
    name: str = Field(min_length=1, max_length=255)
    role_id: UserId | None = None
    department_id: UserId | None = None
    manager_id: UserId | None = None


class AssistedRecoveryRequest(LocalRequest):
    recent_auth_proof: SecretStr = Field(min_length=1, max_length=1024)
    incident_reference: str = Field(min_length=1, max_length=255)
    verification_method: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)
    operation: Literal["factor_recovery", "credential_and_factor_recovery", "verified_address_recovery"]


class LocalAuthChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["mfa_required", "enrollment_required"]
    challenge: str = Field(repr=False, min_length=1)
    expires_in: Literal[300] = 300


class ActionProofResponse(BaseModel):
    proof: str = Field(repr=False, min_length=1)
    expires_in: Literal[300] = 300


class FactorSetupResponse(BaseModel):
    challenge: str = Field(repr=False)
    provisioning_uri: str = Field(repr=False)
    expires_in: Literal[300] = 300


class FactorEnrollmentResponse(BaseModel):
    status: Literal["enrolled"] = "enrolled"
    recovery_codes: list[str] = Field(repr=False)
    # Enrollment completion need not also create a full app session. Login may follow.


class InvitationResponse(BaseModel):
    user_id: UserId
    enrollment_state: Literal["invited"] = "invited"
    delivery_status: Literal["pending", "sent", "failed"]


class LocalIdentityStatusResponse(BaseModel):
    user_id: UserId
    enrollment_state: Literal["invited", "password_set", "enrolled"] | None
    local_suspended: bool
    is_active: bool
    delivery_status: Literal["pending", "sent", "failed", "expired", "cancelled"] | None


class ReasonRequest(LocalRequest):
    reason: str = Field(min_length=1, max_length=2000)


class RecoveryStartRequest(LocalRequest):
    grant: SecretStr = Field(min_length=1, max_length=1024)
    current_password: SecretStr | None = None
    new_password: SecretStr | None = None


class AcceptedResponse(BaseModel):
    status: Literal["accepted"] = "accepted"


class CompletedResponse(BaseModel):
    status: Literal["completed"] = "completed"
    reauthentication_required: bool = True


@dataclass(frozen=True)
class LocalEndpointContract:
    path: str
    request: type[BaseModel]
    response: type[BaseModel]
    authentication: str
    owner_issue: int
    status_code: int = 200
    method: Literal["get", "post"] = "post"


# This catalogue is documentation/schema input, never a dynamic route registry.
LOCAL_ENDPOINT_CONTRACTS = (
    LocalEndpointContract(
        "/users/{user_id}/local-auth/status",
        LocalRequest,
        LocalIdentityStatusResponse,
        "platform admin",
        198,
        200,
        "get",
    ),
    LocalEndpointContract(
        "/auth/local/enrollment/start", EnrollmentStartRequest, LocalAuthChallenge, "invitation grant", 198, 202
    ),
    LocalEndpointContract("/auth/local/mfa/setup", ChallengeRequest, FactorSetupResponse, "enrollment challenge", 199),
    LocalEndpointContract(
        "/auth/local/mfa/confirm", FactorVerifyRequest, FactorEnrollmentResponse, "setup challenge", 199
    ),
    LocalEndpointContract(
        "/auth/local/mfa/verify", FactorVerifyRequest, TokenResponse, "password + bound MFA challenge", 199
    ),
    LocalEndpointContract(
        "/auth/local/recent-auth", RecentAuthenticationRequest, ActionProofResponse, "bearer + password + factor", 199
    ),
    LocalEndpointContract(
        "/auth/local/password/reset/request", ResetRequest, AcceptedResponse, "public, generic result", 200, 202
    ),
    LocalEndpointContract(
        "/auth/local/password/reset/complete", ResetCompleteRequest, CompletedResponse, "reset grant", 200
    ),
    LocalEndpointContract(
        "/auth/local/password/change", PasswordChangeRequest, CompletedResponse, "bearer + recent proof", 200
    ),
    LocalEndpointContract(
        "/auth/local/email/change", EmailChangeRequest, AcceptedResponse, "bearer + recent proof", 200, 202
    ),
    LocalEndpointContract(
        "/auth/local/email/confirm",
        EmailChangeCompleteRequest,
        CompletedResponse,
        "bearer + recent proof + new-address grant",
        200,
    ),
    LocalEndpointContract(
        "/auth/local/factor/replace", FactorReplacementRequest, FactorSetupResponse, "bearer + recent proof", 201
    ),
    LocalEndpointContract(
        "/auth/local/recovery-codes/regenerate",
        FactorReplacementRequest,
        FactorEnrollmentResponse,
        "bearer + recent proof",
        201,
    ),
    LocalEndpointContract("/users/invitations", InvitationRequest, InvitationResponse, "platform admin", 198, 202),
    LocalEndpointContract(
        "/users/{user_id}/invitations/resend", ReasonRequest, InvitationResponse, "platform admin", 198, 202
    ),
    LocalEndpointContract(
        "/users/{user_id}/invitations/cancel", ReasonRequest, CompletedResponse, "platform admin", 198
    ),
    LocalEndpointContract(
        "/users/{user_id}/password-reset", ReasonRequest, AcceptedResponse, "platform admin", 200, 202
    ),
    LocalEndpointContract(
        "/auth/local/recovery/start",
        RecoveryStartRequest,
        FactorSetupResponse,
        "approved recovery grant + required credential proof",
        201,
    ),
    LocalEndpointContract(
        "/auth/local/recovery/confirm",
        FactorVerifyRequest,
        FactorEnrollmentResponse,
        "approved bound recovery challenge",
        201,
    ),
    LocalEndpointContract(
        "/users/{user_id}/recovery",
        AssistedRecoveryRequest,
        AcceptedResponse,
        "platform admin + recent proof; privileged targets offline only",
        201,
        202,
    ),
)
