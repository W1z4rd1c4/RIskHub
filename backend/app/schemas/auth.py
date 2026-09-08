"""Pydantic schemas for authentication."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.core.email import normalize_email
from app.schemas.user import UserBrief


class LoginRequest(BaseModel):
    """Schema for login request."""

    email: str  # Changed from EmailStr to allow .test TLD for testing
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if normalized is None:
            raise ValueError("email must not be empty")
        return normalized


class DemoLoginRequest(BaseModel):
    """Schema for dev-only demo login request."""

    email: str

    @field_validator("email", mode="before")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if normalized is None:
            raise ValueError("email must not be empty")
        return normalized


class TokenResponse(BaseModel):
    """Schema for JWT token response."""

    access_token: str
    token_type: str = "bearer"
    user: UserBrief  # Use specific schema instead of dict
    post_login_redirect_to: str | None = None


class AuthSsoConfig(BaseModel):
    enabled: bool
    provider: Literal["entra"] = "entra"
    tenant_id: str | None = None
    client_id: str | None = None
    authority: str | None = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])


class DemoPersonaRead(BaseModel):
    section: Literal["privileged", "department_heads", "employees"]
    name: str
    email: str
    role_key: str
    dept_key: str | None = None
    color: Literal["rose", "purple", "violet", "amber", "emerald", "sky", "teal", "indigo", "pink"]


class AuthConfigResponse(BaseModel):
    auth_mode: Literal["password", "microsoft_sso", "hybrid_dev"]
    demo_login_enabled: bool
    password_login_enabled: bool
    strict_capabilities: bool = False
    sso: AuthSsoConfig
    sso_error: str | None = None
    demo_personas: list[DemoPersonaRead] = Field(default_factory=list)


class SsoStartRequest(BaseModel):
    return_to: str | None = None


class SsoStartResponse(BaseModel):
    nonce: str
    state: str
    expires_in: int


class SsoExchangeRequest(BaseModel):
    id_token: str = Field(..., min_length=1)
    state: str = Field(..., min_length=1)
