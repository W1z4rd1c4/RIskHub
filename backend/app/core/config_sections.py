from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class _FrozenSectionModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class AuthSettingsSection(_FrozenSectionModel):
    mode: Literal["password", "microsoft_sso", "hybrid_dev"]
    entra_tenant_id: str | None
    entra_client_id: str | None
    entra_allowed_email_domains: tuple[str, ...]
    entra_business_role_attribute_name: str | None
    jit_provisioning_enabled: bool
    allow_email_link: bool
    sso_challenge_ttl_seconds: int
    sso_require_challenge: bool
    directory_provider: Literal["auto", "graph", "ad_emulator", "none"]


class OutboundSettingsSection(_FrozenSectionModel):
    allow_private_destinations: bool
    allowed_hosts: tuple[str, ...]
    block_redirects: bool


class SessionSettingsSection(_FrozenSectionModel):
    refresh_token_expire_days: int
    refresh_cookie_name: str
    refresh_cookie_samesite: Literal["lax", "strict", "none"]
    refresh_cookie_domain: str | None
    refresh_token_migration_grace: bool


class RedisSettingsSection(_FrozenSectionModel):
    redis_url: str | None
    rate_limit_limits: dict[str, tuple[int, int]]
    rate_limit_fail_closed_prefixes: tuple[str, ...]
    rate_limit_fail_closed_on_backend_error: bool
    lockout_fail_closed_on_backend_error: bool


class ProtocolGuardSettingsSection(_FrozenSectionModel):
    enabled: bool
    block_method_override: bool
    sensitive_query_keys: tuple[str, ...]
    json_prefixes: tuple[str, ...]
