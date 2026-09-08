"""Native identity inputs; the release-admission guard remains separate."""

from typing import Literal

from pydantic import Field


class LocalAuthSettingsMixin:
    public_url: str | None = None
    local_auth_keyring_file: str | None = Field(default=None, repr=False, exclude=True)
    local_password_blocklist_file: str | None = None
    # Total deployment KDF allowance: two bounded 64-MiB jobs per API process.
    local_kdf_memory_budget_mib: int = Field(default=1024, ge=128, le=65536)
    local_smtp_host: str | None = None
    local_smtp_port: int = Field(default=587, ge=1, le=65535)
    local_smtp_security: Literal["starttls", "tls"] = "starttls"
    local_smtp_sender: str | None = None
    local_smtp_username: str | None = Field(default=None, repr=False)
    local_smtp_password_file: str | None = Field(default=None, repr=False, exclude=True)
    local_smtp_ca_file: str | None = None
    local_smtp_timeout_seconds: float = Field(default=10.0, gt=0, le=30)
