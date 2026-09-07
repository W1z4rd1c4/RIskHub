from typing import Literal

from pydantic import AliasChoices, Field

from app.core.config_sections import AuthSettingsSection
from app.core.settings.common import EntraConfidentialCredential, normalize_optional_string


class AuthSettingsMixin:
    # Authentication
    secret_key: str
    secret_key_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SECRET_KEY_FILE", "secret_key_file"),
        exclude=True,
        repr=False,
    )
    mock_auth_enabled: bool = False
    access_token_expire_minutes: int = Field(default=60, gt=0)
    platform_admin_access_token_expire_minutes: int = Field(default=60, gt=0)
    strict_capabilities_enabled: bool = False

    # Auth mode (password vs SSO)
    auth_mode: Literal["password", "microsoft_sso", "hybrid_dev"] = "password"

    # Microsoft Entra ID (SSO)
    entra_tenant_id: str | None = None
    entra_client_id: str | None = None
    entra_client_secret: str | None = None
    entra_client_secret_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices("ENTRA_CLIENT_SECRET_FILE", "entra_client_secret_file"),
        exclude=True,
        repr=False,
    )
    entra_client_certificate_thumbprint: str | None = None
    entra_client_certificate_private_key: str | None = None
    entra_client_certificate_private_key_file: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY_FILE",
            "entra_client_certificate_private_key_file",
        ),
        exclude=True,
        repr=False,
    )
    entra_jit_provisioning_enabled: bool = False
    entra_allowed_email_domains: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ENTRA_ALLOWED_EMAIL_DOMAINS", "ENTRA_ALLOWED_DOMAINS"),
    )
    entra_business_role_attribute_name: str | None = None
    entra_clock_skew_seconds: int = 60
    entra_oidc_discovery_url: str | None = None
    entra_credential_fingerprint: str | None = None
    auth_sso_allow_email_link: bool = False
    auth_sso_challenge_ttl_seconds: int = 300
    # Deprecated compatibility flag: the backend now enforces the SSO challenge flow unconditionally.
    auth_sso_require_challenge: bool = True
    directory_provider: Literal["auto", "graph", "ad_emulator", "none"] = "graph"
    ad_emulator_base_url: str | None = None
    ad_emulator_api_key: str | None = None
    ad_emulator_api_key_header: str = "X-API-Key"
    graph_timeout_seconds: float = 10.0

    @property
    def normalized_entra_client_secret(self) -> str | None:
        return normalize_optional_string(self.entra_client_secret)

    @property
    def normalized_entra_client_certificate_thumbprint(self) -> str | None:
        return normalize_optional_string(self.entra_client_certificate_thumbprint)

    @property
    def normalized_entra_client_certificate_private_key(self) -> str | None:
        return normalize_optional_string(self.entra_client_certificate_private_key)

    @property
    def normalized_entra_business_role_attribute_name(self) -> str | None:
        return normalize_optional_string(self.entra_business_role_attribute_name)

    @property
    def entra_certificate_credential_error(self) -> str | None:
        has_thumbprint = self.normalized_entra_client_certificate_thumbprint is not None
        has_private_key = self.normalized_entra_client_certificate_private_key is not None
        if has_thumbprint != has_private_key:
            return (
                "Incomplete Entra certificate credential configuration. "
                "Set both ENTRA_CLIENT_CERTIFICATE_THUMBPRINT and "
                "ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY(_FILE)."
            )
        return None

    @property
    def entra_confidential_credential(self) -> EntraConfidentialCredential | None:
        if self.entra_certificate_credential_error is None:
            thumbprint = self.normalized_entra_client_certificate_thumbprint
            private_key = self.normalized_entra_client_certificate_private_key
            if thumbprint and private_key:
                return EntraConfidentialCredential(
                    mode="certificate",
                    client_certificate_private_key=private_key,
                    client_certificate_thumbprint=thumbprint,
                )

        client_secret = self.normalized_entra_client_secret
        if client_secret:
            return EntraConfidentialCredential(mode="secret", client_secret=client_secret)
        return None

    @property
    def auth(self) -> AuthSettingsSection:
        return AuthSettingsSection(
            mode=self.auth_mode,
            entra_tenant_id=self.entra_tenant_id,
            entra_client_id=self.entra_client_id,
            entra_allowed_email_domains=tuple(self.entra_allowed_email_domains),
            entra_business_role_attribute_name=self.normalized_entra_business_role_attribute_name,
            jit_provisioning_enabled=self.entra_jit_provisioning_enabled,
            allow_email_link=self.auth_sso_allow_email_link,
            sso_challenge_ttl_seconds=self.auth_sso_challenge_ttl_seconds,
            sso_require_challenge=self.auth_sso_require_challenge,
            directory_provider=self.directory_provider,
        )

    @property
    def auth_settings(self) -> AuthSettingsSection:
        return self.auth

    @property
    def entra_business_role_graph_field(self) -> str | None:
        attr_name = self.normalized_entra_business_role_attribute_name
        client_id = normalize_optional_string(self.entra_client_id)
        if not attr_name or not client_id:
            return None
        return f"extension_{client_id.replace('-', '')}_{attr_name}"

    @property
    def entra_business_role_token_claim(self) -> str | None:
        attr_name = self.normalized_entra_business_role_attribute_name
        if not attr_name:
            return None
        return f"extn.{attr_name}"

    @property
    def entra_business_role_enabled(self) -> bool:
        return self.normalized_entra_business_role_attribute_name is not None
