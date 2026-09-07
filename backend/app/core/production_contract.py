from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from app.core.config import Settings


@dataclass(frozen=True)
class ProductionInvariant:
    key: str
    required_value: str | None = None
    description: str = ""


PRODUCTION_REQUIRED_CONFIG_KEYS: tuple[str, ...] = (
    "PUBLIC_URL",
    "ALLOWED_HOSTS",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "DIRECTORY_PROVIDER",
    "ENTRA_JIT_PROVISIONING_ENABLED",
    "AUTH_SSO_ALLOW_EMAIL_LINK",
    "BOOTSTRAP_ADMIN_EMAIL",
    "BOOTSTRAP_CRO_EMAIL",
)

PRODUCTION_REQUIRED_SECRET_MODES: tuple[str, ...] = (
    "ENTRA_CLIENT_SECRET_FILE",
    "ENTRA_CLIENT_CERTIFICATE_THUMBPRINT + ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY_FILE",
)

PRODUCTION_INVARIANTS: tuple[ProductionInvariant, ...] = (
    ProductionInvariant("DEBUG", "false", "Production must run without debug mode."),
    ProductionInvariant("MOCK_AUTH_ENABLED", "false", "Mock auth is forbidden in production."),
    ProductionInvariant(
        "AUTH_MODE",
        "microsoft_sso",
        "Production requires Entra SSO-only auth with the mandatory backend-issued SSO challenge flow.",
    ),
    ProductionInvariant("DIRECTORY_PROVIDER", "graph", "Production must use the Graph directory provider."),
    ProductionInvariant(
        "ENTRA_JIT_PROVISIONING_ENABLED",
        "false",
        "Production requires pre-provisioning instead of JIT user creation.",
    ),
    ProductionInvariant(
        "AUTH_SSO_ALLOW_EMAIL_LINK",
        "false",
        "Production forbids fallback email-link matching for SSO account binding.",
    ),
    ProductionInvariant(
        "REFRESH_TOKEN_MIGRATION_GRACE",
        "false",
        "Production requires strict refresh-token audience and issuer claims.",
    ),
    ProductionInvariant(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "30",
        "Production ordinary-user access tokens expire after 30 minutes.",
    ),
    ProductionInvariant(
        "PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES",
        "15",
        "Production platform-administrator access tokens expire after 15 minutes.",
    ),
    ProductionInvariant("ALLOWED_HOSTS", None, "Production requires an explicit host allowlist."),
    ProductionInvariant("CORS_ORIGINS", None, "Production requires an explicit CORS allowlist."),
)

BOOTSTRAP_RUNTIME_ENFORCED_KEYS: tuple[str, ...] = (
    "MOCK_AUTH_ENABLED",
    "AUTH_MODE",
    "DIRECTORY_PROVIDER",
    "ENTRA_JIT_PROVISIONING_ENABLED",
    "AUTH_SSO_ALLOW_EMAIL_LINK",
    "REFRESH_TOKEN_MIGRATION_GRACE",
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES",
    "ALLOWED_HOSTS",
    "CORS_ORIGINS",
)

PRODUCTION_REFERENCE_REQUIRED_SNIPPETS: tuple[str, ...] = (
    "DIRECTORY_PROVIDER=graph",
    "ENTRA_JIT_PROVISIONING_ENABLED=false",
    "AUTH_SSO_ALLOW_EMAIL_LINK=false",
    "ENTRA_CLIENT_SECRET_FILE",
    "ENTRA_CLIENT_CERTIFICATE_THUMBPRINT",
    "ENTRA_CLIENT_CERTIFICATE_PRIVATE_KEY_FILE",
    "ALLOWED_HOSTS",
    "TRUSTED_PROXIES",
    "ACCESS_TOKEN_EXPIRE_MINUTES=30",
    "PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES=15",
)

PRODUCTION_ENV_EXPECTED_LINES: tuple[str, ...] = (
    "AUTH_MODE=microsoft_sso",
    "MOCK_AUTH_ENABLED=false",
    "DIRECTORY_PROVIDER=graph",
    "ENTRA_JIT_PROVISIONING_ENABLED=false",
    "AUTH_SSO_ALLOW_EMAIL_LINK=false",
    "REFRESH_TOKEN_MIGRATION_GRACE=false",
    "ACCESS_TOKEN_EXPIRE_MINUTES=30",
    "PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES=15",
)


IDENTITY_CONTRACT_VERSION = 1
LOCAL_INVITATION_TTL_SECONDS = 24 * 60 * 60
LOCAL_RESET_TTL_SECONDS = 30 * 60
LOCAL_CHALLENGE_TTL_SECONDS = 5 * 60
LOCAL_FULL_AUTH_MAX_SECONDS = 8 * 60 * 60
LOCAL_PASSWORD_MIN_LENGTH = 15
LOCAL_PASSWORD_MAX_LENGTH = 128


@dataclass(frozen=True)
class IdentityProfile:
    """Resolved deployment identity policy, not an independently writable setting."""

    auth_mode: Literal["microsoft_sso", "password"]
    directory_provider: Literal["graph", "none"]
    tenant_id: str | None


def resolve_identity_profile(settings: Settings) -> IdentityProfile:
    """Validate an intended production identity tuple without admitting its release.

    This function deliberately also runs in component tests with DEBUG=true.
    DEBUG/runtime transport requirements remain owned by runtime validation.
    """
    if settings.mock_auth_enabled:
        raise ValueError("MOCK_AUTH_ENABLED must be false for a production identity profile")
    if settings.ad_emulator_base_url or settings.ad_emulator_api_key:
        raise ValueError("AD_EMULATOR configuration is not a production identity provider")
    if settings.entra_jit_provisioning_enabled:
        raise ValueError("ENTRA_JIT_PROVISIONING_ENABLED must be false")
    if settings.auth_sso_allow_email_link:
        raise ValueError("AUTH_SSO_ALLOW_EMAIL_LINK must be false")
    if settings.auth_mode == "microsoft_sso":
        if settings.directory_provider != "graph":
            raise ValueError("AUTH_MODE=microsoft_sso requires DIRECTORY_PROVIDER=graph")
        if not settings.entra_tenant_id or not settings.entra_client_id:
            raise ValueError("ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required")
        if settings.entra_certificate_credential_error:
            raise ValueError(settings.entra_certificate_credential_error)
        if settings.entra_confidential_credential is None:
            raise ValueError("An Entra Graph confidential credential is required")
        return IdentityProfile("microsoft_sso", "graph", settings.entra_tenant_id)
    if settings.auth_mode == "password":
        if settings.directory_provider != "none":
            raise ValueError("AUTH_MODE=password requires DIRECTORY_PROVIDER=none in production")
        if any(
            (
                settings.entra_tenant_id,
                settings.entra_client_id,
                settings.normalized_entra_client_secret,
                settings.normalized_entra_client_certificate_thumbprint,
                settings.normalized_entra_client_certificate_private_key,
                settings.entra_oidc_discovery_url,
                settings.entra_business_role_attribute_name,
                settings.entra_allowed_email_domains,
            )
        ):
            raise ValueError("ENTRA configuration must be unset for the local identity profile")
        return IdentityProfile("password", "none", None)
    raise ValueError("AUTH_MODE must be microsoft_sso or password for a production identity profile")


def enforce_identity_release_admission(profile: IdentityProfile) -> None:
    """Keep incomplete native identity unavailable; removed only by issue #208."""
    if profile.auth_mode != "microsoft_sso":
        raise RuntimeError(
            "AUTH_MODE=password production identity is unavailable until #208 acceptance; "
            "do not enable DEBUG or mock authentication to bypass this release guard."
        )
