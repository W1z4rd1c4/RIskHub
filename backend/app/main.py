from __future__ import annotations

import inspect
from contextlib import asynccontextmanager
from typing import cast

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.v1.router import api_router
from app.core.client_ip import find_broad_trusted_proxy_entries
from app.core.config import Settings, get_settings
from app.core.datetime_utils import utc_now
from app.core.exceptions import DomainError, domain_error_handler
from app.core.logging import (
    DEFAULT_LOG_RETENTION_COUNT,
    DEFAULT_LOG_ROTATION_SIZE_MB,
    get_logger,
    reconfigure_log_rotation,
)
from app.core.otel import configure_opentelemetry
from app.core.production_contract import (
    PRODUCTION_INVARIANTS,
    enforce_identity_release_admission,
    resolve_identity_profile,
)
from app.core.scheduler_jobs import resolve_process_worker_count
from app.core.scheduler_runtime import configure_scheduler, start_scheduler_async, stop_scheduler_async
from app.core.schema_guard import enforce_schema_head
from app.core.settings.database import DEFAULT_DATABASE_URL
from app.db.session import init_app_db

main_logger = get_logger("main")
bootstrap_logger = get_logger("bootstrap")

LOG_ROTATION_CONFIG_KEYS = (
    "app_log_rotation_size_mb",
    "app_log_retention_count",
    "audit_log_rotation_size_mb",
    "audit_log_retention_count",
)
KNOWN_WEAK_SECRET_KEYS = {
    "dev-secret-key-not-for-production-use",
    "changeme",
    "dev-secret",
    "test-secret",
    "secret",
}

ALLOWED_CORS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
ALLOWED_CORS_HEADERS = ["Authorization", "Content-Type", "X-CSRF-Token"]


def validate_settings_for_runtime(settings: Settings) -> None:
    if settings.mock_auth_enabled and not settings.debug:
        bootstrap_logger.critical(
            "mock_auth_production_error",
            message=(
                "FATAL: MOCK_AUTH_ENABLED=true with DEBUG=false is forbidden. "
                "Disable mock auth for production deployment."
            ),
        )
        raise RuntimeError("MOCK_AUTH_ENABLED cannot be true in non-debug mode")
    if settings.mock_auth_enabled and settings.debug:
        bootstrap_logger.warning(
            "mock_auth_warning",
            message="MOCK_AUTH_ENABLED=true - Development mode only",
        )

    if settings.debug:
        return

    invariant_map = {item.key: item for item in PRODUCTION_INVARIANTS}

    if len(settings.secret_key.strip()) < 32:
        raise RuntimeError("FATAL: SECRET_KEY must be at least 32 characters when DEBUG=false.")
    if settings.secret_key.strip().lower() in KNOWN_WEAK_SECRET_KEYS:
        raise RuntimeError("FATAL: SECRET_KEY uses a blocked weak default when DEBUG=false.")
    if settings.database_url == DEFAULT_DATABASE_URL:
        raise RuntimeError("FATAL: DATABASE_URL must be explicitly configured for production deployment.")
    if not settings.cors_origins:
        raise RuntimeError(
            f"FATAL: {invariant_map['CORS_ORIGINS'].key} must be set to an explicit allowlist in production."
        )
    if "*" in settings.cors_origins:
        raise RuntimeError(
            "FATAL: CORS_ORIGINS cannot include '*' when allow_credentials=true. "
            "Set an explicit allowlist of origins."
        )
    if not settings.allowed_hosts:
        raise RuntimeError(
            f"FATAL: {invariant_map['ALLOWED_HOSTS'].key} must be set to an explicit allowlist when DEBUG=false."
        )
    wildcard_allowed_hosts = [host for host in settings.allowed_hosts if "*" in host]
    if wildcard_allowed_hosts:
        raise RuntimeError(
            "FATAL: ALLOWED_HOSTS cannot include wildcard entries when DEBUG=false. "
            "Set explicit production hostnames."
        )
    if settings.auth_mode == "password":
        # A valid future tuple is not permission to expose incomplete local auth.
        try:
            enforce_identity_release_admission(resolve_identity_profile(settings))
        except ValueError as exc:
            raise RuntimeError(f"FATAL: {exc}") from exc
    if settings.auth_mode != invariant_map["AUTH_MODE"].required_value:
        raise RuntimeError(f"FATAL: AUTH_MODE must be '{invariant_map['AUTH_MODE'].required_value}' when DEBUG=false.")
    if not settings.entra_tenant_id or not settings.entra_client_id:
        raise RuntimeError(
            "FATAL: ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required when AUTH_MODE=microsoft_sso and DEBUG=false."
        )
    required_directory_provider = invariant_map["DIRECTORY_PROVIDER"].required_value
    if settings.directory_provider != required_directory_provider:
        raise RuntimeError("FATAL: DIRECTORY_PROVIDER must be " f"'{required_directory_provider}' when DEBUG=false.")
    if settings.ad_emulator_base_url:
        raise RuntimeError("FATAL: AD_EMULATOR_BASE_URL must be unset when DEBUG=false.")
    if settings.entra_confidential_credential is None:
        raise RuntimeError("FATAL: An Entra Graph confidential credential is required when DEBUG=false.")
    jit_required_value = invariant_map["ENTRA_JIT_PROVISIONING_ENABLED"].required_value
    if settings.entra_jit_provisioning_enabled:
        raise RuntimeError("FATAL: ENTRA_JIT_PROVISIONING_ENABLED must be " f"{jit_required_value} when DEBUG=false.")
    email_link_required_value = invariant_map["AUTH_SSO_ALLOW_EMAIL_LINK"].required_value
    if settings.auth_sso_allow_email_link:
        raise RuntimeError("FATAL: AUTH_SSO_ALLOW_EMAIL_LINK must be " f"{email_link_required_value} when DEBUG=false.")
    refresh_grace_required_value = invariant_map["REFRESH_TOKEN_MIGRATION_GRACE"].required_value
    if settings.refresh_token_migration_grace:
        raise RuntimeError(
            "FATAL: REFRESH_TOKEN_MIGRATION_GRACE must be " f"{refresh_grace_required_value} when DEBUG=false."
        )
    ordinary_access_minutes = invariant_map["ACCESS_TOKEN_EXPIRE_MINUTES"].required_value
    if str(settings.access_token_expire_minutes) != ordinary_access_minutes:
        raise RuntimeError("FATAL: ACCESS_TOKEN_EXPIRE_MINUTES must be " f"{ordinary_access_minutes} when DEBUG=false.")
    admin_access_minutes = invariant_map["PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES"].required_value
    if str(settings.platform_admin_access_token_expire_minutes) != admin_access_minutes:
        raise RuntimeError(
            "FATAL: PLATFORM_ADMIN_ACCESS_TOKEN_EXPIRE_MINUTES must be " f"{admin_access_minutes} when DEBUG=false."
        )

    try:
        enforce_identity_release_admission(resolve_identity_profile(settings))
    except ValueError as exc:
        raise RuntimeError(f"FATAL: {exc}") from exc

    broad_proxy_entries = find_broad_trusted_proxy_entries(settings.trusted_proxies)
    if broad_proxy_entries:
        if not settings.allow_broad_trusted_proxies_in_production:
            raise RuntimeError(
                "FATAL: TRUSTED_PROXIES contains broad network ranges. "
                "Use exact proxy hops in production or set "
                "ALLOW_BROAD_TRUSTED_PROXIES_IN_PRODUCTION=true if this trust boundary is intentional."
            )
        bootstrap_logger.warning(
            "trusted_proxy_broad_network_warning",
            message=(
                "TRUSTED_PROXIES contains broad network ranges. "
                "X-Forwarded-For handling, rate limiting, refresh-session IP attribution, and request logs "
                "will trust peers inside these ranges."
            ),
            trusted_proxies=broad_proxy_entries,
        )


def parse_log_rotation_config(raw_values: dict[str, str | None]) -> dict[str, int | None]:
    parsed: dict[str, int | None] = {}
    for key in LOG_ROTATION_CONFIG_KEYS:
        raw_value = raw_values.get(key)
        if raw_value is None:
            parsed[key] = None
            continue
        try:
            parsed_value = int(str(raw_value))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer, got {raw_value!r}") from exc
        if parsed_value < 1:
            raise ValueError(f"{key} must be >= 1, got {parsed_value}")
        parsed[key] = parsed_value
    return parsed


async def apply_persisted_log_rotation_config(db: AsyncSession) -> dict[str, int]:
    from app.models.global_config import GlobalConfig

    defaults = {
        "app_log_rotation_size_mb": DEFAULT_LOG_ROTATION_SIZE_MB,
        "app_log_retention_count": DEFAULT_LOG_RETENTION_COUNT,
        "audit_log_rotation_size_mb": DEFAULT_LOG_ROTATION_SIZE_MB,
        "audit_log_retention_count": DEFAULT_LOG_RETENTION_COUNT,
    }
    result = await db.execute(
        select(GlobalConfig.key, GlobalConfig.value).where(GlobalConfig.key.in_(LOG_ROTATION_CONFIG_KEYS))
    )
    persisted_values = {key: value for key, value in result.all()}

    resolved: dict[str, int] = {}
    for key, default in defaults.items():
        raw_value = persisted_values.get(key)
        if raw_value is None:
            resolved[key] = default
            continue
        try:
            parsed_value = int(str(raw_value))
            if parsed_value < 1:
                raise ValueError(f"{key} must be >= 1")
        except (TypeError, ValueError):
            bootstrap_logger.warning(
                "startup_log_rotation_config_invalid",
                message=f"Invalid persisted log rotation value for {key}; using default {default}.",
                config_key=key,
                raw_value=raw_value,
                default_value=default,
            )
            resolved[key] = default
            continue
        resolved[key] = parsed_value

    reconfigure_log_rotation(
        app_rotation_size_mb=resolved["app_log_rotation_size_mb"],
        app_retention_count=resolved["app_log_retention_count"],
        audit_rotation_size_mb=resolved["audit_log_rotation_size_mb"],
        audit_retention_count=resolved["audit_log_retention_count"],
    )
    bootstrap_logger.info(
        "startup_log_rotation_config_applied",
        app_log_rotation_size_mb=resolved["app_log_rotation_size_mb"],
        app_log_retention_count=resolved["app_log_retention_count"],
        audit_log_rotation_size_mb=resolved["audit_log_rotation_size_mb"],
        audit_log_retention_count=resolved["audit_log_retention_count"],
    )
    return resolved


def configure_default_runtime_state(app: FastAPI, settings: Settings) -> None:
    app.state.settings = settings
    app.state.redis = None

    from app.services.account_lockout_service import AccountLockoutService, InMemoryAccountLockoutBackend
    from app.services.sso_challenge_store import InMemorySsoChallengeStore

    app.state.account_lockout = AccountLockoutService(InMemoryAccountLockoutBackend())
    app.state.sso_challenge_store = InMemorySsoChallengeStore()
    app.state.process_started_at = utc_now()


def configure_app_dependencies(app: FastAPI, settings: Settings) -> None:
    def _app_settings_override() -> Settings:
        return settings

    app.dependency_overrides[get_settings] = _app_settings_override


def configure_database_and_scheduler(app: FastAPI, settings: Settings) -> None:
    init_app_db(app, settings)
    configure_scheduler(app.state.db_sessionmaker, app.state.db_engine)


def register_exception_handlers(app: FastAPI) -> None:
    async def _domain_error_handler_adapter(request: Request, exc: Exception) -> Response:
        # Starlette requires an Exception-typed handler; this adapter is registered for DomainError only.
        return await domain_error_handler(request, cast(DomainError, exc))

    app.add_exception_handler(DomainError, _domain_error_handler_adapter)


def register_middleware(app: FastAPI, settings: Settings) -> None:
    from app.middleware.language import LanguageMiddleware
    from app.middleware.logging_context import LoggingContextMiddleware
    from app.middleware.rate_limit import RateLimitMiddleware
    from app.middleware.security_headers import SecurityHeadersMiddleware
    from app.middleware.security_protocol import ProtocolGuardMiddleware

    app.add_middleware(ProtocolGuardMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        enabled=not settings.debug,
        trusted_proxies=settings.trusted_proxies,
    )
    app.add_middleware(LanguageMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, enable_hsts=not settings.debug)
    app.add_middleware(LoggingContextMiddleware, trusted_proxies=settings.trusted_proxies)

    if not settings.debug:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=ALLOWED_CORS_METHODS,
        allow_headers=ALLOWED_CORS_HEADERS,
    )

    if settings.metrics_enabled:
        from prometheus_fastapi_instrumentator import Instrumentator

        Instrumentator(
            should_group_status_codes=True,
            should_group_untemplated=True,
            excluded_handlers=["/metrics", "/"],
        ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


def configure_observability(settings: Settings) -> None:
    configure_opentelemetry(settings)


def register_routes(app: FastAPI, settings: Settings) -> None:
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/")
    async def root():
        base = {"name": settings.app_name, "version": settings.app_version}
        if settings.debug:
            base["docs"] = "/docs"
        return base


async def bootstrap_runtime_services(app: FastAPI) -> None:
    settings: Settings = app.state.settings

    if not settings.debug:
        if not settings.redis_url:
            raise RuntimeError("FATAL: REDIS_URL is required in production mode (DEBUG=false).")
        from redis.asyncio import Redis

        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        try:
            ping_result = redis.ping()
            if inspect.isawaitable(ping_result):
                await ping_result
        except Exception:
            await redis.aclose()
            raise
        app.state.redis = redis
    else:
        app.state.redis = None

    from app.services.account_lockout_service import (
        AccountLockoutService,
        InMemoryAccountLockoutBackend,
        RedisAccountLockoutBackend,
    )
    from app.services.sso_challenge_store import InMemorySsoChallengeStore, RedisSsoChallengeStore

    if app.state.redis is not None:
        app.state.account_lockout = AccountLockoutService(RedisAccountLockoutBackend(app.state.redis))
        app.state.sso_challenge_store = RedisSsoChallengeStore(app.state.redis)
    else:
        worker_count = resolve_process_worker_count()
        if worker_count > 1:
            raise RuntimeError(
                "FATAL: in-memory account lockout is unsafe for multi-worker runtime. "
                "Set REDIS_URL or run a single worker for debug/demo mode."
            )
        app.state.account_lockout = AccountLockoutService(InMemoryAccountLockoutBackend())
        app.state.sso_challenge_store = InMemorySsoChallengeStore()

    await start_scheduler_async()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    main_logger.info("startup", message="RiskHub application starting")
    settings: Settings = app.state.settings

    db_engine = getattr(app.state, "db_engine", None)
    if db_engine is None:
        raise RuntimeError("Database not initialized; call init_app_db() during app creation.")
    db_sessionmaker = getattr(app.state, "db_sessionmaker", None)
    if db_sessionmaker is None:
        raise RuntimeError("Database sessionmaker not initialized; call init_app_db() during app creation.")
    await enforce_schema_head(engine=db_engine, database_url=settings.database_url)
    async with db_sessionmaker() as db:
        if not settings.debug:
            from app.services.identity_installation import validate_installation_binding

            await validate_installation_binding(db, settings=settings)
        await apply_persisted_log_rotation_config(db)

    await bootstrap_runtime_services(app)
    yield

    main_logger.info("shutdown", message="RiskHub application shutting down")
    await stop_scheduler_async()

    db_engine = getattr(app.state, "db_engine", None)
    if db_engine is not None:
        try:
            await db_engine.dispose()
        except Exception as exc:
            main_logger.warning(
                "shutdown_db_dispose_error",
                message=f"Failed to dispose DB engine: {exc}",
            )

    redis = getattr(app.state, "redis", None)
    if redis is not None:
        try:
            await redis.aclose()
        except Exception as exc:
            main_logger.warning(
                "shutdown_redis_close_error",
                message=f"Failed to close Redis client: {exc}",
            )


def create_app(settings: Settings) -> FastAPI:
    validate_settings_for_runtime(settings)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Enterprise Risk Management Platform for Insurance Companies",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
        lifespan=lifespan,
    )
    configure_default_runtime_state(app, settings)
    configure_app_dependencies(app, settings)
    configure_database_and_scheduler(app, settings)
    register_exception_handlers(app)
    register_middleware(app, settings)
    configure_observability(settings)
    register_routes(app, settings)
    return app


app = create_app(get_settings())
