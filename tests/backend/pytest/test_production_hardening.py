import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import Settings, get_settings
from app.main import DEFAULT_DATABASE_URL, create_app

PRODUCTION_SECRET = "test-secret-for-production-mode-123456"
PRODUCTION_DATABASE_URL = "postgresql+asyncpg://riskhub:tests@prod-db:5432/riskhub"
PRODUCTION_AUTH_MODE = "microsoft_sso"
PRODUCTION_ENTRA_TENANT_ID = "00000000-0000-0000-0000-000000000000"
PRODUCTION_ENTRA_CLIENT_ID = "11111111-1111-1111-1111-111111111111"
PRODUCTION_ENTRA_CLIENT_SECRET = "production-entra-client-secret"


def _production_settings(**overrides) -> Settings:
    values = {
        "debug": False,
        "secret_key": PRODUCTION_SECRET,
        "mock_auth_enabled": False,
        "auth_mode": PRODUCTION_AUTH_MODE,
        "entra_tenant_id": PRODUCTION_ENTRA_TENANT_ID,
        "entra_client_id": PRODUCTION_ENTRA_CLIENT_ID,
        "entra_client_secret": PRODUCTION_ENTRA_CLIENT_SECRET,
        "directory_provider": "graph",
        "entra_jit_provisioning_enabled": False,
        "auth_sso_allow_email_link": False,
        "refresh_token_migration_grace": False,
        "access_token_expire_minutes": 30,
        "platform_admin_access_token_expire_minutes": 15,
        "cors_origins": ["http://testserver"],
        "allowed_hosts": ["testserver"],
        "database_url": PRODUCTION_DATABASE_URL,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.asyncio
async def test_docs_enabled_in_debug_mode():
    app = create_app(
        Settings(
            debug=True,
            secret_key=PRODUCTION_SECRET,
            mock_auth_enabled=False,
            cors_origins=["http://testserver"],
        )
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/docs")
        assert res.status_code == 200


@pytest.mark.asyncio
async def test_docs_disabled_in_production_mode():
    app = create_app(_production_settings())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        docs = await client.get("/docs")
        assert docs.status_code == 404

        openapi = await client.get("/openapi.json")
        assert openapi.status_code == 404


@pytest.mark.asyncio
async def test_trusted_host_blocks_unexpected_host_in_production_mode():
    app = create_app(_production_settings())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        ok = await client.get("/api/v1/health")
        assert ok.status_code == 200

        blocked = await client.get("/api/v1/health", headers={"host": "evil.example"})
        assert blocked.status_code == 400


@pytest.mark.asyncio
async def test_dev_auth_routes_are_unavailable_in_production_mode(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("MOCK_AUTH_ENABLED", "false")
    get_settings.cache_clear()

    app = create_app(_production_settings())
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        demo = await client.post("/api/v1/auth/demo-login/1")
        mock_login = await client.post("/api/v1/users/mock-login/1")

    get_settings.cache_clear()
    assert demo.status_code == 404
    assert mock_login.status_code == 404


def test_cors_guard_rejects_wildcard_origins_in_production_mode():
    with pytest.raises(RuntimeError):
        create_app(_production_settings(cors_origins=["*"]))


def test_cors_guard_requires_explicit_allowlist_in_production_mode():
    with pytest.raises(RuntimeError):
        create_app(_production_settings(cors_origins=[]))


def test_allowed_hosts_are_required_in_production_mode() -> None:
    with pytest.raises(RuntimeError, match="ALLOWED_HOSTS must be set"):
        create_app(_production_settings(allowed_hosts=[]))


@pytest.mark.parametrize("allowed_hosts", [["*"], ["testserver", "*.example.com"]])
def test_allowed_hosts_reject_wildcards_in_production_mode(allowed_hosts: list[str]) -> None:
    with pytest.raises(RuntimeError, match="ALLOWED_HOSTS cannot include wildcard entries"):
        create_app(_production_settings(allowed_hosts=allowed_hosts))


def test_auth_mode_guard_requires_microsoft_sso_in_production():
    with pytest.raises(RuntimeError, match="AUTH_MODE=password requires DIRECTORY_PROVIDER=none"):
        create_app(_production_settings(auth_mode="password"))


def test_auth_mode_guard_requires_entra_config_in_production():
    with pytest.raises(RuntimeError, match="ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required"):
        create_app(_production_settings(entra_tenant_id=None, entra_client_id=None))


def test_secret_key_length_guard_triggers_in_production():
    with pytest.raises(RuntimeError, match="SECRET_KEY must be at least 32 characters"):
        create_app(_production_settings(secret_key="too-short"))


def test_secret_key_blocklist_rejects_known_weak_default_in_production():
    with pytest.raises(RuntimeError, match="blocked weak default"):
        create_app(_production_settings(secret_key="dev-secret-key-not-for-production-use"))


def test_database_url_default_guard_triggers_in_production():
    with pytest.raises(RuntimeError, match="DATABASE_URL must be explicitly configured"):
        create_app(_production_settings(database_url=DEFAULT_DATABASE_URL))


def test_production_requires_graph_directory_provider() -> None:
    with pytest.raises(RuntimeError, match="DIRECTORY_PROVIDER must be 'graph'"):
        create_app(_production_settings(directory_provider="auto"))


def test_production_requires_email_link_disabled() -> None:
    with pytest.raises(RuntimeError, match="AUTH_SSO_ALLOW_EMAIL_LINK must be false"):
        create_app(_production_settings(auth_sso_allow_email_link=True))
