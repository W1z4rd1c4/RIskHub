"""Explicitly requested native identity fixtures; no global auth override."""

import base64
import json
import secrets

import fakeredis.aioredis
import pytest_asyncio

from app.core.config import Settings
from app.models import InstallationIdentity


@pytest_asyncio.fixture
async def native_context(tmp_path, monkeypatch, db_session):
    key_file = tmp_path / "native-keys.json"
    key_file.write_text(
        json.dumps(
            {
                "version": 1,
                "purposes": {
                    name: {
                        "active": "v1",
                        "keys": {
                            "v1": base64.b64encode(secrets.token_bytes(32)).decode()
                        },
                    }
                    for name in ("delivery", "totp", "action")
                },
            }
        )
    )
    key_file.chmod(0o600)
    settings = Settings(
        debug=True,
        mock_auth_enabled=False,
        auth_mode="password",
        directory_provider="none",
        cors_origins=["http://test"],
        public_url="http://test",
        local_auth_keyring_file=str(key_file),
        local_smtp_host="localhost",
        local_smtp_sender="security@example.com",
        refresh_token_migration_grace=False,
        access_token_expire_minutes=30,
        platform_admin_access_token_expire_minutes=15,
    )
    binding = InstallationIdentity(auth_mode="password", establishment_source="pytest")
    db_session.add(binding)
    await db_session.commit()
    from app.main import app

    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(app.state, "redis", redis)
    yield settings
    await redis.aclose()
