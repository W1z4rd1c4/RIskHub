from __future__ import annotations

import pytest

from app.api.v1.endpoints.auth import password as password_endpoint
from app.core.security import get_password_hash, verify_password, verify_password_or_dummy
from app.main import app

TEST_ORIGIN = "http://test"
ALLOWED_ORIGIN_HEADERS = {"Origin": TEST_ORIGIN}


def _set_login_allowed_origin() -> None:
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True, cors_origins=[TEST_ORIGIN])

    app.dependency_overrides[get_settings] = override_settings


def _assert_no_session_cookies(response) -> None:
    cookie_headers = response.headers.get_list("set-cookie")
    assert not any("riskhub_refresh_token=" in header for header in cookie_headers)
    assert not any("riskhub_refresh_hint=1" in header for header in cookie_headers)
    assert not any("riskhub_csrf_token=" in header for header in cookie_headers)


@pytest.mark.asyncio
async def test_missing_user_login_uses_dummy_verifier_and_returns_generic_401(client, monkeypatch):
    _set_login_allowed_origin()
    calls: list[str | None] = []
    real_verify = password_endpoint.verify_password_or_dummy

    def tracking_verify(plain_password: str, hashed_password: str | None) -> bool:
        calls.append(hashed_password)
        return real_verify(plain_password, hashed_password)

    monkeypatch.setattr(password_endpoint, "verify_password_or_dummy", tracking_verify)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "missing-user@example.com", "password": "wrong-password"},
        headers=ALLOWED_ORIGIN_HEADERS,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert calls == [None]


@pytest.mark.asyncio
async def test_wrong_password_login_uses_stored_hash_and_returns_generic_401(
    client,
    db_session,
    test_user,
    monkeypatch,
):
    _set_login_allowed_origin()
    test_user.hashed_password = get_password_hash("correct-password")
    db_session.add(test_user)
    await db_session.commit()

    calls: list[str | None] = []
    real_verify = password_endpoint.verify_password_or_dummy

    def tracking_verify(plain_password: str, hashed_password: str | None) -> bool:
        calls.append(hashed_password)
        return real_verify(plain_password, hashed_password)

    monkeypatch.setattr(password_endpoint, "verify_password_or_dummy", tracking_verify)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": test_user.email, "password": "wrong-password"},
        headers=ALLOWED_ORIGIN_HEADERS,
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}
    assert calls == [test_user.hashed_password]


@pytest.mark.asyncio
async def test_successful_password_login_still_issues_tokens(client, db_session, test_user):
    _set_login_allowed_origin()
    password = "correct-password"
    test_user.hashed_password = get_password_hash(password)
    test_user.email = "normalized.login@example.com"
    db_session.add(test_user)
    await db_session.commit()

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "Normalized.Login@Example.com", "password": password},
        headers=ALLOWED_ORIGIN_HEADERS,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["access_token"]
    assert body["user"]["email"] == "normalized.login@example.com"
    cookie_headers = response.headers.get_list("set-cookie")
    assert any("riskhub_refresh_token=" in header for header in cookie_headers)
    assert any("riskhub_refresh_hint=1" in header for header in cookie_headers)
    assert any("riskhub_csrf_token=" in header for header in cookie_headers)


@pytest.mark.asyncio
async def test_password_login_rejects_missing_origin_before_issuing_cookies(client, monkeypatch):
    _set_login_allowed_origin()
    calls: list[str | None] = []

    def tracking_verify(plain_password: str, hashed_password: str | None) -> bool:
        calls.append(hashed_password)
        return False

    monkeypatch.setattr(password_endpoint, "verify_password_or_dummy", tracking_verify)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "missing-origin@example.com", "password": "password"},
    )

    assert response.status_code == 403
    assert response.json() == {"code": "origin_not_allowed", "detail": "Request origin is not allowed."}
    assert calls == []
    _assert_no_session_cookies(response)


@pytest.mark.asyncio
async def test_password_login_rejects_unallowed_origin_before_issuing_cookies(client, monkeypatch):
    _set_login_allowed_origin()
    calls: list[str | None] = []

    def tracking_verify(plain_password: str, hashed_password: str | None) -> bool:
        calls.append(hashed_password)
        return False

    monkeypatch.setattr(password_endpoint, "verify_password_or_dummy", tracking_verify)

    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "bad-origin@example.com", "password": "password"},
        headers={"Origin": "http://evil.example"},
    )

    assert response.status_code == 403
    assert response.json() == {"code": "origin_not_allowed", "detail": "Request origin is not allowed."}
    assert calls == []
    _assert_no_session_cookies(response)


def test_legacy_bcrypt_verifies_and_new_hashes_use_argon2id():
    """Hashes minted by the previous passlib[bcrypt] implementation must keep verifying."""
    passlib_era_hash = "$2b$12$jNEyM2QKA3984KXadjJTCOOindKtrnp77.y4JAKu/EdmhQj0b6oBG"

    assert verify_password("regression-password-123", passlib_era_hash) is True
    assert verify_password("wrong-password", passlib_era_hash) is False

    new_hash = get_password_hash("regression-password-123")
    assert new_hash.startswith("$argon2id$v=19$m=65536,t=3,p=1$")
    assert verify_password("regression-password-123", new_hash) is True

    assert verify_password_or_dummy("anything", None) is False


def test_malformed_stored_hash_fails_closed():
    """A corrupt or legacy-algorithm stored hash must deny (401 path), never 500."""
    assert verify_password("any-password", "not-a-bcrypt-hash") is False
    assert verify_password_or_dummy("any-password", "not-a-bcrypt-hash") is False
