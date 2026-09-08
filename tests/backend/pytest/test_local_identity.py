"""Public native identity contracts for group 2 (#197--#200)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.core.datetime_utils import utc_now
from app.core.security import get_password_hash, verify_password
from app.models import User

PASSWORD = "A distinct local passphrase 74!"


def test_new_password_hash_is_argon2id():
    encoded = get_password_hash(PASSWORD)
    assert encoded.startswith("$argon2id$v=19$m=65536,t=3,p=1$")
    assert verify_password(PASSWORD, encoded)


@pytest.mark.asyncio
async def test_native_password_does_not_issue_ordinary_session(
    native_context, client_factory, db_session, test_user
):
    test_user.hashed_password = get_password_hash(PASSWORD)
    test_user.local_enrollment_state = "enrolled"
    db_session.add(test_user)
    await db_session.commit()
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        await client.get("/api/v1/auth/csrf")
        client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
        result = await client.post(
            "/api/v1/auth/login", json={"email": test_user.email, "password": PASSWORD}
        )
        assert result.status_code != 200
        assert "access_token" not in result.json()
        assert client.cookies.get("riskhub_refresh_token") is None


@pytest.mark.asyncio
async def test_invitation_creates_pending_user_without_password(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    test_user.local_email_verified_at = utc_now()
    test_user.local_enrollment_state = "enrolled"
    await db_session.commit()
    async with client_factory(
        current_user=test_user,
        settings=native_context,
        headers={"Origin": "http://test"},
    ) as client:
        await client.get("/api/v1/auth/csrf")
        client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
        result = await client.post(
            "/api/v1/users/invitations",
            json={"email": "invited@example.com", "name": "Invited"},
        )
        assert result.status_code == 202, result.text
        target = (
            await db_session.execute(
                select(User).where(User.email == "invited@example.com")
            )
        ).scalar_one()
        assert target.hashed_password is None
        assert target.local_enrollment_state == "invited"
        assert target.is_active is False
        assert result.json()["delivery_status"] == "pending"


@pytest.mark.asyncio
async def test_unknown_reset_returns_generic_accepted(native_context, client_factory):
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        await client.get("/api/v1/auth/csrf")
        client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
        result = await client.post(
            "/api/v1/auth/local/password/reset/request",
            json={"email": "unknown@example.com"},
        )
        assert result.status_code == 202, result.text
        assert result.json() == {"status": "accepted"}


async def csrf(client):
    await client.get("/api/v1/auth/csrf")
    client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")


async def latest_mail(db, settings, *, user_id, kind):
    from app.models import LocalAuthDelivery
    from app.services._local_auth.keys import LocalKeyring

    rows = (
        (
            await db.execute(
                select(LocalAuthDelivery)
                .where(LocalAuthDelivery.user_id == user_id)
                .order_by(LocalAuthDelivery.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    for row in rows:
        if row.ciphertext:
            payload = json.loads(
                LocalKeyring.load(settings.local_auth_keyring_file).decrypt(
                    "delivery",
                    row.key_id,
                    row.ciphertext,
                    [
                        row.installation_id,
                        str(row.user_id),
                        row.id,
                        row.grant_id or "notice",
                    ],
                )
            )
            if payload["kind"] == kind:
                return row, payload
    raise AssertionError("Expected encrypted mail not found")


async def create_invitation(
    client_factory, settings, db, admin, role_id, email="journey@example.com"
):
    admin.local_email_verified_at = utc_now()
    admin.local_enrollment_state = "enrolled"
    await db.commit()
    async with client_factory(
        current_user=admin, settings=settings, headers={"Origin": "http://test"}
    ) as client:
        await csrf(client)
        response = await client.post(
            "/api/v1/users/invitations",
            json={"email": email, "name": "Journey", "role_id": role_id},
        )
        assert response.status_code == 202, response.text
        return response.json()["user_id"]


async def enroll(client, grant):
    import pyotp

    await csrf(client)
    response = await client.post(
        "/api/v1/auth/local/enrollment/start",
        json={"grant": grant, "password": PASSWORD},
    )
    assert response.status_code == 202, response.text
    partial = response.json()["challenge"]
    assert "access_token" not in response.json()
    response = await client.post(
        "/api/v1/auth/local/mfa/setup", json={"challenge": partial}
    )
    assert response.status_code == 200, response.text
    setup = response.json()
    code = pyotp.parse_uri(setup["provisioning_uri"]).now()
    response = await client.post(
        "/api/v1/auth/local/mfa/confirm",
        json={"challenge": setup["challenge"], "code": code},
    )
    assert response.status_code == 200, response.text
    assert client.cookies.get("riskhub_refresh_token") is None
    return response.json()["recovery_codes"], setup


async def login_native(client, email, password, backup):
    await csrf(client)
    response = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "mfa_required"
    response = await client.post(
        "/api/v1/auth/local/mfa/verify",
        json={
            "challenge": response.json()["challenge"],
            "code": backup,
            "method": "recovery_code",
        },
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    client.headers["Authorization"] = "Bearer " + response.json()["access_token"]
    client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
    return response.json()["access_token"]


@pytest.mark.asyncio
async def test_real_enrollment_mfa_refresh_and_reset(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    from app.core.tokens import decode_refresh_token
    from app.models import LocalAuthFactor, LocalAuthGrant

    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    delivery, payload = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    assert payload["credential"] not in delivery.ciphertext
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, setup = await enroll(client, payload["credential"])
        assert len(set(codes)) == 10
        factor = await db_session.get(LocalAuthFactor, user_id)
        generation = factor.generation
        assert setup["provisioning_uri"] not in factor.encrypted_seed
        token = await login_native(client, "journey@example.com", PASSWORD, codes[0])
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 200, response.text
        old_refresh = client.cookies.get("riskhub_refresh_token")
        claims = decode_refresh_token(old_refresh, native_context)
        assert claims["session_exp"] - claims["auth_time"] == 8 * 3600
        response = await client.post("/api/v1/auth/refresh")
        assert response.status_code == 200, response.text
        rotated = decode_refresh_token(
            client.cookies.get("riskhub_refresh_token"), native_context
        )
        assert rotated["session_exp"] == claims["session_exp"]
        assert rotated["auth_time"] == claims["auth_time"]
        client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
        response = await client.post(
            "/api/v1/auth/local/password/reset/request",
            json={"email": "journey@example.com"},
        )
        assert response.status_code == 202, response.text
        assert (
            await client.get("/api/v1/auth/me")
        ).status_code == 200  # request is not revocation
        _, reset_mail = await latest_mail(
            db_session, native_context, user_id=user_id, kind="reset"
        )
        response = await client.post(
            "/api/v1/auth/local/password/reset/complete",
            json={
                "grant": reset_mail["credential"],
                "password": "A replacement passphrase 82!",
            },
        )
        assert response.status_code == 200, response.text
        assert "access_token" not in response.json()
        response = await client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer " + token}
        )
        assert response.status_code == 401
        factor = await db_session.get(LocalAuthFactor, user_id, populate_existing=True)
        assert factor.generation == generation and factor.confirmed_at is not None
        await csrf(client)
        response = await client.post(
            "/api/v1/auth/refresh", cookies={"riskhub_refresh_token": old_refresh}
        )
        assert response.status_code == 401
        client.headers.pop("Authorization", None)
        await login_native(
            client, "journey@example.com", "A replacement passphrase 82!", codes[1]
        )
        grants = (
            (
                await db_session.execute(
                    select(LocalAuthGrant).where(LocalAuthGrant.user_id == user_id)
                )
            )
            .scalars()
            .all()
        )
        assert all(grant.secret_hash != reset_mail["credential"] for grant in grants)


@pytest.mark.asyncio
async def test_recent_proof_binds_password_and_verified_email(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, mail = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, _ = await enroll(client, mail["credential"])
        token = await login_native(client, "journey@example.com", PASSWORD, codes[0])
        proposed = "My replaced local passphrase 55!"
        request = {
            "password": PASSWORD,
            "factor": codes[1],
            "method": "recovery_code",
            "target_user_id": user_id,
            "operation": "password_change",
            "intended_password": proposed,
        }
        proof = await client.post("/api/v1/auth/local/recent-auth", json=request)
        assert proof.status_code == 200, proof.text
        response = await client.post(
            "/api/v1/auth/local/password/change",
            json={
                "recent_auth_proof": proof.json()["proof"],
                "password": "Not the intended passphrase 55!",
            },
        )
        assert response.status_code == 401
        response = await client.post(
            "/api/v1/auth/local/password/change",
            json={"recent_auth_proof": proof.json()["proof"], "password": proposed},
        )
        assert response.status_code == 200, response.text
        assert (
            await client.get(
                "/api/v1/auth/me", headers={"Authorization": "Bearer " + token}
            )
        ).status_code == 401
        client.headers.pop("Authorization", None)
        await login_native(client, "journey@example.com", proposed, codes[2])
        request.update(
            password=proposed,
            factor=codes[3],
            operation="email_change",
            intended_email="new-address@example.com",
        )
        del request["intended_password"]
        proof = await client.post("/api/v1/auth/local/recent-auth", json=request)
        assert proof.status_code == 200, proof.text
        response = await client.post(
            "/api/v1/auth/local/email/change",
            json={
                "recent_auth_proof": proof.json()["proof"],
                "new_email": "new-address@example.com",
            },
        )
        assert response.status_code == 202, response.text
        target = await db_session.get(User, user_id, populate_existing=True)
        assert target.email == "journey@example.com"
        _, email_mail = await latest_mail(
            db_session, native_context, user_id=user_id, kind="email"
        )
        request["factor"] = codes[4]
        proof2 = await client.post("/api/v1/auth/local/recent-auth", json=request)
        assert proof2.status_code == 200, proof2.text
        response = await client.post(
            "/api/v1/auth/local/email/confirm",
            json={
                "recent_auth_proof": proof2.json()["proof"],
                "grant": email_mail["credential"],
            },
        )
        assert response.status_code == 200, response.text
        target = await db_session.get(User, user_id, populate_existing=True)
        assert target.email == "new-address@example.com"
        client.headers.pop("Authorization", None)
        await login_native(client, "new-address@example.com", proposed, codes[5])


@pytest.mark.parametrize("password", ["x" * 14, "x" * 129, "\ud800" * 15])
def test_password_policy_rejects_invalid_boundaries(password):
    from app.core.exceptions import ValidationError
    from app.core.password_policy import validate_local_password

    with pytest.raises(ValidationError):
        validate_local_password(password)


@pytest.mark.parametrize("password", ["x" * 15, "ě" * 128, "  preserve these spaces  "])
def test_password_policy_preserves_unicode_and_whitespace(password):
    from app.core.password_policy import validate_local_password

    validate_local_password(password)
    encoded = get_password_hash(password)
    assert verify_password(password, encoded)
    assert not verify_password(password + "x", encoded)


def test_offline_password_policy_integrity_and_operator_additions(
    tmp_path, monkeypatch
):
    from app.core import password_policy
    from app.core.exceptions import ServiceFailure, ValidationError

    additions = tmp_path / "blocked"
    additions.write_text(PASSWORD + "\n")
    with pytest.raises(ValidationError):
        password_policy.validate_local_password(PASSWORD, additions_file=str(additions))
    monkeypatch.setattr(password_policy, "DATA_DIR", tmp_path)
    with pytest.raises(ServiceFailure):
        password_policy.validate_local_password(PASSWORD)
    (tmp_path / "manifest.json").write_text('{"sha256":"not-valid"}')
    (tmp_path / "common-passwords.txt").write_text("bad-data")
    with pytest.raises(ServiceFailure):
        password_policy.validate_local_password(PASSWORD)


def test_bcrypt_byte_limit_and_malformed_hashes():
    from pwdlib.hashers.bcrypt import BcryptHasher

    from app.core.security import verify_password_or_dummy

    encoded = BcryptHasher().hash("x" * 72)
    assert verify_password("x" * 72, encoded)
    assert not verify_password("x" * 73, encoded)
    assert not verify_password("ě" * 37, encoded)
    for bad in [
        None,
        "broken",
        "$argon2id$v=19$m=999999999,t=3,p=1$aaaa$bbbb",
        "$2b$31$bad",
    ]:
        assert not verify_password_or_dummy(PASSWORD, bad)


@pytest.mark.asyncio
async def test_kdf_capacity_remains_reserved_when_request_cancelled():
    import asyncio
    import threading

    from app.core.exceptions import ServiceFailure
    from app.core.password_policy import run_password_work

    release = threading.Event()
    entered = [threading.Event(), threading.Event()]

    def work(index):
        entered[index].set()
        assert release.wait(5)
        return index

    tasks = [
        asyncio.create_task(run_password_work(lambda i=i: work(i))) for i in range(2)
    ]
    for event in entered:
        assert await asyncio.to_thread(event.wait, 5)
    tasks[0].cancel()
    with pytest.raises(asyncio.CancelledError):
        await tasks[0]
    try:
        with pytest.raises(ServiceFailure):
            await run_password_work(lambda: 3)
    finally:
        release.set()
        assert await tasks[1] == 1


@pytest.mark.asyncio
async def test_wrong_browser_wrong_purpose_expiry_and_enrollment_replay(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    from datetime import timedelta

    from app.models import LocalAuthGrant

    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, mail = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    grant = mail["credential"]
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        await csrf(client)
        result = await client.post(
            "/api/v1/auth/local/password/reset/complete",
            json={"grant": grant, "password": PASSWORD},
        )
        assert result.status_code == 401
        assert (
            await client.get("/api/v1/auth/local/enrollment/start")
        ).status_code == 405
        result = await client.post(
            "/api/v1/auth/local/enrollment/start",
            json={"grant": grant, "password": PASSWORD},
        )
        assert result.status_code == 202
        challenge = result.json()["challenge"]
        saved = client.cookies.get("riskhub_local_challenge")
        client.cookies.delete(
            "riskhub_local_challenge", domain="test.local", path="/api/v1/auth"
        )
        result = await client.post(
            "/api/v1/auth/local/mfa/setup", json={"challenge": challenge}
        )
        assert result.status_code == 401
        client.cookies.set(
            "riskhub_local_challenge", saved, domain="test.local", path="/api/v1/auth"
        )
        result = await client.post(
            "/api/v1/auth/local/enrollment/start",
            json={"grant": grant, "password": PASSWORD},
        )
        assert result.status_code == 401
        row = await db_session.get(
            LocalAuthGrant, challenge.split(".")[0], populate_existing=True
        )
        row.expires_at = utc_now() - timedelta(seconds=1)
        await db_session.commit()
        result = await client.post(
            "/api/v1/auth/local/mfa/setup", json={"challenge": challenge}
        )
        assert result.status_code == 401


@pytest.mark.asyncio
async def test_native_security_dependencies_and_csrf_fail_closed(
    native_context, client_factory, monkeypatch
):
    from app.main import app

    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        path = "/api/v1/auth/local/password/reset/request"
        assert (
            await client.post(path, json={"email": "unknown@example.com"})
        ).status_code == 403
        await csrf(client)
        assert (
            await client.post(
                path,
                json={"email": "unknown@example.com"},
                headers={"Origin": "http://evil.invalid"},
            )
        ).status_code == 403
        monkeypatch.setattr(app.state, "redis", None)
        result = await client.post(path, json={"email": "unknown@example.com"})
        assert result.status_code == 503
        assert "access_token" not in result.json()


@pytest.mark.asyncio
async def test_secret_validation_and_chunked_request_limit(
    native_context, client_factory
):
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        await csrf(client)
        payload = {"grant": "secret-grant-text", "password": "Sensitive-" * 20}
        result = await client.post("/api/v1/auth/local/enrollment/start", json=payload)
        assert result.status_code == 422
        assert (
            payload["password"] not in result.text
            and payload["grant"] not in result.text
        )

        async def oversized():
            yield b'{"email":"unknown@example.com","password":"'
            yield b"x" * 20_000
            yield b'"}'

        result = await client.post(
            "/api/v1/auth/login",
            content=oversized(),
            headers={"Content-Type": "application/json"},
        )
        assert result.status_code == 413


@pytest.mark.asyncio
async def test_enrollment_and_backup_code_replay_denied(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    from app.models import LocalAuthFactor, LocalAuthGrant

    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, mail = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, setup = await enroll(client, mail["credential"])
        await login_native(client, "journey@example.com", PASSWORD, codes[0])
        request = await client.post(
            "/api/v1/auth/login",
            json={"email": "journey@example.com", "password": PASSWORD},
        )
        assert request.status_code == 202
        challenge = request.json()["challenge"]
        result = await client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge": challenge, "code": codes[0], "method": "recovery_code"},
        )
        assert result.status_code == 401
        # Remaining challenge is valid with a different backup code; one failed attempt is persisted.
        row = await db_session.get(
            LocalAuthGrant, challenge.split(".")[0], populate_existing=True
        )
        assert row.failures == 1
        result = await client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge": challenge, "code": codes[1], "method": "recovery_code"},
        )
        assert result.status_code == 200, result.text
        client.headers["X-CSRF-Token"] = client.cookies.get("riskhub_csrf_token")
        result = await client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge": challenge, "code": codes[2], "method": "recovery_code"},
        )
        assert result.status_code == 401
        factor = await db_session.get(LocalAuthFactor, user_id, populate_existing=True)
        assert factor.confirmed_at is not None


@pytest.mark.asyncio
async def test_full_auth_age_cannot_be_renewed_and_legacy_native_tokens_are_denied(
    native_context,
    client_factory,
    db_session,
    test_user,
    test_user_employee,
):
    from datetime import timedelta

    from freezegun import freeze_time

    from app.core.security import create_access_token
    from app.core.tokens import decode_refresh_token

    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, mail = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, _ = await enroll(client, mail["credential"])
        await login_native(client, "journey@example.com", PASSWORD, codes[0])
        target = await db_session.get(User, user_id, populate_existing=True)
        legacy = create_access_token(
            {
                "sub": target.email,
                "user_id": target.id,
                "token_version": target.token_version,
            },
            settings=native_context,
        )
        assert (
            await client.get(
                "/api/v1/auth/me", headers={"Authorization": "Bearer " + legacy}
            )
        ).status_code == 401
        original = client.cookies.get("riskhub_refresh_token")
        original_claims = decode_refresh_token(original, native_context)
        now = utc_now()
        csrf_value = client.cookies.get("riskhub_csrf_token")
        with freeze_time(now + timedelta(hours=7), real_asyncio=True):
            result = await client.post(
                "/api/v1/auth/refresh",
                headers={
                    "Cookie": f"riskhub_refresh_token={original}; riskhub_csrf_token={csrf_value}",
                    "X-CSRF-Token": csrf_value,
                },
            )
            assert result.status_code == 200, result.text
            child = client.cookies.get("riskhub_refresh_token")
            csrf_value = client.cookies.get("riskhub_csrf_token")
            assert (
                decode_refresh_token(child, native_context)["session_exp"]
                == original_claims["session_exp"]
            )
        with freeze_time(now + timedelta(hours=8, seconds=1), real_asyncio=True):
            result = await client.post(
                "/api/v1/auth/refresh",
                headers={
                    "Cookie": f"riskhub_refresh_token={child}; riskhub_csrf_token={csrf_value}",
                    "X-CSRF-Token": csrf_value,
                },
            )
            assert result.status_code == 401


@pytest.mark.asyncio
async def test_native_legacy_admin_mutations_and_cro_invitation_are_forbidden(
    native_context,
    client_factory,
    db_session,
    test_user,
    test_user_employee,
    test_user_cro,
):
    test_user.local_email_verified_at = utc_now()
    test_user.local_enrollment_state = "enrolled"
    test_user_cro.local_email_verified_at = utc_now()
    test_user_cro.local_enrollment_state = "enrolled"
    target_id, role_id = test_user_employee.id, test_user_employee.role_id
    await db_session.commit()
    async with client_factory(
        current_user=test_user,
        settings=native_context,
        headers={"Origin": "http://test"},
    ) as client:
        result = await client.patch(
            f"/api/v1/users/{target_id}", json={"password": PASSWORD}
        )
        assert result.status_code == 403
        result = await client.patch(
            f"/api/v1/users/{target_id}", json={"email": "injected@example.com"}
        )
        assert result.status_code == 403
        result = await client.patch(
            f"/api/v1/access/users/{target_id}", json={"email": "injected@example.com"}
        )
        assert result.status_code == 403
        result = await client.post(
            "/api/v1/users",
            json={
                "email": "bypass@example.com",
                "name": "Bypass",
                "role_id": role_id,
                "password": PASSWORD,
            },
        )
        assert result.status_code == 403
    async with client_factory(
        current_user=test_user_cro,
        settings=native_context,
        headers={"Origin": "http://test"},
    ) as client:
        await csrf(client)
        result = await client.post(
            "/api/v1/users/invitations",
            json={"email": "invite@example.com", "name": "Invite", "role_id": role_id},
        )
        assert result.status_code == 403


@pytest.mark.asyncio
async def test_native_role_loss_and_exhausted_factor_proof_are_denied(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    from app.models import LocalAuthGrant, Role

    role_id = test_user_employee.role_id
    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, mail = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, _ = await enroll(client, mail["credential"])
        result = await client.post(
            "/api/v1/auth/login",
            json={"email": "journey@example.com", "password": PASSWORD},
        )
        challenge = result.json()["challenge"]
        for _ in range(5):
            failed = await client.post(
                "/api/v1/auth/local/mfa/verify",
                json={"challenge": challenge, "code": "bad", "method": "totp"},
            )
            assert failed.status_code == 401
        replay = await client.post(
            "/api/v1/auth/local/mfa/verify",
            json={"challenge": challenge, "code": codes[0], "method": "recovery_code"},
        )
        assert replay.status_code == 401
        assert client.cookies.get("riskhub_refresh_token") is None
        grant = await db_session.get(
            LocalAuthGrant, challenge.split(".", 1)[0], populate_existing=True
        )
        assert grant.failures == 5 and grant.revoked_at is not None
        role = await db_session.get(Role, role_id)
        role.is_active = False
        await db_session.commit()
        denied = await client.post(
            "/api/v1/auth/login",
            json={"email": "journey@example.com", "password": PASSWORD},
        )
        assert denied.status_code == 401


@pytest.mark.asyncio
async def test_sent_invitation_status_reports_expired_grant(
    native_context, client_factory, db_session, test_user, test_user_employee
):
    from datetime import timedelta

    from app.models import LocalAuthGrant

    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    delivery, _ = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    delivery.status, delivery.sent_at = "sent", utc_now()
    grant = await db_session.get(LocalAuthGrant, delivery.grant_id)
    grant.expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    async with client_factory(
        current_user=test_user,
        settings=native_context,
        headers={"Origin": "http://test"},
    ) as client:
        status = await client.get(f"/api/v1/users/{user_id}/local-auth/status")
        assert status.status_code == 200, status.text
        assert status.json()["delivery_status"] == "expired"


@pytest.mark.parametrize("operation", ["password_change", "email_change"])
def test_missing_intent_is_rejected_without_relying_on_assert(operation):
    from app.core.exceptions import AuthenticationError
    from app.schemas.local_auth import RecentAuthenticationRequest
    from app.services._local_auth.factors import intent_value

    # Direct service callers must fail closed even if schema validation was bypassed.
    data = RecentAuthenticationRequest.model_construct(operation=operation)
    with pytest.raises(AuthenticationError):
        intent_value(data)
