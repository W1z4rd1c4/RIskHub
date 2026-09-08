"""Public native-grant/factor races on independent PostgreSQL transactions."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta

import pyotp
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.datetime_utils import utc_now
from app.models import LocalAuthRecoveryCode, RefreshToken, User
from tests.backend.pytest.test_identity_foundations_postgres import (
    require_postgres,
    wait_for_lock_waiters,
)
from tests.backend.pytest.test_local_identity import (
    PASSWORD,
    create_invitation,
    csrf,
    enroll,
    latest_mail,
    login_native,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.postgres]


@pytest.mark.parametrize("operation", ["enrollment", "recovery_code", "totp", "reset"])
async def test_native_one_time_proof_concurrent_consumption(
    async_engine,
    db_session,
    client_factory,
    native_context,
    test_user,
    test_user_employee,
    operation,
):
    require_postgres(async_engine)
    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, invitation = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        await csrf(client)
        if operation == "enrollment":
            path = "/api/v1/auth/local/enrollment/start"
            bodies = [{"grant": invitation["credential"], "password": PASSWORD}] * 2
        else:
            codes, setup = await enroll(client, invitation["credential"])
            if operation in {"recovery_code", "totp"}:
                path = "/api/v1/auth/local/mfa/verify"
                bodies = []
                for _ in range(2):
                    result = await client.post(
                        "/api/v1/auth/login",
                        json={"email": "journey@example.com", "password": PASSWORD},
                    )
                    assert result.status_code == 202, result.text
                    code = (
                        codes[0]
                        if operation == "recovery_code"
                        else pyotp.parse_uri(setup["provisioning_uri"]).at(
                            utc_now() + timedelta(seconds=30)
                        )
                    )
                    bodies.append(
                        {
                            "challenge": result.json()["challenge"],
                            "code": code,
                            "method": "recovery_code"
                            if operation == "recovery_code"
                            else "totp",
                        }
                    )
            else:
                await login_native(client, "journey@example.com", PASSWORD, codes[0])
                result = await client.post(
                    "/api/v1/auth/local/password/reset/request",
                    json={"email": "journey@example.com"},
                )
                assert result.status_code == 202
                _, mail = await latest_mail(
                    db_session, native_context, user_id=user_id, kind="reset"
                )
                path = "/api/v1/auth/local/password/reset/complete"
                bodies = [
                    {
                        "grant": mail["credential"],
                        "password": "Reset concurrently by exactly one request!",
                    }
                ] * 2
        cookies = dict(client.cookies)
    # Release the fixture's read transaction before independent HTTP transactions.
    await db_session.rollback()
    maker = async_sessionmaker(async_engine, expire_on_commit=False)
    names = iter(["native-proof-0", "native-proof-1"])

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('application_name', :name, true)"),
                {"name": next(names)},
            )
            yield session

    async with maker() as gate, maker() as observer:
        await gate.execute(select(User.id).where(User.id == user_id).with_for_update())
        async with client_factory(
            settings=native_context,
            headers={"Origin": "http://test"},
            db_override=independent_db,
        ) as client:
            client.cookies.update(cookies)
            client.headers["X-CSRF-Token"] = cookies["riskhub_csrf_token"]
            tasks = [
                asyncio.create_task(client.post(path, json=body)) for body in bodies
            ]
            try:
                await wait_for_lock_waiters(
                    observer, {"native-proof-0", "native-proof-1"}
                )
            finally:
                await gate.commit()
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=20)
    assert sorted(result.status_code for result in results) == (
        [202, 401] if operation == "enrollment" else [200, 401]
    )
    active = (
        (
            await db_session.execute(
                select(RefreshToken).where(
                    RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(active) == (1 if operation in {"recovery_code", "totp"} else 0)
    if operation == "recovery_code":
        used = (
            (
                await db_session.execute(
                    select(LocalAuthRecoveryCode).where(
                        LocalAuthRecoveryCode.user_id == user_id,
                        LocalAuthRecoveryCode.consumed_at.is_not(None),
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(used) == 1


async def test_concurrent_invitation_email_uniqueness_has_one_outbox_side_effect(
    async_engine,
    db_session,
    client_factory,
    native_context,
    test_user,
    test_user_employee,
):
    from app.models import LocalAuthDelivery

    require_postgres(async_engine)
    test_user.local_email_verified_at = utc_now()
    test_user.local_enrollment_state = "enrolled"
    role_id = test_user_employee.role_id
    await db_session.commit()
    maker = async_sessionmaker(async_engine, expire_on_commit=False)
    names = iter(["native-invite-0", "native-invite-1"])

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('application_name', :name, true)"),
                {"name": next(names)},
            )
            yield session

    async with maker() as gate, maker() as observer:
        await gate.execute(
            text(
                "SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.administration'))"
            )
        )
        async with client_factory(
            current_user=test_user,
            settings=native_context,
            db_override=independent_db,
            headers={"Origin": "http://test"},
        ) as client:
            await csrf(client)
            tasks = [
                asyncio.create_task(
                    client.post(
                        "/api/v1/users/invitations",
                        json={
                            "email": "same@example.com",
                            "name": "Same user",
                            "role_id": role_id,
                        },
                    )
                )
                for _ in range(2)
            ]
            try:
                await wait_for_lock_waiters(
                    observer, {"native-invite-0", "native-invite-1"}
                )
            finally:
                await gate.commit()
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=20)
    assert sorted(result.status_code for result in results) == [202, 409]
    users = (
        (await db_session.execute(select(User).where(User.email == "same@example.com")))
        .scalars()
        .all()
    )
    assert len(users) == 1
    deliveries = (
        (
            await db_session.execute(
                select(LocalAuthDelivery).where(
                    LocalAuthDelivery.user_id == users[0].id
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(deliveries) == 1


async def test_native_reset_racing_refresh_cannot_leave_usable_old_authority(
    async_engine,
    db_session,
    client_factory,
    native_context,
    test_user,
    test_user_employee,
):
    require_postgres(async_engine)
    user_id = await create_invitation(
        client_factory,
        native_context,
        db_session,
        test_user,
        test_user_employee.role_id,
    )
    _, invitation = await latest_mail(
        db_session, native_context, user_id=user_id, kind="invitation"
    )
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        codes, _ = await enroll(client, invitation["credential"])
        access = await login_native(client, "journey@example.com", PASSWORD, codes[0])
        assert (
            await client.post(
                "/api/v1/auth/local/password/reset/request",
                json={"email": "journey@example.com"},
            )
        ).status_code == 202
        _, mail = await latest_mail(
            db_session, native_context, user_id=user_id, kind="reset"
        )
        cookies = dict(client.cookies)
    await db_session.rollback()
    maker = async_sessionmaker(async_engine, expire_on_commit=False)
    names = iter(["native-reset-race-0", "native-reset-race-1"])

    async def independent_db() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('application_name', :name, true)"),
                {"name": next(names)},
            )
            yield session

    async with maker() as gate, maker() as observer:
        await gate.execute(select(User.id).where(User.id == user_id).with_for_update())
        async with client_factory(
            settings=native_context,
            headers={"Origin": "http://test"},
            db_override=independent_db,
        ) as client:
            client.cookies.update(cookies)
            client.headers["X-CSRF-Token"] = cookies["riskhub_csrf_token"]
            reset = asyncio.create_task(
                client.post(
                    "/api/v1/auth/local/password/reset/complete",
                    json={
                        "grant": mail["credential"],
                        "password": "New credential after concurrent refresh!",
                    },
                )
            )
            refresh = asyncio.create_task(client.post("/api/v1/auth/refresh"))
            try:
                await wait_for_lock_waiters(
                    observer, {"native-reset-race-0", "native-reset-race-1"}
                )
            finally:
                await gate.commit()
            reset_result, refresh_result = await asyncio.wait_for(
                asyncio.gather(reset, refresh), timeout=20
            )
    assert reset_result.status_code == 200, reset_result.text
    assert refresh_result.status_code in {200, 401}
    tokens = [access]
    if refresh_result.status_code == 200:
        tokens.append(refresh_result.json()["access_token"])
    async with client_factory(
        settings=native_context, headers={"Origin": "http://test"}
    ) as client:
        for token in tokens:
            result = await client.get(
                "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
            )
            assert result.status_code == 401
    active = (
        await db_session.execute(
            select(RefreshToken.id).where(
                RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
            )
        )
    ).all()
    assert active == []
