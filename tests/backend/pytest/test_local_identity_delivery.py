"""Real verified-TLS SMTP delivery and durable retry/purge behavior."""

from __future__ import annotations

import asyncio
import ssl
from datetime import timedelta

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app.core.datetime_utils import utc_now
from app.models import LocalAuthDelivery, OutboxEvent
from app.services._local_auth.delivery import (
    deliver_mail,
    purge_expired_delivery_secrets,
)
from app.services._local_auth.keys import LocalKeyring
from app.services.outbox.errors import RetryableOutboxError
from app.services.outbox.payloads import LocalAuthDeliveryPayload
from app.services.outbox.registry import OUTBOX_EVENT_HANDLERS
from tests.backend.pytest.test_local_identity import create_invitation, latest_mail


@pytest_asyncio.fixture
async def tls_mail_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(utc_now() - timedelta(minutes=1))
        .not_valid_after(utc_now() + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "smtp-ca.pem", tmp_path / "smtp-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_file.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    messages, connections = [], set()

    async def smtp(reader, writer):
        task = asyncio.current_task()
        connections.add(task)
        try:
            writer.write(b"220 localhost controlled SMTP\r\n")
            await writer.drain()
            while line := await reader.readline():
                verb = line.split(b" ", 1)[0].strip().upper()
                if verb in {b"EHLO", b"HELO"}:
                    writer.write(b"250 localhost\r\n")
                elif verb == b"DATA":
                    writer.write(b"354 End data with dot\r\n")
                    await writer.drain()
                    chunks = []
                    while (chunk := await reader.readline()) and chunk != b".\r\n":
                        chunks.append(chunk)
                    messages.append(b"".join(chunks).decode())
                    writer.write(b"250 Accepted\r\n")
                elif verb == b"QUIT":
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            connections.discard(task)

    server = await asyncio.start_server(smtp, host="127.0.0.1", port=0, ssl=context)
    yield server.sockets[0].getsockname()[1], str(cert_file), messages
    server.close()
    await server.wait_closed()
    if connections:
        await asyncio.gather(*connections)


@pytest.mark.asyncio
async def test_actual_tls_smtp_registered_handler_and_post_send_secret_removal(
    native_context,
    client_factory,
    db_session,
    test_user,
    test_user_employee,
    tls_mail_server,
    monkeypatch,
):
    port, ca_file, messages = tls_mail_server
    settings = native_context.model_copy(
        update={
            "local_smtp_port": port,
            "local_smtp_ca_file": ca_file,
            "local_smtp_security": "tls",
        }
    )
    user_id = await create_invitation(
        client_factory, settings, db_session, test_user, test_user_employee.role_id
    )
    row, mail = await latest_mail(
        db_session, settings, user_id=user_id, kind="invitation"
    )
    delivery_id = row.id
    events = (await db_session.execute(select(OutboxEvent))).scalars().all()
    event = next(event for event in events if event.event_type == "local_auth.deliver")
    assert event.payload == {"delivery_id": delivery_id}
    assert mail["credential"] not in str(event.payload)
    assert messages == []  # account commit only enqueues, never sends
    from app.services._local_auth import delivery

    monkeypatch.setattr(delivery, "get_settings", lambda: settings)
    await OUTBOX_EVENT_HANDLERS["local_auth.deliver"](
        db_session, LocalAuthDeliveryPayload(delivery_id=delivery_id)
    )
    await db_session.commit()
    assert len(messages) == 1
    from email import policy
    from email.parser import Parser

    assert (
        mail["credential"]
        in Parser(policy=policy.default).parsestr(messages[0]).get_content()
    )
    row = await db_session.get(LocalAuthDelivery, delivery_id, populate_existing=True)
    assert row.ciphertext is None and row.status == "sent"
    await deliver_mail(db_session, delivery_id, settings=settings)
    assert len(messages) == 1


@pytest.mark.asyncio
async def test_untrusted_smtp_certificate_retries_same_grant_then_expiry_purges(
    native_context,
    client_factory,
    db_session,
    test_user,
    test_user_employee,
    tls_mail_server,
):
    port, _, messages = tls_mail_server
    settings = native_context.model_copy(
        update={"local_smtp_port": port, "local_smtp_security": "tls"}
    )
    user_id = await create_invitation(
        client_factory, settings, db_session, test_user, test_user_employee.role_id
    )
    row, mail = await latest_mail(
        db_session, settings, user_id=user_id, kind="invitation"
    )
    delivery_id, ciphertext = row.id, row.ciphertext
    with pytest.raises(
        RetryableOutboxError, match="Local identity delivery unavailable"
    ):
        await deliver_mail(db_session, delivery_id, settings=settings)
    row = await db_session.get(LocalAuthDelivery, delivery_id, populate_existing=True)
    assert row.ciphertext == ciphertext and messages == []
    row.expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    await purge_expired_delivery_secrets(db_session)
    await db_session.commit()
    row = await db_session.get(LocalAuthDelivery, delivery_id, populate_existing=True)
    assert row.ciphertext is None and row.status == "expired"


def test_key_material_is_permission_guarded_and_context_bound(tmp_path):
    import base64
    import json
    import secrets
    from app.core.exceptions import ServiceFailure

    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "purposes": {
                    name: {
                        "active": "one",
                        "keys": {
                            "one": base64.b64encode(secrets.token_bytes(32)).decode()
                        },
                    }
                    for name in ("delivery", "totp", "action")
                },
            }
        )
    )
    path.chmod(0o644)
    with pytest.raises(ServiceFailure):
        LocalKeyring.load(str(path))
    path.chmod(0o600)
    keys = LocalKeyring.load(str(path))
    key_id, cipher = keys.encrypt("totp", "test-only-seed", ["installation", "user-a"])
    assert (
        keys.decrypt("totp", key_id, cipher, ["installation", "user-a"])
        == "test-only-seed"
    )
    with pytest.raises(ServiceFailure):
        keys.decrypt("totp", key_id, cipher, ["installation", "user-b"])
    with pytest.raises(ServiceFailure):
        keys.decrypt("delivery", key_id, cipher, ["installation", "user-a"])
