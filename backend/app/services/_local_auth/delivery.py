"""Encrypted post-commit local-identity mail on the existing transactional outbox."""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage
from uuid import uuid4

from pydantic import EmailStr, TypeAdapter
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.datetime_utils import coerce_utc, utc_now
from app.models import LocalAuthDelivery, LocalAuthGrant, User
from app.services.outbox.errors import RetryableOutboxError
from app.services.outbox.store import OutboxService

from .artifacts import grant_active
from .common import NativeContext, native_identity_selected
from .keys import LocalKeyring, read_secret_file, unavailable

_TITLES = {
    "invitation": "RiskHub account invitation",
    "reset": "RiskHub password recovery",
    "email": "Verify your RiskHub email address",
    "email_requested": "RiskHub email change requested",
    "credentials_changed": "RiskHub account security changed",
}
_ROUTES = {"invitation": "enroll", "reset": "reset-password", "email": "verify-email"}


def validate_mail_configuration(settings: Settings) -> None:
    try:
        if not settings.local_smtp_host or not settings.local_smtp_sender:
            raise ValueError("Missing mail configuration")
        TypeAdapter(EmailStr).validate_python(settings.local_smtp_sender)
        if settings.local_smtp_username:
            read_secret_file(settings.local_smtp_password_file)
        ssl.create_default_context(cafile=settings.local_smtp_ca_file)
    except (ValueError, OSError):
        raise unavailable() from None


async def enqueue_mail(
    db: AsyncSession,
    ctx: NativeContext,
    user: User,
    *,
    recipient: str,
    kind: str,
    grant: LocalAuthGrant | None = None,
    credential: str | None = None,
) -> LocalAuthDelivery:
    validate_mail_configuration(ctx.settings)
    delivery_id = uuid4().hex
    payload = {"recipient": recipient, "kind": kind, "credential": credential, "origin": ctx.public_url}
    context = [ctx.installation_id, str(user.id), delivery_id, grant.id if grant else "notice"]
    key_id, encrypted = ctx.keys.encrypt("delivery", json.dumps(payload), context)
    expires = coerce_utc(grant.expires_at) if grant else utc_now() + timedelta(hours=24)
    if expires is None:
        raise unavailable()
    row = LocalAuthDelivery(
        id=delivery_id,
        user_id=user.id,
        installation_id=ctx.installation_id,
        grant_id=grant.id if grant else None,
        key_id=key_id,
        ciphertext=encrypted,
        status="pending",
        created_at=utc_now(),
        expires_at=expires,
    )
    db.add(row)
    await db.flush()
    await OutboxService.enqueue(
        db,
        event_type="local_auth.deliver",
        aggregate_type="user",
        aggregate_id=user.id,
        idempotency_key=f"local-auth-mail:{delivery_id}",
        payload={"delivery_id": delivery_id},
    )
    return row


def send_smtp(settings: Settings, *, delivery_id: str, payload: dict) -> None:
    """Bounded verified TLS; caller gets sanitized failures, never SMTP content."""
    validate_mail_configuration(settings)
    tls = ssl.create_default_context(cafile=settings.local_smtp_ca_file)
    kind = payload["kind"]
    message = EmailMessage()
    message["From"] = settings.local_smtp_sender
    message["To"] = str(TypeAdapter(EmailStr).validate_python(payload["recipient"]))
    message["Subject"] = _TITLES[kind]
    message["Message-ID"] = f"<{delivery_id}@riskhub.local>"
    if payload["credential"]:
        link = f'{payload["origin"]}/auth/local/{_ROUTES[kind]}#{payload["credential"]}'
        message.set_content(
            f"{_TITLES[kind]}. Open this single-use link in RiskHub:\n\n{link}\n\n"
            "Do not forward this link. Contact your administrator if you did not request it."
        )
    else:
        message.set_content(
            "Your RiskHub account security settings changed or a change was requested. "
            "Contact your administrator immediately if this was not you."
        )
    host = settings.local_smtp_host
    if host is None:
        raise unavailable()
    connection: smtplib.SMTP
    if settings.local_smtp_security == "tls":
        connection = smtplib.SMTP_SSL(
            host, settings.local_smtp_port, timeout=settings.local_smtp_timeout_seconds, context=tls
        )
    else:
        connection = smtplib.SMTP(host, settings.local_smtp_port, timeout=settings.local_smtp_timeout_seconds)
    with connection:
        connection.ehlo()
        if settings.local_smtp_security == "starttls":
            connection.starttls(context=tls)
            connection.ehlo()
        if settings.local_smtp_username:
            password = read_secret_file(settings.local_smtp_password_file).decode().rstrip("\r\n")
            connection.login(settings.local_smtp_username, password)
        refused = connection.send_message(message)
        if refused:
            raise OSError("Delivery refused")


async def deliver_mail(db: AsyncSession, delivery_id: str, *, settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    row = await db.get(LocalAuthDelivery, delivery_id)
    if row is None or row.ciphertext is None or row.sent_at is not None:
        return
    user = await db.get(User, row.user_id)
    grant = await db.get(LocalAuthGrant, row.grant_id) if row.grant_id else None
    expires = coerce_utc(row.expires_at)
    valid = native_identity_selected(settings) and user is not None and expires is not None and expires > utc_now()
    if row.grant_id:
        valid = valid and grant is not None and user is not None and grant_active(grant, user, row.installation_id)
    if not valid:
        row.ciphertext, row.status = None, "cancelled"
        return
    try:
        from app.services.identity_installation import validate_installation_binding

        binding = await validate_installation_binding(db, settings=settings)
        if binding.installation_id != row.installation_id:
            raise ValueError("Delivery installation mismatch")
        keys = LocalKeyring.load(settings.local_auth_keyring_file)
        plaintext = keys.decrypt(
            "delivery",
            row.key_id,
            row.ciphertext,
            [row.installation_id, str(row.user_id), row.id, row.grant_id or "notice"],
        )
        payload = json.loads(plaintext)
        # No User/grant row locks are held across network I/O. A concurrently
        # revoked link can still be mailed, but can never be redeemed afterward.
        await asyncio.to_thread(send_smtp, settings, delivery_id=row.id, payload=payload)
    except Exception:
        raise RetryableOutboxError("Local identity delivery unavailable") from None
    row.sent_at, row.status, row.ciphertext = utc_now(), "sent", None
    db.add(row)


async def purge_expired_delivery_secrets(db: AsyncSession) -> None:
    await db.execute(
        update(LocalAuthDelivery)
        .execution_options(synchronize_session="fetch")
        .where(LocalAuthDelivery.expires_at <= utc_now(), LocalAuthDelivery.ciphertext.is_not(None))
        .values(ciphertext=None, status="expired")
    )
