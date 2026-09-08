"""Native factor, purpose-grant and encrypted-delivery state, never app sessions."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, BigInteger, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.datetime_utils import utc_now
from app.db.base import Base


def new_id() -> str:
    return uuid4().hex


class LocalAuthGrant(Base):
    __tablename__ = "local_auth_grants"
    __table_args__ = (
        CheckConstraint("failures >= 0", name="ck_local_grant_failures"),
        Index("ix_local_auth_grants_user_purpose", "user_id", "purpose"),
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    installation_id: Mapped[str] = mapped_column(ForeignKey("installation_identity.installation_id"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    token_version: Mapped[int] = mapped_column(Integer, nullable=False)
    factor_generation: Mapped[str | None] = mapped_column(String(32), nullable=True)
    browser_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LocalAuthFactor(Base):
    __tablename__ = "local_auth_factors"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    generation: Mapped[str] = mapped_column(String(32), nullable=False, default=new_id)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_seed: Mapped[str] = mapped_column(Text, nullable=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    setup_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_time_step: Mapped[int] = mapped_column(BigInteger, nullable=False, default=-1)


class LocalAuthRecoveryCode(Base):
    __tablename__ = "local_auth_recovery_codes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    factor_generation: Mapped[str] = mapped_column(String(32), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LocalAuthDelivery(Base):
    __tablename__ = "local_auth_deliveries"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    installation_id: Mapped[str] = mapped_column(ForeignKey("installation_identity.installation_id"), nullable=False)
    grant_id: Mapped[str | None] = mapped_column(ForeignKey("local_auth_grants.id"), nullable=True)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
