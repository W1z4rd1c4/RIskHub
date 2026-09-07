"""Persistent deployment identity binding; never changed by normal startup."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class InstallationIdentity(Base):
    __tablename__ = "installation_identity"
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_installation_identity_singleton"),
        CheckConstraint("contract_version = 1", name="ck_installation_identity_version"),
        CheckConstraint(
            "(auth_mode = 'microsoft_sso' AND tenant_id IS NOT NULL) OR "
            "(auth_mode = 'password' AND tenant_id IS NULL)",
            name="ck_installation_identity_profile",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    installation_id: Mapped[str] = mapped_column(String(36), unique=True, default=lambda: str(uuid4()))
    auth_mode: Mapped[str] = mapped_column(String(20), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    contract_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    established_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    establishment_source: Mapped[str] = mapped_column(String(255), nullable=False)
