from datetime import datetime
from enum import Enum as PyEnum
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, func
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.datetime_utils import coerce_utc
from app.db.base import Base

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.control import Control
    from app.models.control_execution import ControlExecution
    from app.models.department import Department
    from app.models.notification import Notification
    from app.models.process import Process
    from app.models.refresh_token import RefreshToken
    from app.models.risk import Risk
    from app.models.role import Role
    from app.models.threat import Threat
    from app.models.vendor import Vendor


class AccessScope(str, PyEnum):
    """Defines data access scope for a user."""

    GLOBAL = "global"
    DEPARTMENT = "department"
    MANAGER = "manager"


class User(Base):
    """User model with role-based access control."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[str | None] = mapped_column(String(255), unique=True, index=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    __table_args__ = (
        Index("ux_users_email_lower", func.lower(email), unique=True),
        CheckConstraint(
            "local_enrollment_state IS NULL OR local_enrollment_state IN ('invited', 'password_set', 'enrolled')",
            name="ck_users_local_enrollment_state",
        ),
    )
    name: Mapped[str] = mapped_column(String(255))
    job_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Entra-owned organizational metadata. This must never drive RiskHub authorization.
    entra_business_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Local suspension survives upstream directory changes. is_active is its effective projection.
    local_suspended: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false", nullable=False)
    local_suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # NULL denotes an existing Entra/legacy-development account, not native production enrollment.
    local_enrollment_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    employee_type: Mapped[str | None] = mapped_column(String(50), nullable=True, default="employee")
    token_version: Mapped[int] = mapped_column(default=0, server_default="0", nullable=False)

    local_email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Access scope (data visibility)
    access_scope: Mapped[AccessScope] = mapped_column(
        SQLEnum(
            AccessScope,
            name="access_scope",
            create_constraint=True,
            values_callable=lambda x: [e.value for e in x],
        ),
        default=AccessScope.DEPARTMENT,
        nullable=False,
    )

    # Authentication (nullable for future Entra ID integration)
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Role relationship
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"))
    role: Mapped["Role"] = relationship("Role", back_populates="users")

    # Department relationship (optional)
    department_id: Mapped[int | None] = mapped_column(ForeignKey("departments.id"), nullable=True)
    department: Mapped["Department"] = relationship("Department", back_populates="users", foreign_keys=[department_id])

    # Manager-employee hierarchy
    manager_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    manager: Mapped["User | None"] = relationship(
        "User", remote_side=[id], back_populates="subordinates", foreign_keys="User.manager_id"
    )
    subordinates: Mapped[list["User"]] = relationship("User", back_populates="manager", foreign_keys="User.manager_id")

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    directory_last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    directory_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    entra_business_role_last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    directory_sync_status: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    deprovisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deprovision_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    break_glass_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    break_glass_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    break_glass_granted_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    break_glass_granted_by_user: Mapped["User | None"] = relationship(
        "User", remote_side=[id], foreign_keys=[break_glass_granted_by_user_id]
    )

    # User preferences (synced across devices)
    preferred_theme: Mapped[str] = mapped_column(String(20), default="riskhub", server_default="riskhub")
    preferred_language: Mapped[str] = mapped_column(String(10), default="en", server_default="en")

    # Notification preferences (JSON blob for flexibility)
    # Structure: {"approval_pending": true, "approval_resolved": true, "kri_due_soon": true, ...}
    notification_preferences: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Control relationships
    owned_controls: Mapped[list["Control"]] = relationship(
        "Control", foreign_keys="Control.control_owner_id", back_populates="control_owner"
    )
    executed_controls: Mapped[list["ControlExecution"]] = relationship("ControlExecution", back_populates="executed_by")

    # Risk relationships
    owned_risks: Mapped[list["Risk"]] = relationship("Risk", foreign_keys="Risk.owner_id", back_populates="owner")
    stewarded_threats: Mapped[list["Threat"]] = relationship(
        "Threat", foreign_keys="Threat.threat_steward_user_id", back_populates="threat_steward"
    )
    owned_processes: Mapped[list["Process"]] = relationship(
        "Process", foreign_keys="Process.process_owner_user_id", back_populates="process_owner"
    )
    business_owned_assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        foreign_keys="Asset.business_owner_user_id",
        back_populates="business_owner",
    )
    ict_owned_assets: Mapped[list["Asset"]] = relationship(
        "Asset",
        foreign_keys="Asset.ict_owner_user_id",
        back_populates="ict_owner",
    )

    # Vendor relationships (Phase 18)
    owned_vendors: Mapped[list["Vendor"]] = relationship(
        "Vendor",
        foreign_keys="Vendor.outsourcing_owner_user_id",
        back_populates="outsourcing_owner",
    )

    # Notification relationship
    notifications: Mapped[list["Notification"]] = relationship("Notification", back_populates="user")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship("RefreshToken", back_populates="user")

    @property
    def manager_name(self) -> str | None:
        """Get manager's name if manager exists."""
        return self.manager.name if self.manager else None

    @property
    def department_name(self) -> str | None:
        """Get department name if department is assigned."""
        return self.department.name if self.department else None

    def has_active_break_glass(self, *, now: datetime) -> bool:
        expires_at = coerce_utc(self.break_glass_expires_at)
        current_time = coerce_utc(now)
        return bool(expires_at is not None and current_time is not None and expires_at > current_time)
