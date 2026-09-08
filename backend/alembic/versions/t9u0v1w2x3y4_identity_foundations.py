"""Persist identity binding and independent local account suspension.

Revision ID: t9u0v1w2x3y4
Revises: s8t9u0v1w2x3
Forward-only. No binding is inferred from environment variables during migration.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "t9u0v1w2x3y4"
down_revision: Union[str, Sequence[str], None] = "s8t9u0v1w2x3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "installation_identity",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("installation_id", sa.String(36), nullable=False, unique=True),
        sa.Column("auth_mode", sa.String(20), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("contract_version", sa.Integer(), nullable=False),
        sa.Column("established_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("establishment_source", sa.String(255), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_installation_identity_singleton"),
        sa.CheckConstraint("contract_version = 1", name="ck_installation_identity_version"),
        sa.CheckConstraint(
            "(auth_mode = 'microsoft_sso' AND tenant_id IS NOT NULL) OR "
            "(auth_mode = 'password' AND tenant_id IS NULL)",
            name="ck_installation_identity_profile",
        ),
    )
    op.add_column("users", sa.Column("local_suspended", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("local_suspended_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("local_enrollment_state", sa.String(20), nullable=True))
    # Inactive accounts are never reactivated by migration. Preserve known upstream
    # denial; unexplained/manual inactivity becomes an explicit local suspension.
    op.execute(
        sa.text(
            "UPDATE users SET local_suspended = true, local_suspended_at = CURRENT_TIMESTAMP "
            "WHERE is_active = false AND (external_id IS NULL OR deprovision_reason IS NULL "
            "OR deprovision_reason NOT IN ('ad_deprovision', 'missing', 'directory_disabled'))"
        )
    )
    with op.batch_alter_table("users") as batch:
        batch.create_check_constraint(
            "ck_users_local_enrollment_state",
            "local_enrollment_state IS NULL OR local_enrollment_state IN ('invited', 'password_set', 'enrolled')",
        )


def downgrade() -> None:
    raise NotImplementedError("Forward-only identity migration; use the reviewed compatible restore procedure.")
