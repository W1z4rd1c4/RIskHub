"""Native purpose grants, factors, encrypted mail and refresh context.

Revision ID: u0v1w2x3y4z5
Revises: t9u0v1w2x3y4
"""

from alembic import op
import sqlalchemy as sa

revision = "u0v1w2x3y4z5"
down_revision = "t9u0v1w2x3y4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("local_email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("refresh_tokens", sa.Column("auth_method", sa.String(20), nullable=True))
    op.add_column("refresh_tokens", sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("refresh_tokens", sa.Column("factor_generation", sa.String(32), nullable=True))
    op.add_column("refresh_tokens", sa.Column("installation_id", sa.String(36), nullable=True))
    op.create_table(
        "local_auth_grants",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "installation_id", sa.String(36), sa.ForeignKey("installation_identity.installation_id"), nullable=False
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("token_version", sa.Integer(), nullable=False),
        sa.Column("factor_generation", sa.String(32), nullable=True),
        sa.Column("browser_hash", sa.String(64), nullable=True),
        sa.Column("context", sa.JSON(), nullable=False),
        sa.Column("failures", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("failures >= 0", name="ck_local_grant_failures"),
    )
    op.create_index("ix_local_auth_grants_user_purpose", "local_auth_grants", ["user_id", "purpose"])
    op.create_index("ix_local_auth_grants_expires_at", "local_auth_grants", ["expires_at"])
    op.create_table(
        "local_auth_factors",
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("generation", sa.String(32), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("encrypted_seed", sa.Text(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("setup_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_time_step", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "local_auth_recovery_codes",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("factor_generation", sa.String(32), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False, unique=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_local_auth_recovery_codes_user_id", "local_auth_recovery_codes", ["user_id"])
    op.create_table(
        "local_auth_deliveries",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column(
            "installation_id", sa.String(36), sa.ForeignKey("installation_identity.installation_id"), nullable=False
        ),
        sa.Column("grant_id", sa.String(32), sa.ForeignKey("local_auth_grants.id"), nullable=True),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_local_auth_deliveries_user_id", "local_auth_deliveries", ["user_id"])
    op.create_index("ix_local_auth_deliveries_expires_at", "local_auth_deliveries", ["expires_at"])
    # No historical email, password or MFA proof can be inferred by this migration.


def downgrade() -> None:
    raise RuntimeError("Native credential state is forward-only; retain verification or use maintenance/roll-forward")
