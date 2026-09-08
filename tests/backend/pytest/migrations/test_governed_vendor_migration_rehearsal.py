"""Automated ADR-010 PostgreSQL rehearsals for the #87 Vendor migration."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.engine import make_url

from tests.backend.pytest.migrations.conftest import rehearsal_head_after

ROOT = Path(__file__).resolve().parents[4]
BACKEND = ROOT / "backend"
TARGET_REVISION = "s8t9u0v1w2x3"
PREVIOUS_HEAD = "o5p6q7r8s9t0"


async def _database_command(url: str, command: str) -> None:
    import asyncpg

    parsed = make_url(url)
    connection = await asyncpg.connect(
        user=parsed.username,
        password=parsed.password,
        host=parsed.host,
        port=parsed.port,
        database="postgres",
    )
    try:
        await connection.execute(command)
    finally:
        await connection.close()


async def _target_connection(url: str):
    import asyncpg

    parsed = make_url(url)
    return await asyncpg.connect(
        user=parsed.username,
        password=parsed.password,
        host=parsed.host,
        port=parsed.port,
        database=parsed.database,
    )


async def _seed_vendor(url: str, marker: str) -> tuple[int, int]:
    connection = await _target_connection(url)
    try:
        role_id = await connection.fetchval(
            "INSERT INTO roles (name, display_name, description) "
            "VALUES ($1, $2, $3) RETURNING id",
            f"vendor_migration_{marker}",
            "Vendor migration",
            "Representative pre-migration authority",
        )
        department_id = await connection.fetchval(
            "INSERT INTO departments (name, code) VALUES ($1, $2) RETURNING id",
            f"Vendor migration {marker}",
            f"VM{marker[:3].upper()}",
        )
        user_id = await connection.fetchval(
            "INSERT INTO users (email, name, role_id, department_id, access_scope, is_active) "
            "VALUES ($1, $2, $3, $4, 'global', true) RETURNING id",
            f"{marker}@vendor-migration.test",
            "Vendor migration actor",
            role_id,
            department_id,
        )
        vendor_id = await connection.fetchval(
            "INSERT INTO vendors "
            "(name, process, outsourcing_owner_user_id, department_id, vendor_type, "
            "risk_score_1_5, supports_important_core_insurance_function, dora_relevant, "
            "is_significant_vendor, has_alternative_providers) "
            "VALUES ($1, $2, $3, $4, 'other', 3, false, false, false, false) RETURNING id",
            f"Preserved Vendor {marker}",
            "Operations",
            user_id,
            department_id,
        )
        return user_id, vendor_id
    finally:
        await connection.close()


async def _assert_head(url: str, *, marker: str, user_id: int, vendor_id: int) -> None:
    connection = await _target_connection(url)
    try:
        labels = [
            row["enumlabel"]
            for row in await connection.fetch(
                "SELECT e.enumlabel FROM pg_enum e "
                "JOIN pg_type t ON t.oid = e.enumtypid "
                "WHERE t.typname = 'approval_resource_type' ORDER BY e.enumsortorder"
            )
        ]
        assert labels == [
            "RISK",
            "CONTROL",
            "KRI",
            "PROCESS",
            "ASSET",
            "VENDOR",
            "THREAT",
        ]
        column = await connection.fetchrow(
            "SELECT data_type, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'vendors' "
            "AND column_name = 'governance_version'"
        )
        assert column is not None
        assert tuple(column.values()) in {
            ("integer", "NO", "1"),
            ("integer", "NO", "'1'::integer"),
        }
        preserved = await connection.fetchrow(
            "SELECT name, governance_version FROM vendors WHERE id = $1",
            vendor_id,
        )
        assert tuple(preserved.values()) == (f"Preserved Vendor {marker}", 1)
        constraints = {
            row["conname"]: (row["definition"], row["convalidated"])
            for row in await connection.fetch(
                "SELECT c.conname, pg_get_constraintdef(c.oid) AS definition, "
                "c.convalidated FROM pg_constraint c "
                "JOIN pg_class r ON r.oid = c.conrelid "
                "WHERE r.relname IN ('approval_requests', 'governed_mutation_proposals') "
                "AND c.conname IN ("
                "'ck_approval_requests_process_create_resource_identity', "
                "'ck_governed_mutation_process_create_resource_identity')"
            )
        }
        assert len(constraints) == 2
        assert all(validated for _, validated in constraints.values())
        assert all(
            "VENDOR" in definition.upper() for definition, _ in constraints.values()
        )
        scenario = await connection.fetchrow(
            "SELECT display_name, description, requires_approval, approver_roles, "
            "jsonb_typeof(approver_roles) AS roles_type "
            "FROM approval_scenarios WHERE key = 'protected_vendor_edit'"
        )
        assert scenario is not None
        assert scenario["display_name"] == "Protected Vendor mutations"
        assert scenario["description"] == (
            "Independent approval for Critical or Significant Vendor mutations"
        )
        assert scenario["requires_approval"] is True
        assert scenario["roles_type"] == "array"
        assert json.loads(scenario["approver_roles"]) == ["risk_manager", "cro"]
        approval_id = await connection.fetchval(
            "INSERT INTO approval_requests "
            "(resource_type, resource_id, resource_name, action_type, requested_by_id, "
            "reason, status, requires_privileged_approval, created_at) "
            "VALUES ('VENDOR', NULL, $1, 'CREATE', $2, $3, 'PENDING', false, now()) "
            "RETURNING id",
            f"Post-migration Vendor {marker}",
            user_id,
            "Vendor-create identity is accepted",
        )
        identity = await connection.fetchrow(
            "SELECT resource_type::text, resource_id, action_type::text "
            "FROM approval_requests WHERE id = $1",
            approval_id,
        )
        assert tuple(identity.values()) == ("VENDOR", None, "CREATE")
    finally:
        await connection.close()


def _alembic(url: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = url
    environment["TEST_DATABASE_URL"] = url
    environment.setdefault(
        "SECRET_KEY",
        "test-only-vendor-migration-secret-key-0000000000000000",
    )
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=BACKEND,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return completed


@pytest.mark.postgres
@pytest.mark.parametrize("starting_revision", [None, PREVIOUS_HEAD])
def test_governed_vendor_migration_rehearses_zero_and_previous_head_to_head(
    starting_revision: str | None,
) -> None:
    source_url = os.environ.get("TEST_DATABASE_URL", "")
    if not source_url.startswith("postgresql"):
        pytest.skip("ADR-010 migration rehearsal requires PostgreSQL")
    target_revision = rehearsal_head_after(TARGET_REVISION)
    database_name = f"riskhub_t87_rehearsal_{uuid4().hex[:12]}"
    quoted_name = '"' + database_name.replace('"', '""') + '"'
    target_url = (
        make_url(source_url)
        .set(database=database_name)
        .render_as_string(hide_password=False)
    )
    asyncio.run(_database_command(source_url, f"CREATE DATABASE {quoted_name}"))
    try:
        marker = "zero" if starting_revision is None else "o5"
        if starting_revision is None:
            _alembic(target_url, "upgrade", "head")
            user_id, vendor_id = asyncio.run(_seed_vendor(target_url, marker))
        else:
            _alembic(target_url, "upgrade", PREVIOUS_HEAD)
            user_id, vendor_id = asyncio.run(_seed_vendor(target_url, marker))
            _alembic(target_url, "upgrade", "head")
        assert f"{target_revision} (head)" in _alembic(
            target_url, "current"
        ).stdout
        heads = [
            line.strip()
            for line in _alembic(target_url, "heads").stdout.splitlines()
            if line.strip()
        ]
        assert heads == [f"{target_revision} (head)"]
        asyncio.run(
            _assert_head(
                target_url,
                marker=marker,
                user_id=user_id,
                vendor_id=vendor_id,
            )
        )
    finally:
        asyncio.run(
            _database_command(
                source_url,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{database_name}' AND pid <> pg_backend_pid()",
            )
        )
        asyncio.run(_database_command(source_url, f"DROP DATABASE {quoted_name}"))
