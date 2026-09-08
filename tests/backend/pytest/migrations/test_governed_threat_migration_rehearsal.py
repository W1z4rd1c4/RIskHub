"""Automated ADR-010 PostgreSQL rehearsals for the #88 Threat migrations."""

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
PREVIOUS_HEAD = "p6q7r8s9t0u1"


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


async def _seed_previous_head(
    url: str,
    marker: str,
    *,
    existing_scenario: bool,
) -> int:
    connection = await _target_connection(url)
    try:
        role_id = await connection.fetchval(
            "INSERT INTO roles (name, display_name, description) "
            "VALUES ($1, $2, $3) RETURNING id",
            f"threat_migration_{marker}",
            "Threat migration",
            "Representative pre-migration authority",
        )
        steward_id = await connection.fetchval(
            "INSERT INTO users (email, name, role_id, access_scope, is_active) "
            "VALUES ($1, $2, $3, 'global', true) RETURNING id",
            f"{marker}@threat-migration.test",
            "Threat migration steward",
            role_id,
        )
        threat_id = await connection.fetchval(
            "INSERT INTO threats (name, threat_steward_user_id) "
            "VALUES ($1, $2) RETURNING id",
            f"Preserved Threat {marker}",
            steward_id,
        )
        if existing_scenario:
            await connection.execute(
                "INSERT INTO approval_scenarios "
                "(key, display_name, description, requires_approval, approver_roles) "
                "VALUES ('accountability_reassignment', $1, $2, false, $3::jsonb)",
                "Preserved accountability policy",
                "Existing deployment policy must not be overwritten",
                json.dumps(["ciso"]),
            )
        return threat_id
    finally:
        await connection.close()


async def _assert_head(
    url: str,
    *,
    marker: str,
    threat_id: int,
) -> None:
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
        assert labels.count("THREAT") == 1

        column = await connection.fetchrow(
            "SELECT data_type, is_nullable, column_default "
            "FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'threats' "
            "AND column_name = 'governance_version'"
        )
        assert column is not None
        assert tuple(column.values()) in {
            ("integer", "NO", "1"),
            ("integer", "NO", "'1'::integer"),
        }
        preserved = await connection.fetchrow(
            "SELECT name, governance_version FROM threats WHERE id = $1",
            threat_id,
        )
        assert tuple(preserved.values()) == (f"Preserved Threat {marker}", 1)

        scenario = await connection.fetchrow(
            "SELECT display_name, description, requires_approval, approver_roles, "
            "jsonb_typeof(approver_roles) AS roles_type "
            "FROM approval_scenarios WHERE key = 'accountability_reassignment'"
        )
        assert scenario is not None
        if marker == "p6":
            assert scenario["display_name"] == "Preserved accountability policy"
            assert scenario["description"] == (
                "Existing deployment policy must not be overwritten"
            )
            assert scenario["requires_approval"] is False
            expected_roles = ["ciso"]
        else:
            assert scenario["display_name"] == "Accountability reassignments"
            assert scenario["description"] == (
                "Independent approval for accountable user or owning department changes"
            )
            assert scenario["requires_approval"] is True
            expected_roles = ["risk_manager", "cro"]
        assert scenario["roles_type"] == "array"
        assert json.loads(scenario["approver_roles"]) == expected_roles
    finally:
        await connection.close()


def _alembic(url: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = url
    environment["TEST_DATABASE_URL"] = url
    environment.setdefault(
        "SECRET_KEY",
        "test-only-threat-migration-secret-key-0000000000000000",
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
def test_governed_threat_migrations_rehearse_zero_and_previous_head_to_head(
    starting_revision: str | None,
) -> None:
    source_url = os.environ.get("TEST_DATABASE_URL", "")
    if not source_url.startswith("postgresql"):
        pytest.skip("ADR-010 migration rehearsal requires PostgreSQL")
    target_revision = rehearsal_head_after(TARGET_REVISION)
    database_name = f"riskhub_t88_rehearsal_{uuid4().hex[:12]}"
    quoted_name = '"' + database_name.replace('"', '""') + '"'
    target_url = (
        make_url(source_url)
        .set(database=database_name)
        .render_as_string(hide_password=False)
    )
    asyncio.run(_database_command(source_url, f"CREATE DATABASE {quoted_name}"))
    try:
        marker = "zero" if starting_revision is None else "p6"
        if starting_revision is None:
            _alembic(target_url, "upgrade", "head")
            threat_id = asyncio.run(
                _seed_previous_head(
                    target_url,
                    marker,
                    existing_scenario=False,
                )
            )
        else:
            _alembic(target_url, "upgrade", PREVIOUS_HEAD)
            threat_id = asyncio.run(
                _seed_previous_head(
                    target_url,
                    marker,
                    existing_scenario=True,
                )
            )
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
                threat_id=threat_id,
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
