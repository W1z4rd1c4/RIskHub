"""Automated ADR-010 PostgreSQL rehearsals for the #86 Asset migration."""

from __future__ import annotations

import asyncio
import inspect
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
PREVIOUS_HEAD = "n4o5p6q7r8s9"


def test_migration_rehearsal_declares_genuinely_distinct_zero_and_n4_paths() -> None:
    source = inspect.getsource(
        test_governed_asset_migration_rehearses_zero_and_previous_head_to_head
    )
    assert "if starting_revision is None:" in source
    zero_lane = source.index('_alembic(target_url, "upgrade", "head")')
    n4_lane = source.index('_alembic(target_url, "upgrade", PREVIOUS_HEAD)')
    assert zero_lane < n4_lane
    assert "assert upgrade_path == expected_path" in source


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


async def _seed_previous_head_data(url: str, marker: str) -> tuple[int, int]:
    connection = await _target_connection(url)
    try:
        role_id = await connection.fetchval(
            "INSERT INTO roles (name, display_name, description) "
            "VALUES ($1, $2, $3) RETURNING id",
            f"migration_rehearsal_{marker}",
            "Migration rehearsal",
            "Representative pre-migration authority row",
        )
        user_id = await connection.fetchval(
            "INSERT INTO users (email, name, role_id, access_scope, is_active) "
            "VALUES ($1, $2, $3, 'global', true) RETURNING id",
            f"{marker}@migration.test",
            "Migration rehearsal actor",
            role_id,
        )
        asset_id = await connection.fetchval(
            "INSERT INTO assets (name, notes) VALUES ($1, $2) RETURNING id",
            f"Preserved Asset {marker}",
            f"pre-head-{marker}",
        )
        return user_id, asset_id
    finally:
        await connection.close()


async def _assert_governed_asset_head_contract(
    url: str,
    *,
    marker: str,
    user_id: int,
    asset_id: int,
) -> None:
    connection = await _target_connection(url)
    try:
        enum_labels = await connection.fetch(
            "SELECT e.enumlabel FROM pg_enum e "
            "JOIN pg_type t ON t.oid = e.enumtypid "
            "WHERE t.typname = 'approval_resource_type' ORDER BY e.enumsortorder"
        )
        assert [row["enumlabel"] for row in enum_labels] == [
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
            "WHERE table_schema = 'public' AND table_name = 'assets' "
            "AND column_name = 'governance_version'"
        )
        assert column is not None
        assert column["data_type"] == "integer"
        assert column["is_nullable"] == "NO"
        assert column["column_default"] in {"1", "'1'::integer"}
        assert (
            await connection.fetchval(
                "SELECT count(*) FROM assets WHERE governance_version IS NULL "
                "OR governance_version <> 1"
            )
            == 0
        )
        preserved = await connection.fetchrow(
            "SELECT name, notes, governance_version FROM assets WHERE id = $1",
            asset_id,
        )
        assert tuple(preserved.values()) == (
            f"Preserved Asset {marker}",
            f"pre-head-{marker}",
            1,
        )

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
        assert set(constraints) == {
            "ck_approval_requests_process_create_resource_identity",
            "ck_governed_mutation_process_create_resource_identity",
        }
        assert all(validated for _, validated in constraints.values())
        assert all(
            "ASSET" in definition.upper() for definition, _ in constraints.values()
        )
        assert (
            await connection.fetchval(
                "SELECT count(*) FROM approval_requests WHERE NOT ("
                "(resource_id IS NULL AND resource_type IN ('PROCESS', 'ASSET') "
                "AND action_type = 'CREATE') OR (resource_id IS NOT NULL AND NOT ("
                "resource_type IN ('PROCESS', 'ASSET') AND action_type = 'CREATE')))"
            )
            == 0
        )
        assert (
            await connection.fetchval(
                "SELECT count(*) FROM governed_mutation_proposals WHERE NOT ("
                "(primary_resource_id IS NULL AND ((primary_resource_type = 'process' "
                "AND mutation_kind = 'process.create') OR (primary_resource_type = 'asset' "
                "AND mutation_kind = 'asset.create'))) OR (primary_resource_id IS NOT NULL "
                "AND NOT ((primary_resource_type = 'process' AND mutation_kind = 'process.create') "
                "OR (primary_resource_type = 'asset' AND mutation_kind = 'asset.create'))))"
            )
            == 0
        )

        scenario = await connection.fetchrow(
            "SELECT display_name, description, requires_approval, approver_roles, "
            "jsonb_typeof(approver_roles) AS roles_type "
            "FROM approval_scenarios WHERE key = 'protected_asset_edit'"
        )
        assert scenario is not None
        assert scenario["display_name"] == "Protected Asset mutations"
        assert scenario["description"] == (
            "Independent approval for CIF or Critical Asset mutations"
        )
        assert scenario["requires_approval"] is True
        assert scenario["roles_type"] == "array"
        assert json.loads(scenario["approver_roles"]) == ["risk_manager", "cro"]

        approval_id = await connection.fetchval(
            "INSERT INTO approval_requests "
            "(resource_type, resource_id, resource_name, action_type, requested_by_id, "
            "reason, status, requires_privileged_approval, created_at) "
            "VALUES ('ASSET', NULL, $1, 'CREATE', $2, $3, 'PENDING', false, now()) "
            "RETURNING id",
            f"Post-migration Asset {marker}",
            user_id,
            "Post-migration Asset-create identity is accepted",
        )
        post = await connection.fetchrow(
            "SELECT resource_type::text, resource_id, action_type::text "
            "FROM approval_requests WHERE id = $1",
            approval_id,
        )
        assert tuple(post.values()) == ("ASSET", None, "CREATE")
    finally:
        await connection.close()


def _alembic(url: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = url
    environment["TEST_DATABASE_URL"] = url
    environment.setdefault(
        "SECRET_KEY",
        "test-only-migration-rehearsal-secret-key-0000000000000000",
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
def test_governed_asset_migration_rehearses_zero_and_previous_head_to_head(
    starting_revision: str | None,
) -> None:
    source_url = os.environ.get("TEST_DATABASE_URL", "")
    if not source_url.startswith("postgresql"):
        pytest.skip("ADR-010 migration rehearsal requires PostgreSQL")
    target_revision = rehearsal_head_after(TARGET_REVISION)
    database_name = f"riskhub_t86_rehearsal_{uuid4().hex[:12]}"
    quoted_name = '"' + database_name.replace('"', '""') + '"'
    target_url = (
        make_url(source_url)
        .set(database=database_name)
        .render_as_string(hide_password=False)
    )
    asyncio.run(_database_command(source_url, f"CREATE DATABASE {quoted_name}"))
    try:
        marker = "zero" if starting_revision is None else "n4"
        upgrade_path: list[tuple[str, str]] = []
        if starting_revision is None:
            completed = _alembic(target_url, "upgrade", "head")
            upgrade_path.append(tuple(completed.args[-2:]))
            user_id, asset_id = asyncio.run(
                _seed_previous_head_data(target_url, marker)
            )
            expected_path = [("upgrade", "head")]
        else:
            completed = _alembic(target_url, "upgrade", PREVIOUS_HEAD)
            upgrade_path.append(tuple(completed.args[-2:]))
            user_id, asset_id = asyncio.run(
                _seed_previous_head_data(target_url, marker)
            )
            completed = _alembic(target_url, "upgrade", "head")
            upgrade_path.append(tuple(completed.args[-2:]))
            expected_path = [
                ("upgrade", PREVIOUS_HEAD),
                ("upgrade", "head"),
            ]
        assert upgrade_path == expected_path
        current = _alembic(target_url, "current").stdout
        assert f"{target_revision} (head)" in current
        heads = [
            line.strip()
            for line in _alembic(target_url, "heads").stdout.splitlines()
            if line.strip()
        ]
        assert heads == [f"{target_revision} (head)"]
        asyncio.run(
            _assert_governed_asset_head_contract(
                target_url,
                marker=marker,
                user_id=user_id,
                asset_id=asset_id,
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


@pytest.mark.parametrize("required_revision", [PREVIOUS_HEAD, TARGET_REVISION])
def test_rehearsal_head_keeps_required_revision_in_ancestry(required_revision: str) -> None:
    assert rehearsal_head_after(required_revision)


def test_rehearsal_head_rejects_missing_contract_revision() -> None:
    with pytest.raises(AssertionError, match="Required revision .* is not an ancestor"):
        rehearsal_head_after("not-a-contract-revision")
