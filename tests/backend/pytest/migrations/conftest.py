"""Postgres-lane fixtures for vendor migration tests."""

from __future__ import annotations

import os
import sys
from importlib import util
from pathlib import Path
from types import ModuleType
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.exceptions import MigrationAlreadyAppliedError

POSTGRES_URL = os.environ.get("TEST_DATABASE_URL")
MIGRATION_MODULE_NAME = "riskhub_k6l7m8n9o0p1_vendor_link_cascade_and_status_drop"
MIGRATION_PATH = (
    Path(__file__).resolve().parents[4]
    / "backend"
    / "alembic"
    / "versions"
    / "k6l7m8n9o0p1_vendor_link_cascade_and_status_drop.py"
)


def rehearsal_head_after(required_revision: str) -> str:
    """Resolve this checkout's single head without accepting a missing contract revision."""
    backend = Path(__file__).resolve().parents[4] / "backend"
    script = ScriptDirectory.from_config(Config(str(backend / "alembic.ini")))
    heads = script.get_heads()
    assert len(heads) == 1, f"Migration rehearsal requires one head, found {heads}"
    head = heads[0]
    ancestors = {revision.revision for revision in script.walk_revisions(head=head)}
    assert required_revision in ancestors, f"Required revision {required_revision} is not an ancestor of {head}"
    return head


def load_vendor_migration() -> ModuleType:
    """Load the migration module from the Alembic versions directory."""

    if not MIGRATION_PATH.exists():
        raise ModuleNotFoundError(f"Migration file not found: {MIGRATION_PATH}")
    spec = util.spec_from_file_location(MIGRATION_MODULE_NAME, MIGRATION_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load migration module from {MIGRATION_PATH}")
    module = util.module_from_spec(spec)
    sys.modules[MIGRATION_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


def run_vendor_migration_upgrade(sync_connection) -> None:
    """Run the migration upgrade body with Alembic's operations proxy bound."""

    context = MigrationContext.configure(sync_connection)
    with Operations.context(context):
        try:
            load_vendor_migration().upgrade()
        except Exception as exc:
            message = str(exc).lower()
            if "already" in message or "does not exist" in message or "no such column" in message:
                raise MigrationAlreadyAppliedError(f"Vendor status-removal migration already applied: {exc}") from exc
            raise


def _require_postgres() -> str:
    if not POSTGRES_URL or "postgresql" not in POSTGRES_URL:
        pytest.skip("TEST_DATABASE_URL not set to a Postgres URL; skipping postgres-lane test.")
    return POSTGRES_URL


@pytest_asyncio.fixture
async def postgres_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Engine connected to the post-upgrade test DB."""

    engine = create_async_engine(_require_postgres(), echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def postgres_session(postgres_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Session bound to the post-upgrade engine."""

    factory = async_sessionmaker(postgres_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def postgres_engine_pre_migration() -> AsyncGenerator[AsyncEngine, None]:
    """Engine pinned at revision j5k6l7m8n9o0."""

    pre_url = os.environ.get("TEST_DATABASE_URL_PRE_MIGRATION")
    if not pre_url:
        pytest.skip("TEST_DATABASE_URL_PRE_MIGRATION not set; skipping pre-migration test.")
    engine = create_async_engine(pre_url, echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def seeded_vendor(postgres_session: AsyncSession):
    """Insert a vendor so cascade-delete tests have data to delete."""

    result = await postgres_session.execute(
        text(
            "INSERT INTO vendors (name, process, vendor_type, "
            "risk_score_1_5, supports_important_core_insurance_function, "
            "dora_relevant, is_significant_vendor, has_alternative_providers, "
            "is_archived, outsourcing_owner_user_id, created_at, updated_at) "
            "VALUES ('TestCascade', 'p', 'ict', 1, false, false, false, false, "
            "false, 1, now(), now()) RETURNING id"
        )
    )
    vendor_id = result.scalar_one()
    await postgres_session.commit()

    class _Vendor:
        id = vendor_id

    yield _Vendor()
