"""
Pytest configuration and fixtures for backend tests.
"""
# ruff: noqa: E402

import os

# Ensure app can import in test runs without requiring production secrets.
# Must run before importing any app modules that call get_settings() at import time.
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-chars-minimum-value")


def _normalize_async_database_url(url: str) -> str:
    """Normalize a DB URL to an async SQLAlchemy URL suitable for create_async_engine()."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql+psycopg2://"):
        return url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite://"):
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


# Default is fast SQLite in-memory. Override by exporting TEST_DATABASE_URL.
TEST_DATABASE_URL = _normalize_async_database_url(os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:"))
os.environ["TEST_DATABASE_URL"] = TEST_DATABASE_URL
# Ensure app settings and Alembic use the test database during test runs.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

import asyncio
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterator, Callable, Generator
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from syrupy.assertion import SnapshotAssertion
from syrupy.extensions.amber import AmberSnapshotExtension
from syrupy.location import PyTestLocation

# Tests now live outside /backend, so add backend root explicitly for imports.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BACKEND_ROOT = _REPO_ROOT / "backend"
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models import Department, Risk, Role, User
from app.models.risk import RiskStatus
from app.models.user import AccessScope

_ALEMBIC_INI_PATH = _BACKEND_ROOT / "alembic.ini"
_USING_POSTGRES = TEST_DATABASE_URL.startswith("postgresql")


@dataclass(frozen=True)
class AlembicLiveDb:
    database_url: str
    current_revision: str | None
    head_revision: str | None


@pytest.fixture
def alembic_live_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[AlembicLiveDb, None, None]:
    """Create a disposable migration-versioned DB and report revision state.

    SQLite cannot execute several historical ALTER CONSTRAINT migrations. The fast
    harness therefore creates metadata and stamps the disposable DB at head. The
    Postgres gate remains responsible for exercising the real Alembic migration
    chain against a production-like dialect.
    """
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    from app.core.settings import get_settings

    db_path = tmp_path / "riskhub-alembic-live.db"
    database_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("TEST_DATABASE_URL", database_url.replace("sqlite://", "sqlite+aiosqlite://", 1))
    get_settings.cache_clear()

    alembic_cfg = Config(str(_ALEMBIC_INI_PATH))
    script = ScriptDirectory.from_config(alembic_cfg)
    head_revision = script.get_current_head()

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            Base.metadata.create_all(connection)
            connection.execute(text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL)"))
            connection.execute(text("DELETE FROM alembic_version"))
            connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": head_revision},
            )
        with engine.connect() as connection:
            current_revision = MigrationContext.configure(connection).get_current_revision()
        yield AlembicLiveDb(
            database_url=database_url,
            current_revision=current_revision,
            head_revision=head_revision,
        )
    finally:
        engine.dispose()
        get_settings.cache_clear()


@pytest.fixture
def frozen_clock():
    from freezegun import freeze_time

    frozen_now = datetime(2026, 5, 7, 12, 0, 0, tzinfo=UTC)
    with freeze_time(frozen_now):
        yield


@pytest.fixture
def stable_uuid():
    counter = 0

    def next_uuid() -> UUID:
        nonlocal counter
        counter += 1
        return UUID(f"00000000-0000-7000-8000-{counter:012d}")

    return next_uuid


_REDACT_EXACT = {"id", "trace_id", "request_id", "ip", "email"}


class RedactingSnapshotExtension(AmberSnapshotExtension):
    """Syrupy extension that redacts volatile identity and timestamp fields."""

    @classmethod
    def _redact(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {
                key: "<redacted>" if cls._should_redact_key(str(key)) else cls._redact(value)
                for key, value in data.items()
            }
        if isinstance(data, list):
            return [cls._redact(value) for value in data]
        if isinstance(data, tuple):
            return tuple(cls._redact(value) for value in data)
        return data

    @staticmethod
    def _should_redact_key(key: str) -> bool:
        return key in _REDACT_EXACT or key.endswith("_at")

    def serialize(self, data: Any, **kwargs: Any) -> str:
        return super().serialize(self._redact(data), **kwargs)


@pytest.fixture
def snapshot(request: pytest.FixtureRequest) -> SnapshotAssertion:
    return SnapshotAssertion(
        update_snapshots=request.config.option.update_snapshots,
        extension_class=RedactingSnapshotExtension,
        test_location=PyTestLocation(request.node),
        session=request.session.config._syrupy,
    )


@pytest.fixture
def redacting_snapshot_extension() -> type[RedactingSnapshotExtension]:
    return RedactingSnapshotExtension


def pytest_configure(config: pytest.Config) -> None:
    # Ensure marker availability even when pytest rootdir resolves to repository root.
    config.addinivalue_line(
        "markers",
        "redis_integration: Tests that require Docker-backed Redis fault-injection/integration",
    )
    config.addinivalue_line(
        "markers",
        "postgres: Tests that require PostgreSQL behavior or a Postgres test database",
    )
    config.addinivalue_line(
        "markers",
        "contract: Architecture, documentation, and repository invariant-lock tests",
    )


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.run_until_complete(loop.shutdown_default_executor())
    loop.close()
    asyncio.set_event_loop(None)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """
    Debug-only thread dump for diagnosing interpreter exit hangs.

    Enable by setting PYTEST_THREAD_DEBUG=1.
    """
    if os.getenv("PYTEST_THREAD_DEBUG") != "1":
        return

    import sys
    import threading
    import traceback

    non_daemon_threads = [
        t for t in threading.enumerate() if t is not threading.main_thread() and t.is_alive() and not t.daemon
    ]
    if non_daemon_threads:
        print("\nNon-daemon threads still alive at pytest_sessionfinish (will hang interpreter exit):")
        frames = sys._current_frames()
        for t in non_daemon_threads:
            print(f"- {t.name} ident={t.ident}")
            frame = frames.get(t.ident)
            if frame is not None:
                traceback.print_stack(frame)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _dispose_app_engine_at_session_end(event_loop) -> AsyncGenerator[None, None]:
    """
    Ensure the app-global SQLAlchemy engine is disposed at end-of-session.

    The app constructs an AsyncEngine during app creation and stores it on
    app.state. If any test path causes it to open a SQLite+aiosqlite connection,
    the aiosqlite worker thread can keep the interpreter alive unless the engine
    is disposed.
    """
    yield
    db_engine = getattr(app.state, "db_engine", None)
    if db_engine is not None:
        await db_engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def async_engine():
    """Create async engine for each test."""
    if _USING_POSTGRES:
        engine = create_async_engine(TEST_DATABASE_URL)
        yield engine
        await engine.dispose()
        return

    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def migrate_postgres_db() -> None:
    """Apply Alembic migrations once per test session when using PostgreSQL."""
    if not _USING_POSTGRES:
        return

    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config(str(_ALEMBIC_INI_PATH))
    command.upgrade(alembic_cfg, "head")


@pytest_asyncio.fixture(scope="function")
async def db_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a new database session for each test."""
    async_session_maker = async_sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        if _USING_POSTGRES:
            table_names = [table.name for table in Base.metadata.sorted_tables]
            if table_names:
                quoted_names = ", ".join(f'"{name}"' for name in table_names)
                await session.execute(text(f"TRUNCATE TABLE {quoted_names} RESTART IDENTITY CASCADE"))
                await session.commit()
        yield session


# Entity factories


@pytest_asyncio.fixture
async def test_department(db_session: AsyncSession) -> Department:
    """Create a test department."""
    dept = Department(name="Test Department", code="TEST", description="Test department for testing")
    db_session.add(dept)
    await db_session.commit()
    await db_session.refresh(dept)
    return dept


@pytest_asyncio.fixture
async def seed_risk_types(db_session: AsyncSession):
    """Seed default risk types for API validation."""
    from app.models.risk_type import RiskTypeConfig

    risk_types = [
        RiskTypeConfig(
            code="operational",
            display_name="Operational",
            description="Operational risk",
            color="#3b82f6",
            is_system=True,
            sort_order=1,
        ),
        RiskTypeConfig(
            code="strategic",
            display_name="Strategic",
            description="Strategic risk",
            color="#8b5cf6",
            is_system=True,
            sort_order=2,
        ),
    ]
    for rt in risk_types:
        db_session.add(rt)
    await db_session.commit()
    return risk_types


@pytest_asyncio.fixture
async def test_role(db_session: AsyncSession) -> Role:
    """Legacy wildcard superuser role fixture (backward-compatible)."""
    from app.models import Permission, RolePermission

    role = Role(name="admin", display_name="Administrator", description="Admin role for testing")
    db_session.add(role)
    await db_session.commit()  # Commit to get ID

    # Create wildcard permission
    perm = Permission(resource="*", action="*", description="Super admin access")
    db_session.add(perm)
    await db_session.commit()

    # Link
    role_perm = RolePermission(role_id=role.id, permission_id=perm.id)
    db_session.add(role_perm)
    await db_session.commit()

    await db_session.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_role_superuser_wildcard(test_role: Role) -> Role:
    """Explicit alias for wildcard superuser role fixture."""
    return test_role


@pytest_asyncio.fixture
async def test_role_platform_admin(db_session: AsyncSession) -> Role:
    """Create a canonical platform-admin role fixture (non-wildcard)."""
    from app.models import Permission, RolePermission

    role = Role(name="admin", display_name="Administrator", description="Platform admin role for testing")
    db_session.add(role)
    await db_session.commit()

    permission_specs = [
        ("users", "read", "View users"),
        ("users", "write", "Manage users"),
        ("activity_log", "read", "View activity log"),
        ("departments", "read", "View departments"),
        ("admin", "session.revoke", "Revoke user sessions"),
    ]
    permissions: list[Permission] = []
    for resource, action, description in permission_specs:
        perm = Permission(resource=resource, action=action, description=description)
        db_session.add(perm)
        permissions.append(perm)
    await db_session.commit()

    for perm in permissions:
        db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    await db_session.commit()

    await db_session.refresh(role)
    return role


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession, test_department: Department, test_role: Role) -> User:
    """Legacy wildcard superuser test user fixture (backward-compatible)."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    user = User(
        name="Test Admin",
        email="admin@test.com",
        department_id=test_department.id,
        role_id=test_role.id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    db_session.add(user)
    await db_session.commit()

    # Reload with all relationships
    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
            selectinload(User.manager),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_user_superuser_wildcard(test_user: User) -> User:
    """Explicit alias for wildcard superuser test user fixture."""
    return test_user


@pytest_asyncio.fixture
async def test_user_platform_admin(
    db_session: AsyncSession,
    test_department: Department,
    test_role_platform_admin: Role,
) -> User:
    """Create a canonical platform-admin test user fixture."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role as RoleModel
    from app.models import RolePermission

    user = User(
        name="Test Platform Admin",
        email="platform.admin@test.com",
        department_id=test_department.id,
        role_id=test_role_platform_admin.id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(RoleModel.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
            selectinload(User.manager),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_employee(db_session: AsyncSession) -> Role:
    """Create the canonical seeded employee role."""
    from app.models import Permission, RolePermission

    role = Role(name="employee", display_name="Employee", description="Standard employee role")
    db_session.add(role)
    await db_session.commit()

    permissions = [
        Permission(resource="risks", action="read", description="Read risks"),
        Permission(resource="controls", action="read", description="Read controls"),
        Permission(resource="controls", action="execute", description="Execute controls"),
        Permission(resource="vendors", action="read", description="Read vendors"),
        Permission(resource="vendor_contracts", action="read", description="Read vendor contracts"),
        Permission(resource="processes", action="read", description="Read ICT Register processes"),
        Permission(resource="assets", action="read", description="Read ICT Register assets"),
        Permission(resource="threats", action="read", description="Read ICT Register threats"),
        Permission(resource="departments", action="read", description="Read departments"),
        Permission(resource="reports", action="read", description="Read reports"),
    ]
    for p in permissions:
        db_session.add(p)
    await db_session.commit()

    for p in permissions:
        db_session.add(RolePermission(role_id=role.id, permission_id=p.id))
    await db_session.commit()

    return role


@pytest_asyncio.fixture
async def test_user_employee(db_session: AsyncSession, test_department: Department, test_role_employee: Role) -> User:
    """Create an employee user."""
    user = User(
        name="Test Employee",
        email="employee@test.com",
        department_id=test_department.id,
        role_id=test_role_employee.id,
        is_active=True,
        access_scope=AccessScope.DEPARTMENT,
    )
    db_session.add(user)
    await db_session.commit()

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_approval_requester(db_session: AsyncSession) -> Role:
    """Create a department-scoped non-privileged user that can initiate approval-bound edits/deletes."""
    from app.models import Permission, RolePermission

    role = Role(
        name="approval_requester",
        display_name="Approval Requester",
        description="Department-scoped requester for approval workflow tests",
    )
    db_session.add(role)
    await db_session.commit()

    permissions = [
        Permission(resource="risks", action="read", description="Read risks"),
        Permission(resource="risks", action="write", description="Request risk edits"),
        Permission(resource="risks", action="delete", description="Request risk deletions"),
        Permission(resource="controls", action="read", description="Read controls"),
        Permission(resource="controls", action="write", description="Request control edits"),
        Permission(resource="controls", action="delete", description="Request control deletions"),
        Permission(resource="controls", action="execute", description="Execute controls"),
        Permission(resource="vendors", action="read", description="Read vendors"),
        Permission(resource="departments", action="read", description="Read departments"),
        Permission(resource="reports", action="read", description="Read reports"),
    ]
    for permission in permissions:
        db_session.add(permission)
    await db_session.commit()

    for permission in permissions:
        db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    await db_session.commit()

    return role


@pytest_asyncio.fixture
async def test_user_approval_requester(
    db_session: AsyncSession,
    test_department: Department,
    test_role_approval_requester: Role,
) -> User:
    """Create a non-privileged approval requester user."""
    user = User(
        name="Test Approval Requester",
        email="approval.requester@test.com",
        department_id=test_department.id,
        role_id=test_role_approval_requester.id,
        is_active=True,
        access_scope=AccessScope.DEPARTMENT,
    )
    db_session.add(user)
    await db_session.commit()

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_directory_reader(db_session: AsyncSession) -> Role:
    """Create a test-only directory reader role with users:read and no access-view powers."""
    from app.models import Permission, RolePermission

    role = Role(name="directory_reader", display_name="Directory Reader", description="Test-only directory reader role")
    db_session.add(role)
    await db_session.commit()

    permission = Permission(resource="users", action="read", description="Read user directory")
    db_session.add(permission)
    await db_session.commit()

    db_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    await db_session.commit()

    return role


@pytest_asyncio.fixture
async def test_user_directory_reader(
    db_session: AsyncSession,
    test_department: Department,
    test_role_directory_reader: Role,
) -> User:
    """Create a department-scoped directory-only reader."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role as RoleModel
    from app.models import RolePermission

    user = User(
        name="Directory Reader",
        email="directory.reader@test.com",
        department_id=test_department.id,
        role_id=test_role_directory_reader.id,
        is_active=True,
        access_scope=AccessScope.DEPARTMENT,
    )
    db_session.add(user)
    await db_session.commit()

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(RoleModel.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
            selectinload(User.manager),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_risk_manager(db_session: AsyncSession) -> Role:
    """Create a risk manager role."""
    from app.models import Permission, RolePermission

    role = Role(name="risk_manager", display_name="Risk Manager", description="Risk Manager role")
    db_session.add(role)
    await db_session.commit()

    perms = [
        Permission(resource="approvals", action="*", description="Manage approvals"),
        Permission(resource="risks", action="read", description="Read risks"),
        Permission(resource="users", action="read", description="View user directory"),
    ]
    db_session.add_all(perms)
    await db_session.commit()
    for p in perms:
        await db_session.refresh(p)

    db_session.add_all([RolePermission(role_id=role.id, permission_id=p.id) for p in perms])
    await db_session.commit()

    return role


@pytest_asyncio.fixture
async def test_user_risk_manager(
    db_session: AsyncSession, test_department: Department, test_role_risk_manager: Role
) -> User:
    """Create a risk manager user."""
    user = User(
        name="Test Risk Manager",
        email="rm@test.com",
        department_id=test_department.id,
        role_id=test_role_risk_manager.id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    db_session.add(user)
    await db_session.commit()

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_cro(db_session: AsyncSession) -> Role:
    """Create a CRO role."""
    from app.models import Permission, RolePermission

    role = Role(name="cro", display_name="CRO", description="CRO role")
    db_session.add(role)
    await db_session.commit()

    # CRO has full wildcard access like admin
    perm = Permission(resource="*", action="*", description="Full access")
    db_session.add(perm)
    await db_session.commit()

    db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    await db_session.commit()

    return role


@pytest_asyncio.fixture
async def test_user_cro(db_session: AsyncSession, test_department: Department, test_role_cro: Role) -> User:
    """Create a CRO user."""
    user = User(
        name="Test CRO",
        email="cro@test.com",
        department_id=test_department.id,
        role_id=test_role_cro.id,
        is_active=True,
        access_scope=AccessScope.GLOBAL,
    )
    db_session.add(user)
    await db_session.commit()

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_role_department_head(db_session: AsyncSession) -> Role:
    """Create a department head role."""
    role = Role(name="department_head", display_name="Department Head", description="Department head role")
    db_session.add(role)
    await db_session.commit()
    # Dashboard and committee endpoints require risks:read.
    from app.models import Permission, RolePermission

    perm = Permission(resource="risks", action="read", description="Read risks")
    db_session.add(perm)
    await db_session.commit()
    await db_session.refresh(perm)
    db_session.add(RolePermission(role_id=role.id, permission_id=perm.id))
    await db_session.commit()
    return role


@pytest_asyncio.fixture
async def test_user_department_head(
    db_session: AsyncSession,
    test_department: Department,
    test_role_department_head: Role,
) -> User:
    """Create a department head user."""
    user = User(
        name="Test Department Head",
        email="depthead@test.com",
        department_id=test_department.id,
        role_id=test_role_department_head.id,
        is_active=True,
        access_scope=AccessScope.DEPARTMENT,
    )
    db_session.add(user)
    await db_session.commit()

    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.models import Role, RolePermission

    result = await db_session.execute(
        select(User)
        .options(
            selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission),
            selectinload(User.department),
        )
        .where(User.id == user.id)
    )
    return result.scalar_one()


@pytest_asyncio.fixture
async def test_risk(db_session: AsyncSession, test_department: Department, test_user_cro: User) -> Risk:
    """Create a test risk."""
    risk = Risk(
        risk_id_code="R-TEST-001",
        name="Test Risk",
        process="Test Process",
        description="Test Risk Description",
        category="Test Category",
        department_id=test_department.id,
        owner_id=test_user_cro.id,
        risk_type="operational",
        gross_probability=3,
        gross_impact=3,
        net_probability=2,
        net_impact=2,
        status=RiskStatus.active.value,
    )
    db_session.add(risk)
    await db_session.commit()
    await db_session.refresh(risk)
    return risk


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create an unauthenticated async test client."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def client_factory(db_session: AsyncSession):
    """Create async clients while centralizing app dependency overrides."""
    from app.api import deps
    from app.core import security
    from app.core.config import Settings, get_settings

    SettingsProvider = Settings | Callable[[], Settings] | None
    DbProvider = Callable[[], AsyncIterator[Any]] | None

    @asynccontextmanager
    async def _client_factory(
        *,
        user: User | None = None,
        current_user: User | None = None,
        settings: SettingsProvider = None,
        headers: dict[str, str] | None = None,
        db_override: DbProvider = None,
        raise_app_exceptions: bool = True,
    ) -> AsyncIterator[AsyncClient]:
        def override_settings() -> Settings:
            if callable(settings):
                return settings()
            return settings or Settings(mock_auth_enabled=True, debug=True)

        async def override_get_db() -> AsyncIterator[Any]:
            if db_override is not None:
                async for session in db_override():
                    yield session
                return
            yield db_session

        previous_overrides = dict(app.dependency_overrides)
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_settings] = override_settings

        if current_user is not None:

            async def override_get_current_user() -> User:
                return current_user

            app.dependency_overrides[deps.get_current_user] = override_get_current_user
            app.dependency_overrides[security.get_current_user] = override_get_current_user

        client_headers = dict(headers or {})
        if user is not None:
            client_headers.setdefault("X-Mock-User-Id", str(user.id))

        transport = ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions)
        try:
            async with AsyncClient(
                transport=transport,
                base_url="http://test",
                headers=client_headers or None,
            ) as ac:
                yield ac
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous_overrides)

    return _client_factory


@pytest_asyncio.fixture(scope="function")
async def auth_client(db_session: AsyncSession, test_user: User) -> AsyncGenerator[AsyncClient, None]:
    """Create authenticated client using legacy wildcard superuser fixture."""
    from app.api import deps
    from app.core import security

    async def override_get_db():
        yield db_session

    # IMPORTANT: Dependencies must be async if they perform DB operations or are used in async contexts
    async def override_get_current_user():
        return test_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user
    app.dependency_overrides[security.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def auth_client_superuser(
    db_session: AsyncSession,
    test_user_superuser_wildcard: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Explicit wildcard-superuser auth client fixture."""
    from app.api import deps
    from app.core import security

    async def override_get_db():
        yield db_session

    async def override_get_current_user():
        return test_user_superuser_wildcard

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user
    app.dependency_overrides[security.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_platform_admin(
    db_session: AsyncSession,
    test_user_platform_admin: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Client for canonical platform admin role using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_platform_admin.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_employee(db_session: AsyncSession, test_user_employee: User) -> AsyncGenerator[AsyncClient, None]:
    """Client for employee user using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_employee.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_approval_requester(
    db_session: AsyncSession,
    test_user_approval_requester: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Client for non-privileged approval-request workflow tests using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_approval_requester.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_risk_manager(
    db_session: AsyncSession, test_user_risk_manager: User
) -> AsyncGenerator[AsyncClient, None]:
    """Client for risk manager user using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_risk_manager.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_directory_reader(
    db_session: AsyncSession,
    test_user_directory_reader: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Client for the test-only directory reader using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_directory_reader.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(test_user: User) -> dict:
    """Convenience headers for mock-authenticated requests using the default test user."""
    return {"X-Mock-User-Id": str(test_user.id)}


@pytest_asyncio.fixture(scope="function")
async def client_cro(db_session: AsyncSession, test_user_cro: User) -> AsyncGenerator[AsyncClient, None]:
    """Client for CRO user using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_cro.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def client_department_head(
    db_session: AsyncSession,
    test_user_department_head: User,
) -> AsyncGenerator[AsyncClient, None]:
    """Client for department head user using header-based mock auth."""
    from app.core.config import Settings, get_settings

    def override_settings():
        return Settings(mock_auth_enabled=True, debug=True)

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = override_settings

    transport = ASGITransport(app=app)
    headers = {"X-Mock-User-Id": str(test_user_department_head.id)}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac

    app.dependency_overrides.clear()


# Native fixtures are inert unless explicitly requested by a test.
pytest_plugins = ["tests.backend.pytest._local_identity_fixtures"]
