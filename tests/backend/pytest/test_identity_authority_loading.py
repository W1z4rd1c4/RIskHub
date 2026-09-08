"""Public identity edits retain eagerly loaded authority in fresh sessions."""

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.models import User


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["users", "access/users"])
async def test_manager_cycle_rejected_with_fresh_authority_relationships(
    async_engine: AsyncEngine,
    db_session: AsyncSession,
    client_factory,
    test_user: User,
    test_user_cro: User,
    test_user_employee: User,
    route: str,
):
    """A subordinate reload must not expire its manager's authorization graph."""
    # Each transport uses its authorized actor: Admin identity edit, CRO access edit.
    actor = test_user if route == "users" else test_user_cro
    subordinate = User(
        name="Managed subordinate",
        email="managed-subordinate@example.com",
        role_id=actor.role_id,
        department_id=test_user_employee.department_id,
        manager_id=test_user_employee.id,
        is_active=True,
    )
    db_session.add(subordinate)
    await db_session.commit()
    manager_id = test_user_employee.id
    subordinate_id = subordinate.id
    session_maker = async_sessionmaker(async_engine, expire_on_commit=False)

    async def independent_db():
        async with session_maker() as session:
            yield session

    async with client_factory(user=actor, db_override=independent_db) as client:
        response = await client.patch(
            f"/api/v1/{route}/{manager_id}", json={"manager_id": subordinate_id}
        )

    assert response.status_code == 400, response.json()
    assert response.json()["detail"] == "User manager hierarchy cannot contain a cycle"
    async with session_maker() as session:
        manager = await session.get(User, manager_id)
        subordinate = await session.get(User, subordinate_id)
        assert manager.manager_id is None
        assert subordinate.manager_id == manager_id
