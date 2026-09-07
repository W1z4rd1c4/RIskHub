from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.models.department import Department

ORG_CHART_LOCK_KEY = "org_chart"


async def acquire_org_chart_lock(db: AsyncSession) -> None:
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": ORG_CHART_LOCK_KEY})


async def validate_department_manager_membership(
    db: AsyncSession,
    *,
    department_id: int | None,
    manager_id: int | None,
) -> None:
    if manager_id is None:
        return

    manager = (await db.execute(select(User).where(User.id == manager_id))).scalar_one_or_none()
    if not manager:
        raise HTTPException(status_code=400, detail="Manager user not found")
    if not manager.is_active:
        raise HTTPException(status_code=400, detail="Department manager must be active")
    if department_id is None or manager.department_id != department_id:
        raise HTTPException(status_code=400, detail="Department manager must belong to the selected department")


async def validate_no_manager_cycle(
    db: AsyncSession,
    *,
    user_id: int | None,
    new_manager_id: int | None,
    max_depth: int = 64,
) -> None:
    if user_id is None or new_manager_id is None:
        return
    if new_manager_id == user_id:
        raise HTTPException(status_code=400, detail="User manager hierarchy cannot contain a cycle")

    if db.get_bind().dialect.name == "postgresql":
        result = await db.execute(
            text(
                """
                WITH RECURSIVE manager_chain(id, manager_id, depth, path) AS (
                    SELECT id, manager_id, 1, ARRAY[id]
                    FROM users
                    WHERE id = :new_manager_id
                    UNION ALL
                    SELECT users.id, users.manager_id, manager_chain.depth + 1, manager_chain.path || users.id
                    FROM users
                    JOIN manager_chain ON users.id = manager_chain.manager_id
                    WHERE manager_chain.manager_id IS NOT NULL
                      AND manager_chain.depth < :max_depth
                      AND NOT users.id = ANY(manager_chain.path)
                )
                SELECT
                    COALESCE(bool_or(id = :user_id), false) AS has_cycle,
                    COALESCE(bool_or(manager_id IS NOT NULL AND depth >= :max_depth), false) AS exceeds_depth
                FROM manager_chain
                """
            ),
            {"user_id": user_id, "new_manager_id": new_manager_id, "max_depth": max_depth},
        )
        row = result.mappings().one()
        if row["has_cycle"]:
            raise HTTPException(status_code=400, detail="User manager hierarchy cannot contain a cycle")
        if row["exceeds_depth"]:
            raise HTTPException(status_code=400, detail="User manager hierarchy exceeds the maximum allowed depth")
        return

    seen_user_ids = {user_id}
    current_manager_id = new_manager_id
    for _ in range(max_depth):
        if current_manager_id in seen_user_ids:
            raise HTTPException(status_code=400, detail="User manager hierarchy cannot contain a cycle")

        seen_user_ids.add(current_manager_id)
        result = await db.execute(select(User.manager_id).where(User.id == current_manager_id))
        manager_id = result.scalar_one_or_none()
        if manager_id is None:
            return
        current_manager_id = manager_id

    raise HTTPException(status_code=400, detail="User manager hierarchy exceeds the maximum allowed depth")


async def validate_dept_manager_dept_change(
    db: AsyncSession,
    *,
    user: User,
    new_department_id: int | None,
) -> None:
    if user.department_id is None or new_department_id == user.department_id:
        return

    managed_department_id = (
        await db.execute(
            select(Department.id).where(Department.id == user.department_id, Department.manager_id == user.id)
        )
    ).scalar_one_or_none()
    if managed_department_id is not None:
        raise HTTPException(status_code=400, detail="Clear the department manager before moving this user")


async def clear_manager_references_for_inactive_user(db: AsyncSession, *, user_id: int) -> None:
    await db.execute(update(Department).where(Department.manager_id == user_id).values(manager_id=None))
    from app.services._auth_session_workflow.authority import invalidate_user_sessions

    subordinates = (
        (await db.execute(select(User).where(User.manager_id == user_id).order_by(User.id).with_for_update(of=User)))
        .scalars()
        .all()
    )
    for subordinate in subordinates:
        subordinate.manager_id = None
        await invalidate_user_sessions(db=db, user=subordinate, reason="manager_deactivated")
