from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.activity_logger import log_activity
from app.core.config import Settings, get_settings
from app.core.datetime_utils import utc_now
from app.core.identity_policy import projected_account_active
from app.db.session import get_db
from app.models import User
from app.models.activity_log import ActivityAction, ActivityEntityType
from app.schemas.directory import DirectoryBreakGlassEnableRequest
from app.services._auth_session_workflow.authority import invalidate_user_sessions
from app.services._identity_authority_lock import lock_identity_transition
from app.services.ad_deprovision_service import ADDeprovisionService
from app.services.directory_provider_service import DirectoryProviderUnavailableError
from app.services.transaction_boundary import commit_service_transaction

from ._deps import require_platform_admin

router = APIRouter()


@router.post("/directory/check-user/{user_id}")
async def check_directory_user_status(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_platform_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        return await ADDeprovisionService.check_user_by_id(
            db,
            user_id=user_id,
            settings=settings,
            actor=admin_user,
            trigger="admin_check_user",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except DirectoryProviderUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/directory/check-all")
async def check_all_directory_users(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_platform_admin),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        return await ADDeprovisionService.check_all_users(
            db,
            settings=settings,
            actor=admin_user,
            trigger="admin_check_all",
        )
    except DirectoryProviderUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.post("/directory/break-glass-enable/{user_id}")
async def break_glass_enable_directory_user(
    user_id: int,
    payload: DirectoryBreakGlassEnableRequest,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_platform_admin),
) -> dict:
    user = await lock_identity_transition(db, user_id=user_id, actor=admin_user)
    if user.local_suspended:
        raise HTTPException(
            status_code=409, detail="Local suspension must be resolved separately from directory break-glass"
        )
    if not user.external_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User is not directory-linked")
    if user.deprovision_reason not in ADDeprovisionService.AUTO_DEPROVISION_REASONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Break-glass enable is only allowed for directory-deprovisioned users",
        )

    now = utc_now()
    user.break_glass_reason = payload.reason.strip()
    user.break_glass_expires_at = now + payload.expires_delta
    user.break_glass_granted_by_user_id = admin_user.id
    user.is_active = projected_account_active(user)
    await invalidate_user_sessions(db=db, user=user, reason="directory_break_glass_granted")
    db.add(user)

    await log_activity(
        db=db,
        actor=admin_user,
        action=ActivityAction.UPDATE,
        entity_type=ActivityEntityType.USER,
        entity_id=user.id,
        entity_name=user.name,
        description=(
            "Break-glass enabled for directory-linked user "
            f"(expires_in_hours={payload.expires_in_hours}, reason={payload.reason.strip()})"
        ),
    )
    await commit_service_transaction(db)
    return {"status": "success", "user_id": user.id}
