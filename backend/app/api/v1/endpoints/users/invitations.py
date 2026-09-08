"""Admin-only local enrollment and nonsecret status adapters."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.api.v1.endpoints.auth._local_transport import SafeAuthRoute, native_context, native_read_context
from app.db.session import get_db
from app.models import User
from app.schemas.local_auth import (
    AcceptedResponse,
    CompletedResponse,
    InvitationRequest,
    InvitationResponse,
    LocalIdentityStatusResponse,
    ReasonRequest,
)
from app.services._local_auth.admin import admin_reset, identity_status
from app.services._local_auth.common import NativeContext
from app.services._local_auth.enrollment import invite_user, manage_invitation

router = APIRouter(route_class=SafeAuthRoute)


@router.post("/invitations", response_model=InvitationResponse, status_code=202)
async def invite(
    data: InvitationRequest,
    ctx: NativeContext = Depends(native_context),
    actor: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await invite_user(db, ctx, actor, data)


@router.post("/{user_id}/invitations/resend", response_model=InvitationResponse, status_code=202)
async def resend(
    user_id: int,
    data: ReasonRequest,
    ctx: NativeContext = Depends(native_context),
    actor: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await manage_invitation(db, ctx, actor, user_id, resend=True, reason=data.reason)


@router.post("/{user_id}/invitations/cancel", response_model=CompletedResponse)
async def cancel(
    user_id: int,
    data: ReasonRequest,
    ctx: NativeContext = Depends(native_context),
    actor: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await manage_invitation(db, ctx, actor, user_id, resend=False, reason=data.reason)
    return CompletedResponse(reauthentication_required=False)


@router.post("/{user_id}/password-reset", response_model=AcceptedResponse, status_code=202)
async def request_reset(
    user_id: int,
    data: ReasonRequest,
    ctx: NativeContext = Depends(native_context),
    actor: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await admin_reset(db, ctx, actor, user_id=user_id, reason=data.reason)
    return AcceptedResponse()


@router.get("/{user_id}/local-auth/status", response_model=LocalIdentityStatusResponse)
async def status(
    user_id: int,
    ctx: NativeContext = Depends(native_read_context),
    actor: User = Depends(deps.get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await identity_status(db, ctx, actor, user_id=user_id)
