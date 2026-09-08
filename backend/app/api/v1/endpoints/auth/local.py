"""Native credential adapters. Ordinary sessions still use the shared issuer."""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.tokens import clear_refresh_cookie
from app.db.session import get_db
from app.models import User
from app.schemas.auth import TokenResponse
from app.schemas.local_auth import (
    AcceptedResponse,
    ActionProofResponse,
    ChallengeRequest,
    CompletedResponse,
    EmailChangeCompleteRequest,
    EmailChangeRequest,
    EnrollmentStartRequest,
    FactorEnrollmentResponse,
    FactorSetupResponse,
    FactorVerifyRequest,
    LocalAuthChallenge,
    PasswordChangeRequest,
    RecentAuthenticationRequest,
    ResetCompleteRequest,
    ResetRequest,
)
from app.services._local_auth import credentials, enrollment, factors
from app.services._local_auth.common import NativeContext, atomic_local_work, commit_local

from ._local_transport import SafeAuthRoute, browser_binding, establish_browser, native_context
from ._shared import _build_token_response, _issue_refresh_session

router = APIRouter(prefix="/local", route_class=SafeAuthRoute)


@router.post("/enrollment/start", response_model=LocalAuthChallenge, status_code=202)
async def enrollment_start(
    data: EnrollmentStartRequest,
    request: Request,
    response: Response,
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    return await enrollment.start_enrollment(
        db,
        ctx,
        raw=data.grant.get_secret_value(),
        password=data.password.get_secret_value(),
        browser=establish_browser(request, response, ctx.settings),
    )


@router.post("/mfa/setup", response_model=FactorSetupResponse)
async def mfa_setup(
    data: ChallengeRequest,
    request: Request,
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    return await factors.setup_factor(db, ctx, raw=data.challenge.get_secret_value(), browser=browser_binding(request))


@router.post("/mfa/confirm", response_model=FactorEnrollmentResponse)
async def mfa_confirm(
    data: FactorVerifyRequest,
    request: Request,
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    return await factors.confirm_factor(
        db,
        ctx,
        raw=data.challenge.get_secret_value(),
        browser=browser_binding(request),
        code=data.code.get_secret_value(),
        method=data.method,
    )


@router.post("/mfa/verify", response_model=TokenResponse)
async def mfa_verify(
    data: FactorVerifyRequest,
    request: Request,
    response: Response,
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    async with atomic_local_work(db):
        outcome = await factors.verify_factor(
            db,
            ctx,
            raw=data.challenge.get_secret_value(),
            browser=browser_binding(request),
            code=data.code.get_secret_value(),
            method=data.method,
        )
        result = _build_token_response(outcome.user, settings=ctx.settings, local_context=outcome.session)
        await _issue_refresh_session(
            db=db,
            request=request,
            response=response,
            user=outcome.user,
            settings=ctx.settings,
            local_context=outcome.session,
        )
        await commit_local(db, "mfa_session")
        return result


@router.post("/recent-auth", response_model=ActionProofResponse)
async def recent_auth(
    data: RecentAuthenticationRequest,
    request: Request,
    user: User = Depends(deps.get_current_user),
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    return await factors.recent_authentication(db, ctx, user, data, browser=browser_binding(request))


@router.post("/password/reset/request", response_model=AcceptedResponse, status_code=202)
async def reset_request(
    data: ResetRequest, ctx: NativeContext = Depends(native_context), db: AsyncSession = Depends(get_db)
):
    await credentials.request_password_reset(db, ctx, email=str(data.email))
    return AcceptedResponse()


@router.post("/password/reset/complete", response_model=CompletedResponse)
async def reset_complete(
    data: ResetCompleteRequest,
    response: Response,
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    result = await credentials.complete_password_reset(
        db, ctx, raw=data.grant.get_secret_value(), password=data.password.get_secret_value()
    )
    clear_refresh_cookie(response, ctx.settings)
    return result


@router.post("/password/change", response_model=CompletedResponse)
async def password_change(
    data: PasswordChangeRequest,
    request: Request,
    response: Response,
    user: User = Depends(deps.get_current_user),
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    result = await credentials.change_password(
        db,
        ctx,
        user,
        proof=data.recent_auth_proof.get_secret_value(),
        password=data.password.get_secret_value(),
        browser=browser_binding(request),
    )
    if result.reauthentication_required:
        clear_refresh_cookie(response, ctx.settings)
    return result


@router.post("/email/change", response_model=AcceptedResponse, status_code=202)
async def email_change(
    data: EmailChangeRequest,
    request: Request,
    user: User = Depends(deps.get_current_user),
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    await credentials.request_email_change(
        db,
        ctx,
        user,
        proof=data.recent_auth_proof.get_secret_value(),
        email=str(data.new_email),
        browser=browser_binding(request),
    )
    return AcceptedResponse()


@router.post("/email/confirm", response_model=CompletedResponse)
async def email_confirm(
    data: EmailChangeCompleteRequest,
    request: Request,
    response: Response,
    user: User = Depends(deps.get_current_user),
    ctx: NativeContext = Depends(native_context),
    db: AsyncSession = Depends(get_db),
):
    result = await credentials.complete_email_change(
        db,
        ctx,
        user,
        raw=data.grant.get_secret_value(),
        proof=data.recent_auth_proof.get_secret_value(),
        browser=browser_binding(request),
    )
    clear_refresh_cookie(response, ctx.settings)
    return result
