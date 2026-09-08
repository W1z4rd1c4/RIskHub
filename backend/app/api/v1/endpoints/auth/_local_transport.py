"""HTTP-only native proof protection; no session authority lives here."""

from __future__ import annotations

import re
import secrets
from typing import Callable

from fastapi import Depends, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.exceptions import AuthorizationError
from app.core.tokens import get_request_client_ip
from app.db.session import get_db
from app.services._local_auth.common import NativeContext, build_context, invalid_proof, require_native_identity

from ._request_protection import validate_csrf, validate_request_origin

BROWSER_COOKIE = "riskhub_local_challenge"


class SafeAuthRoute(APIRoute):
    """Never echo validation inputs from credential requests."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def safe_handler(request: Request) -> Response:
            try:
                response = await original(request)
            except RequestValidationError as exc:
                errors = [
                    {"type": error["type"], "loc": error["loc"], "msg": "Invalid authentication request field"}
                    for error in exc.errors()
                ]
                response = JSONResponse(status_code=422, content={"detail": errors})
            response.headers["Cache-Control"] = "no-store"
            response.headers["Referrer-Policy"] = "no-referrer"
            return response

        return safe_handler


async def native_context(
    request: Request, db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
) -> NativeContext:
    require_native_identity(settings)
    if validate_request_origin(request, settings) is not None:
        raise AuthorizationError("Request origin is not allowed", code="origin_not_allowed")
    if validate_csrf(request) is not None:
        raise AuthorizationError("CSRF validation failed", code="csrf_validation_failed")
    return await build_context(
        db,
        settings=settings,
        redis=getattr(request.app.state, "redis", None),
        source=get_request_client_ip(request, settings.trusted_proxies) or "unknown",
    )


def browser_binding(request: Request) -> str:
    value = request.cookies.get(BROWSER_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise invalid_proof()
    return value


def establish_browser(request: Request, response: Response, settings: Settings) -> str:
    value = request.cookies.get(BROWSER_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        value = secrets.token_urlsafe(32)
    response.set_cookie(
        BROWSER_COOKIE,
        value,
        httponly=True,
        secure=not settings.debug,
        samesite="strict",
        path="/api/v1/auth",
        max_age=8 * 3600,
    )
    return value


async def native_read_context(
    request: Request, db: AsyncSession = Depends(get_db), settings: Settings = Depends(get_settings)
) -> NativeContext:
    """Read-only projection still requires the actor dependency, not browser CSRF."""
    return await build_context(
        db,
        settings=settings,
        redis=getattr(request.app.state, "redis", None),
        source=get_request_client_ip(request, settings.trusted_proxies) or "unknown",
    )
