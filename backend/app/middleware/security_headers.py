from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Headers added:
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME type sniffing
    - Strict-Transport-Security: Forces HTTPS
    - Referrer-Policy: Controls referrer information
    - Content-Security-Policy: Restricts resource loading
    - Permissions-Policy: Controls browser features
    """

    def __init__(self, app, enable_hsts: bool = True, csp_report_uri: str | None = None):
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.csp_report_uri = csp_report_uri
        self._default_settings = get_settings()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        settings = getattr(request.app.state, "settings", self._default_settings)

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        sensitive_auth = request.url.path.startswith("/api/v1/auth/") or (
            request.url.path.startswith("/api/v1/users/")
            and any(part in request.url.path for part in ("invitations", "password-reset", "local-auth"))
        )
        response.headers["Referrer-Policy"] = "no-referrer" if sensitive_auth else "strict-origin-when-cross-origin"
        if sensitive_auth:
            response.headers["Cache-Control"] = "no-store"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"

        if self.enable_hsts and not settings.debug:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        if settings.debug:
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "style-src 'self' 'unsafe-inline'",
                "font-src 'self'",
                "img-src 'self' data: https: blob:",
                "connect-src 'self' http://localhost:* https://*",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'self'",
                "object-src 'none'",
            ]
        else:
            csp_directives = [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "font-src 'self'",
                "img-src 'self' data: https: blob:",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'self'",
                "object-src 'none'",
                "upgrade-insecure-requests",
            ]

        if self.csp_report_uri:
            csp_directives.append(f"report-uri {self.csp_report_uri}")

        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        return response
