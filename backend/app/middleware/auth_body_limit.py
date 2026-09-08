"""Bound credential JSON before parsing, including chunked requests."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class AuthBodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        protected = path.startswith("/api/v1/auth/") or (
            path.startswith("/api/v1/users/")
            and any(word in path for word in ("invitations", "password-reset", "local-auth"))
        )
        if scope["type"] != "http" or not protected or scope.get("method") not in {"POST", "PATCH", "PUT"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > 16_384:
                await JSONResponse(
                    {"detail": "Authentication request too large"},
                    status_code=413,
                    headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
                )(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
