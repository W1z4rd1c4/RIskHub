"""Shared Redis admission; never silently falls back to per-worker counters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.core.exceptions import DomainError

from .keys import unavailable


@dataclass
class NativeRateLimiter:
    redis: Any = field(repr=False)
    installation_id: str

    def key(self, scope: str, identifier: str) -> str:
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        return f"riskhub:{self.installation_id}:local-auth:{scope}:{digest}"

    async def count(self, scope: str, identifier: str, seconds: int) -> tuple[int, int]:
        try:
            if self.redis is None:
                raise ConnectionError("No shared backend")
            key = self.key(scope, identifier)
            pipe = self.redis.pipeline(transaction=True)
            pipe.incr(key)
            pipe.expire(key, seconds, nx=True)
            pipe.ttl(key)
            result = await pipe.execute()
            return int(result[0]), max(1, int(result[2]))
        except Exception:
            raise unavailable() from None

    async def limit(self, scope: str, identifier: str, maximum: int, seconds: int) -> bool:
        count, _ = await self.count(scope, identifier, seconds)
        return count <= maximum

    async def require(self, scope: str, identifier: str, maximum: int, seconds: int) -> None:
        count, remaining = await self.count(scope, identifier, seconds)
        if count > maximum:
            raise DomainError(
                "Too many attempts; retry later",
                code="LOCAL_AUTH_THROTTLED",
                status_code=429,
                headers={"Retry-After": str(remaining)},
            )

    async def password_locked(self, account: str) -> bool:
        try:
            return bool(await self.redis.get(self.key("password-lock", account)))
        except Exception:
            raise unavailable() from None

    async def password_failed(self, account: str) -> None:
        count, _ = await self.count("password-fail", account, 900)
        if count >= 5:
            try:
                await self.redis.set(self.key("password-lock", account), "locked", ex=900, nx=True)
            except Exception:
                raise unavailable() from None

    async def password_succeeded(self, account: str) -> None:
        try:
            await self.redis.delete(self.key("password-fail", account))
        except Exception:
            raise unavailable() from None
