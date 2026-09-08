"""Actual Redis multi-client admission proof; no SQLite/fakeredis substitute."""

from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.core.exceptions import DomainError, ServiceFailure
from app.services._local_auth.limiter import NativeRateLimiter

pytestmark = [pytest.mark.asyncio, pytest.mark.redis_integration]


async def test_native_limits_are_shared_across_clients_and_fail_closed():
    url = os.environ.get("TEST_REDIS_URL")
    if not url:
        pytest.skip("TEST_REDIS_URL required for real Redis proof")
    first, second = Redis.from_url(url), Redis.from_url(url)
    installation = str(uuid4())
    one, two = (
        NativeRateLimiter(first, installation),
        NativeRateLimiter(second, installation),
    )
    try:
        await first.ping()
        results = await asyncio.gather(
            one.count("proof", "target", 900), two.count("proof", "target", 900)
        )
        assert sorted(count for count, _ in results) == [1, 2]
        await one.require("proof", "target", 3, 900)
        with pytest.raises(DomainError) as error:
            await two.require("proof", "target", 3, 900)
        assert error.value.status_code == 429
        unavailable = Redis.from_url(
            "redis://127.0.0.1:1", socket_connect_timeout=0.2, socket_timeout=0.2
        )
        try:
            with pytest.raises(ServiceFailure) as error:
                await NativeRateLimiter(unavailable, installation).require(
                    "proof", "target", 3, 900
                )
            assert error.value.status_code == 503
        finally:
            await unavailable.aclose()
    finally:
        async for key in first.scan_iter(match=f"riskhub:{installation}:local-auth:*"):
            await first.delete(key)
        await first.aclose()
        await second.aclose()
