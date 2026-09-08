"""Report measured native KDF costs; does not read or print real credentials."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import secrets
import statistics
import time

from app.core.password_policy import KDF_SLOTS_PER_PROCESS, run_password_work
from app.core.security import get_password_hash, verify_password


async def benchmark(samples: int) -> dict:
    password = secrets.token_urlsafe(32)
    durations = []
    for _ in range(samples):
        start = time.perf_counter()
        encoded = await run_password_work(lambda: get_password_hash(password))
        assert await run_password_work(lambda: verify_password(password, encoded))
        durations.append(time.perf_counter() - start)
    start = time.perf_counter()
    await asyncio.gather(
        *(run_password_work(lambda: get_password_hash(password)) for _ in range(KDF_SLOTS_PER_PROCESS))
    )
    return {
        "python": platform.python_version(),
        "platform": platform.system(),
        "samples": samples,
        "argon2_memory_kib": 65536,
        "iterations": 3,
        "parallelism": 1,
        "per_process_slots": KDF_SLOTS_PER_PROCESS,
        "hash_plus_verify_seconds_median": statistics.median(durations),
        "hash_plus_verify_seconds_max": max(durations),
        "two_hashes_concurrent_seconds": time.perf_counter() - start,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=5, choices=range(1, 51))
    print(json.dumps(asyncio.run(benchmark(parser.parse_args().samples)), indent=2))


if __name__ == "__main__":
    main()
