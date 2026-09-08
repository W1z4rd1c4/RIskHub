"""Offline native-password policy and bounded, cancellation-safe KDF admission."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import TypeVar

from app.core.exceptions import ServiceFailure, ValidationError
from app.core.production_contract import LOCAL_PASSWORD_MAX_LENGTH, LOCAL_PASSWORD_MIN_LENGTH

_T = TypeVar("_T")
DATA_DIR = Path(__file__).parent / "password_data"
KDF_SLOTS_PER_PROCESS = 2
_KDF_SLOTS = threading.BoundedSemaphore(KDF_SLOTS_PER_PROCESS)


def policy_unavailable() -> ServiceFailure:
    return ServiceFailure("Password policy is unavailable", code="LOCAL_SECURITY_UNAVAILABLE", status_code=503)


@lru_cache(maxsize=4)
def _packaged_passwords(directory: str) -> frozenset[str]:
    root = Path(directory)
    try:
        manifest = json.loads((root / "manifest.json").read_text())
        with (root / "common-passwords.txt").open("rb") as stream:
            raw = stream.read(4_000_001)
        if len(raw) > 4_000_000 or hashlib.sha256(raw).hexdigest() != manifest["sha256"]:
            raise ValueError("Invalid policy data")
        return frozenset(raw.decode("utf-8").splitlines())
    except (OSError, ValueError, KeyError, TypeError):
        raise policy_unavailable() from None


def validate_local_password(password: str, *, additions_file: str | None = None) -> None:
    # Never strip, normalize, case-fold or silently truncate the credential.
    if not LOCAL_PASSWORD_MIN_LENGTH <= len(password) <= LOCAL_PASSWORD_MAX_LENGTH:
        raise ValidationError(
            "Password must contain 15–128 Unicode characters", code="PASSWORD_POLICY", status_code=422
        )
    try:
        password.encode("utf-8")
    except UnicodeError:
        raise ValidationError("Password contains invalid Unicode", code="PASSWORD_POLICY", status_code=422) from None
    blocked = _packaged_passwords(str(DATA_DIR))
    additions: set[str] = set()
    if additions_file:
        try:
            with Path(additions_file).open("rb") as stream:
                raw = stream.read(4_000_001)
            if len(raw) > 4_000_000:
                raise ValueError("Policy data is too large")
            additions = set(raw.decode("utf-8").splitlines())
        except (OSError, ValueError):
            raise policy_unavailable() from None
    if password in blocked or password in additions:
        raise ValidationError(
            "Choose a password not present in the common-password blocklist", code="PASSWORD_POLICY", status_code=422
        )


async def run_password_work(operation: Callable[[], _T]) -> _T:
    """Reserve before scheduling; a cancelled waiter cannot release a running KDF.

    There is no unbounded executor queue. The worker owns slot release, including
    when the request is cancelled. All native hash/verification calls use this.
    """
    if not _KDF_SLOTS.acquire(blocking=False):
        raise ServiceFailure("Authentication capacity is temporarily exhausted", code="AUTH_CAPACITY", status_code=503)

    def execute() -> _T:
        try:
            return operation()
        finally:
            _KDF_SLOTS.release()

    # Shield submission from cancellation: execute must run to release its slot.
    task = asyncio.create_task(asyncio.to_thread(execute))
    task.add_done_callback(lambda finished: finished.exception() if not finished.cancelled() else None)
    return await asyncio.shield(task)
