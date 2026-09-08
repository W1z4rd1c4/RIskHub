"""Versioned, secret-file-only native key material and authenticated encryption."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.exceptions import ServiceFailure


def unavailable() -> ServiceFailure:
    return ServiceFailure(
        "Local authentication security state is unavailable", code="LOCAL_SECURITY_UNAVAILABLE", status_code=503
    )


def read_secret_file(path: str | None, *, max_bytes: int = 65536) -> bytes:
    if not path:
        raise unavailable()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > max_bytes:
                raise ValueError("Unsafe secret file")
            value = stream.read(max_bytes + 1)
            if not value or len(value) > max_bytes:
                raise ValueError("Invalid secret file")
            return value
    except (OSError, ValueError):
        raise unavailable() from None


def _aad(purpose: str, context: list[str]) -> bytes:
    return json.dumps(["riskhub-local-v1", purpose, *context], separators=(",", ":")).encode()


@dataclass(frozen=True)
class KeyPurpose:
    active: str
    keys: dict[str, bytes] = field(repr=False)


@dataclass(frozen=True)
class LocalKeyring:
    purposes: dict[str, KeyPurpose] = field(repr=False)

    @classmethod
    def load(cls, path: str | None) -> "LocalKeyring":
        try:
            data = json.loads(read_secret_file(path))
            if (
                type(data["version"]) is not int
                or data["version"] != 1
                or set(data["purposes"]) != {"delivery", "totp", "action"}
            ):
                raise ValueError("Invalid keyring")
            purposes = {}
            unique: set[bytes] = set()
            for purpose, entry in data["purposes"].items():
                keys = {}
                for key_id, value in entry["keys"].items():
                    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key_id):
                        raise ValueError("Invalid key identifier")
                    raw = base64.b64decode(value, validate=True)
                    if len(raw) != 32 or raw in unique:
                        raise ValueError("Keys must be independently generated")
                    unique.add(raw)
                    keys[key_id] = raw
                if entry["active"] not in keys:
                    raise ValueError("Missing active key")
                purposes[purpose] = KeyPurpose(entry["active"], keys)
            return cls(purposes)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise unavailable() from None

    def encrypt(self, purpose: str, plaintext: str, context: list[str]) -> tuple[str, str]:
        entry = self.purposes[purpose]
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(entry.keys[entry.active]).encrypt(
            nonce, plaintext.encode(), _aad(purpose, [entry.active, *context])
        )
        return entry.active, base64.b64encode(nonce + ciphertext).decode()

    def decrypt(self, purpose: str, key_id: str, ciphertext: str, context: list[str]) -> str:
        try:
            raw = base64.b64decode(ciphertext, validate=True)
            return (
                AESGCM(self.purposes[purpose].keys[key_id])
                .decrypt(raw[:12], raw[12:], _aad(purpose, [key_id, *context]))
                .decode()
            )
        except (KeyError, ValueError, InvalidTag):
            raise unavailable() from None

    def commitment(self, value: str, *, context: list[str], key_id: str | None = None) -> tuple[str, str]:
        entry = self.purposes["action"]
        selected = key_id or entry.active
        try:
            key = entry.keys[selected]
        except KeyError:
            raise unavailable() from None
        digest = hmac.new(key, _aad("action", [*context, value]), hashlib.sha256).hexdigest()
        return selected, digest
