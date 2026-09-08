import logging
import re
from datetime import timedelta
from typing import Any, Iterable, Optional

import jwt
from fastapi import Depends, Header
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings, get_settings
from app.core.datetime_utils import utc_now
from app.core.exceptions import AuthenticationError, AuthorizationError
from app.core.permissions import ensure_business_view_access, has_permission
from app.db.session import get_db
from app.models import Role, RolePermission, User

# New credentials use Argon2id; bcrypt remains a bounded legacy verifier.
password_hasher = PasswordHash((Argon2Hasher(memory_cost=65536, time_cost=3, parallelism=1), BcryptHasher()))
logger = logging.getLogger(__name__)
DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=1$+pjzxiPA06E1N9cX8WST1A$Dkb6tmfx1t+GJSaSknRJwXXSdb/NYzxtJ7vrwrCcmZI"
)
ACCESS_TOKEN_TYPE = "access"
ACCESS_TOKEN_ISSUER = "riskhub"
ACCESS_TOKEN_AUDIENCE = "riskhub-api"

# Backward-compatible alias used by auth dependencies.
TokenDecodeError = InvalidTokenError


# Password hashing utilities
def _bounded_password_hash(encoded: str) -> bool:
    if len(encoded) > 255:
        return False
    if match := re.fullmatch(r"\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+", encoded):
        memory, iterations, parallelism = map(int, match.groups())
        return 8 <= memory <= 65536 and 1 <= iterations <= 3 and 1 <= parallelism <= 4
    if match := re.fullmatch(r"\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}", encoded):
        return 4 <= int(match.group(1)) <= 14
    return False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify supported bounded hashes, never truncate a legacy bcrypt input."""
    if len(plain_password) > 128 or not _bounded_password_hash(hashed_password):
        return False
    try:
        if hashed_password.startswith("$2") and len(plain_password.encode("utf-8")) > 72:
            return False
        return password_hasher.verify(plain_password, hashed_password)
    except (UnknownHashError, ValueError, UnicodeError):
        return False


def verify_password_or_dummy(plain_password: str, hashed_password: str | None) -> bool:
    """Unknown, missing and malformed hashes still perform current-cost work."""
    supported = bool(hashed_password and _bounded_password_hash(hashed_password))
    target_hash = hashed_password if supported else DUMMY_PASSWORD_HASH
    assert target_hash is not None
    verified = verify_password(plain_password, target_hash)
    return supported and verified


def get_password_hash(password: str) -> str:
    """Hash using the canonical current algorithm; native writers enforce policy first."""
    if len(password) > 128:
        raise ValueError("Password input is too long")
    return password_hasher.hash(password)


def password_hash_needs_update(encoded: str) -> bool:
    return _bounded_password_hash(encoded) and (
        encoded.startswith("$2") or password_hasher.current_hasher.check_needs_rehash(encoded)
    )


# JWT token utilities
def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
    *,
    settings: Settings | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Dictionary of claims to encode in the token
        expires_delta: Optional expiration time delta

    Returns:
        Encoded JWT token string
    """
    active_settings = settings or get_settings()
    to_encode = data.copy()
    expire = utc_now() + (expires_delta or timedelta(minutes=active_settings.access_token_expire_minutes))
    to_encode.update(
        {
            "type": ACCESS_TOKEN_TYPE,
            "iss": ACCESS_TOKEN_ISSUER,
            "aud": ACCESS_TOKEN_AUDIENCE,
            "exp": expire,
        }
    )
    return jwt.encode(to_encode, active_settings.secret_key, algorithm="HS256")


def decode_access_token(token: str, *, settings: Settings | None = None) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Dictionary of decoded claims

    Raises:
        InvalidTokenError: If token is invalid or expired
    """
    active_settings = settings or get_settings()
    payload = jwt.decode(
        token,
        active_settings.secret_key,
        algorithms=["HS256"],
        audience=ACCESS_TOKEN_AUDIENCE,
        issuer=ACCESS_TOKEN_ISSUER,
        options={"require": ["exp", "aud", "iss", "type"]},
    )
    if payload.get("type") != ACCESS_TOKEN_TYPE:
        raise InvalidTokenError("Unexpected token type")
    return payload


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    x_mock_user_id: Optional[int] = Header(None, alias="X-Mock-User-Id"),
) -> User:
    """
    Get the current user - mocked for development only.

    In development with MOCK_AUTH_ENABLED=true, uses X-Mock-User-Id header.
    In production, this endpoint is disabled - use deps.get_current_user with JWT.
    """
    current_settings = get_settings()
    mock_auth_enabled = current_settings.mock_auth_enabled and current_settings.debug

    # Only allow mock auth in explicit debug+mock mode
    if mock_auth_enabled and x_mock_user_id:
        # Eager load role -> permissions -> permission
        permission_load = selectinload(User.role).selectinload(Role.permissions).selectinload(RolePermission.permission)

        # Mock auth: get user by ID from header
        result = await db.execute(select(User).options(permission_load).where(User.id == x_mock_user_id))
        user = result.scalar_one_or_none()
        if user:
            return user

    # Production: Mock auth not allowed - this function should not be used
    # Use deps.get_current_user instead for JWT-based auth
    raise AuthenticationError(
        "Mock auth disabled. Use JWT authentication via /auth/login",
        headers={"WWW-Authenticate": "Bearer"},
    )


def check_permission(user: User, resource: str, action: str) -> bool:
    """
    Backwards-compatible permission check.

    Canonical permission evaluation lives in app.core.permissions.has_permission.
    """
    return has_permission(user, resource, action)


def forbid(detail: str) -> None:
    raise AuthorizationError(detail)


def require_any_permission(permissions: Iterable[tuple[str, str]]):
    """FastAPI dependency factory for requiring any one of the provided permissions."""
    from app.api import deps

    perms = list(permissions)
    if not perms:
        raise ValueError("require_any_permission() requires at least one (resource, action) pair")

    async def permission_checker(current_user: User = Depends(deps.get_current_user)) -> User:
        if not any(check_permission(current_user, resource, action) for resource, action in perms):
            required = ", ".join(f"{r}:{a}" for r, a in perms)
            forbid(f"Permission denied: requires one of [{required}]")
        return current_user

    setattr(permission_checker, "required_any_capability", tuple(perms))
    return permission_checker


def require_permission(resource: str, action: str):
    """FastAPI dependency factory for requiring specific permissions."""
    # Delayed import to avoid circular dependency
    from app.api import deps

    async def permission_checker(
        current_user: User = Depends(deps.get_current_user),
    ) -> User:
        if not check_permission(current_user, resource, action):
            forbid(f"Permission denied: {resource}:{action}")
        return current_user

    setattr(permission_checker, "required_capability", (resource, action))
    return permission_checker


def require_business_permission(
    resource: str,
    action: str,
    *,
    detail: str = "Platform admins cannot access business data",
):
    """Require a permission while explicitly blocking platform admins from business views."""
    from app.api import deps

    async def permission_checker(
        current_user: User = Depends(deps.get_current_user),
    ) -> User:
        ensure_business_view_access(current_user, detail=detail)
        if not check_permission(current_user, resource, action):
            forbid(f"Permission denied: {resource}:{action}")
        return current_user

    setattr(permission_checker, "required_capability", (resource, action))
    setattr(permission_checker, "requires_business_view", True)
    return permission_checker
