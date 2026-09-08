#!/usr/bin/env python3
"""Bootstrap (pre-provision and pre-link) an SSO user by email or UPN."""

from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.email import email_equals, normalize_email
from app.db.session import session_context
from app.models import Department, Role, User
from app.models.user import AccessScope
from app.services._directory_identity import (
    DirectoryIdentityConflictError,
    apply_directory_profile,
    has_auto_deprovision_reason,
)
from app.services.directory_provider_service import DirectoryProviderService, DirectoryProviderUnavailableError
from app.services.identity_installation import validate_installation_binding
from app.services.transaction_boundary import commit_service_boundary


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap and pre-link an SSO user (idempotent upsert).")
    parser.add_argument("--email", required=True, help="User email or UPN (used for exact directory lookup).")
    parser.add_argument(
        "--external-id",
        default=None,
        help="Optional Entra object ID. If omitted, the script resolves an exact directory match by email/UPN.",
    )
    parser.add_argument("--role", required=True, help="Role name (e.g. admin, cro).")
    parser.add_argument(
        "--access-scope",
        required=True,
        choices=[s.value for s in AccessScope],
        help="Access scope (global|department|manager).",
    )
    parser.add_argument(
        "--department",
        default=None,
        help="Optional department code or name to assign (e.g. RISK or 'Risk Management').",
    )
    parser.add_argument(
        "--name",
        default=None,
        help="Optional display name. Defaults to email if not provided.",
    )
    return parser.parse_args(argv)


async def _resolve_directory_user(email_or_upn: str):
    settings = get_settings()
    try:
        provider = DirectoryProviderService(settings)
    except DirectoryProviderUnavailableError as exc:
        raise SystemExit(f"Directory provider unavailable: {exc}") from exc

    matches = await provider.find_user_by_login_identifier(email_or_upn)
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one exact directory match for {email_or_upn!r}; found {len(matches)}")
    return matches[0]


async def _resolve_department_id(department: str | None) -> int | None:
    if not department:
        return None

    dept_key = department.strip()
    if not dept_key:
        return None

    async with session_context(get_settings()) as db:
        # Prefer code match first (codes are typically short and stable).
        code_result = await db.execute(select(Department).where(func.lower(Department.code) == dept_key.lower()))
        dept = code_result.scalar_one_or_none()
        if dept is not None:
            return dept.id

        name_result = await db.execute(select(Department).where(func.lower(Department.name) == dept_key.lower()))
        dept = name_result.scalar_one_or_none()
        if dept is not None:
            return dept.id

    raise SystemExit(f"Department not found: {department!r} (seed departments first)")


async def _run(args: argparse.Namespace) -> int:
    settings = get_settings()
    email = normalize_email(args.email)
    if not email or "@" not in email:
        raise SystemExit("Invalid --email (must be a valid email address)")

    if not settings.debug:
        if settings.auth_mode != "microsoft_sso":
            raise SystemExit("SSO bootstrap requires the Entra identity profile")
        async with session_context(settings) as db:
            await validate_installation_binding(db, settings=settings)

    directory_user = None
    external_id = args.external_id.strip() if args.external_id else None
    if external_id == "":
        external_id = None
    if external_id is None:
        directory_user = await _resolve_directory_user(args.email)
        external_id = directory_user.external_id
    if not external_id:
        raise SystemExit("Unable to resolve an external_id for bootstrap user")

    department_id = await _resolve_department_id(args.department)

    async with session_context(settings) as db:
        if not settings.debug:
            await validate_installation_binding(db, settings=settings)
            # Prevent competing bootstraps and lifecycle changes before creation.
            if db.get_bind().dialect.name == "postgresql":
                await db.execute(text("SELECT pg_advisory_xact_lock(hashtext('riskhub.identity.administration'))"))
        role_result = await db.execute(select(Role).where(Role.name == args.role))
        role = role_result.scalar_one_or_none()
        if role is None:
            raise SystemExit(f"Role not found: {args.role!r} (seed roles first)")

        user_by_external_id = (
            await db.execute(select(User).where(User.external_id == external_id))
        ).scalar_one_or_none()
        user_by_email = (await db.execute(select(User).where(email_equals(User.email, email)))).scalar_one_or_none()
        if user_by_external_id is not None and user_by_email is not None and user_by_external_id.id != user_by_email.id:
            raise SystemExit(
                "Bootstrap conflict: existing email and external_id records refer to different users. "
                "Resolve manually before continuing."
            )
        user = user_by_external_id or user_by_email

        access_scope = AccessScope(args.access_scope)

        created = user is None
        if not created and not settings.debug:
            # Bootstrap is not a privilege restoration or recovery interface.
            if (
                not user.is_active
                or user.local_suspended
                or user.role_id != role.id
                or user.access_scope != access_scope
                or user.department_id != department_id
                or user.external_id != external_id
            ):
                raise SystemExit(
                    "Existing account differs from bootstrap intent or is suspended; "
                    "use the authenticated identity lifecycle or governed recovery"
                )
            print("BOOTSTRAP_OK no-op existing enrolled identity preserved")
            return 0

        if user is None:
            user = User(
                email=email,
                name=args.name.strip() if args.name else (directory_user.display_name if directory_user else email),
                role_id=role.id,
                department_id=department_id,
                access_scope=access_scope,
                hashed_password=None,
                external_id=external_id,
                is_active=True,
            )
            db.add(user)
            await db.flush()
        elif user.external_id not in (None, external_id):
            raise SystemExit(
                f"Bootstrap conflict: existing user {user.email!r} is already linked to a different external_id"
            )

        changed = created

        if user.role_id != role.id:
            user.role_id = role.id
            changed = True
        if user.access_scope != access_scope:
            user.access_scope = access_scope
            changed = True
        if user.department_id != department_id:
            user.department_id = department_id
            changed = True
        if args.name and directory_user is None and user.name != args.name.strip():
            user.name = args.name.strip()
            changed = True
        if not user.is_active and not has_auto_deprovision_reason(user):
            user.is_active = True
            changed = True
        if user.external_id != external_id:
            user.external_id = external_id
            changed = True

        try:
            if directory_user is not None:
                await apply_directory_profile(
                    db,
                    user=user,
                    directory_user=directory_user,
                    sync_business_role=settings.entra_business_role_enabled,
                )
                changed = True
        except DirectoryIdentityConflictError as exc:
            raise SystemExit(str(exc)) from exc

        if changed:
            db.add(user)
            await db.flush()
            await commit_service_boundary(db, boundary="identity_access.bootstrap_sso_user")
            print(
                "BOOTSTRAP_OK updated "
                f"email={email} role={role.name} scope={access_scope.value} external_id_set={bool(user.external_id)}"
            )
        else:
            print(
                "BOOTSTRAP_OK no-op "
                f"email={email} role={role.name} scope={access_scope.value} external_id_set={bool(user.external_id)}"
            )
        return 0


def main() -> int:
    args = _parse_args(sys.argv[1:])
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
