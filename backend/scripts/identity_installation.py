"""Explicit, operator-only identity binding; this command never creates Users."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import asdict

from app.core.config import get_settings
from app.db.session import session_context
from app.services.identity_installation import (
    IdentityBindingError,
    eligibility_backfill_report,
    establish_installation_binding,
    validate_installation_binding,
)


async def run(args: argparse.Namespace) -> dict[str, object]:
    settings = get_settings()
    if settings.debug or settings.mock_auth_enabled:
        raise IdentityBindingError(
            "Binding requires the installed production configuration (DEBUG=false, mock disabled)"
        )
    if args.operation in {"initialize", "adopt-entra"} and not args.maintenance_confirmed:
        raise IdentityBindingError("Stop/drain old API and scheduler writers and supply --maintenance-confirmed")
    async with session_context(settings) as db:
        if args.operation == "verify":
            return {"status": "verified", **asdict(await validate_installation_binding(db, settings=settings))}
        if args.operation == "eligibility-report":
            return {"status": "read-only", **await eligibility_backfill_report(db)}
        if not args.source:
            raise IdentityBindingError("--source must identify the accountable operator/change reference")
        binding = await establish_installation_binding(
            db,
            settings=settings,
            source=args.source,
            adopt_entra=args.operation == "adopt-entra",
            dry_run=args.dry_run,
        )
        return {
            "status": "validated-not-written" if args.dry_run else "established",
            "installation_id": binding.installation_id,
            "auth_mode": binding.auth_mode,
            "tenant_id": binding.tenant_id,
            "contract_version": binding.contract_version,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["initialize", "adopt-entra", "verify", "eligibility-report"])
    parser.add_argument("--source", help="Accountable operator/change reference; no secrets")
    parser.add_argument("--maintenance-confirmed", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Validate without storing a binding")
    args = parser.parse_args()
    try:
        result = asyncio.run(run(args))
    except IdentityBindingError as exc:
        parser.exit(2, f"Identity admission refused: {exc}\n")
    except Exception:
        parser.exit(3, "Identity validation unavailable; inspect protected database/directory diagnostics.\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
