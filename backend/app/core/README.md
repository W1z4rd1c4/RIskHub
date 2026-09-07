# backend/app/core

## Purpose

Shared backend runtime primitives: settings, logging, security, scheduling, pagination, permission helpers, and other cross-cutting services used by the API and background jobs.

## Contents

- `settings/`
  - Physical settings segmentation behind the import-stable `app.core.config` facade.
- `_permissions/`
  - Internal permission-evaluation helpers behind `permissions.py`.
- `activity_logger.py`, `activity_redaction.py`
  - Audit/event logging and payload sanitization.
- `client_ip.py`, `limits.py`, `outbound_guard.py`, `production_contract.py`, `security.py`
  - Runtime hardening, request attribution, and production-safety helpers.
- `datetime_utils.py`, `pagination.py`, `query_filters.py`, `snapshot_service.py`, `ttl_cache.py`
  - Cross-cutting utility modules used by multiple endpoint/service packages.
- `scheduler.py`
  - Background scheduler bootstrap and job execution coordination.

## Notes

- Keep `app.core.config` as the public settings import surface even though the implementation now lives under `settings/`.
- Treat this directory as infrastructure code, not a grab bag for endpoint-specific business logic.
- If a module grows around one bounded concern, prefer a dedicated subpackage with its own README instead of expanding a flat utility file.

- `identity_policy.py`: common stored/underlying account eligibility and field ownership.
