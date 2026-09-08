# backend/app/api/v1/endpoints/users

## Purpose

API endpoint package for `users` domain.

## Contents

- `__init__.py`
- `__pycache__/`
- `_lifecycle.py`
- `_visibility.py`
- `crud.py`
- `detail.py`
- `directory.py`
- `invitations.py` — Admin-only native invitation/reset-link/status adapters
- `lookup.py`
- `mock_auth.py`
- `org.py`
- `summary.py`

## Notes

Keep this README updated when responsibilities or structure in this folder change.

- `invitations.py` — Admin-only native invitation/reset-link/status adapters
- `lookup.py` owns the `users:read`-guarded generic picker plus narrow assignment lookups. Risk/KRI, Control, and Vendor owner lookups require their exact resource write permission, retain caller visibility scope, exclude inactive/platform-admin identities, and return only assignment fields. The Threat Steward picker is cross-Department, requires `threats:write`, and returns active CISOs only.
- `_lifecycle.py` contains the Admin-only guard shared by lifecycle/detail helpers under `/users`.
- `directory.py` is the explicit paginated directory contract for `/users` directory mode and returns backend-driven `available_roles` facets alongside the paginated directory items.
- `_visibility.py` contains shared scope filtering used by both lookup and directory list flows.
- `invitations.py` — Admin-only native invitation/reset-link/status adapters
- `lookup.py` keeps `/users/lookup` as the generic picker; `/users/lookup/{risk,control,vendor}-owners` and `/users/lookup/threat-stewards` are purpose-scoped assignment surfaces, while `/users/roles` is now an Admin-only lifecycle helper.
- `crud.py` and `detail.py` remain user-lifecycle/admin-detail surfaces and should not absorb directory responsibilities.
- Active access-management role selection belongs to `/access/roles`, not to the lifecycle helpers in this package.
