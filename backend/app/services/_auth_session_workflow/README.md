# backend/app/services/_auth_session_workflow

## Purpose

Shared service-layer workflow for admin auth/session operations.

## Contents

- `__init__.py`
- `admin_sessions.py`
- `demo.py`
- `logout.py`
- `password.py`
- `refresh.py`
- `sso.py`
- `transactions.py`

## Notes

Admin session endpoints should use this package for active-session projection, self-revoke protection, target-user locking, refresh-token revocation, token-version bumps, and activity logging. Auth login, SSO, refresh, logout, and demo-login endpoints use this package for service-owned transaction boundaries per ADR-011/#76.

- `authority.py`: shared locked User loading and caller-owned session revocation.
