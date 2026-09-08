# backend/app/schemas

## Purpose

API request/response schema definitions.

## Contents

- `__init__.py`
- `__pycache__/`
- `access.py`
- `activity_log.py`
- `admin.py`
- `approval_request.py`
- `auth.py`
- `control.py`
- `dashboard.py`
- `department.py`
- `directory.py`
- `execution.py`
- `issue.py`
- `kri.py`
- `notification.py`
- `...`

## Notes

Execution request/response schema ownership for the execution domain lives in
`execution.py`, including the canonical `ExecutionResultEnum` and generic
paginated `/executions` response shapes.

Keep this README updated when responsibilities or structure in this folder change.

- `local_auth.py`: reserved native request/response contract; no live route registration.
