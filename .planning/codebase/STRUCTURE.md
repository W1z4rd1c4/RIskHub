# Repository Structure

**Analysis Date:** 2026-08-30

This file is a versioned repository-structure snapshot for the commit that
contains it. It does not assign live work or determine whether an issue, pull
request, or project item is open. See
[`docs/DOCUMENTATION_OWNERSHIP.md`](../../docs/DOCUMENTATION_OWNERSHIP.md).

Tracked file counts refreshed from `git ls-files` on 2026-09-06.

## Top-Level Layout

- `backend/` - FastAPI API, domain services, Alembic migrations, pytest suites
- `frontend/` - React + TypeScript SPA, Vitest tests, Playwright E2E suites
- `docs/` - product/business/admin/user documentation
- `tests/` - centralized backend/frontend test suites and test result artifacts
- `.planning/` - versioned roadmap/state snapshots, phase archives, and codebase maps
- `scripts/` - operational/dev utilities, including the public installer/orchestrator `scripts/install.sh` plus the underlying `scripts/dev.sh`, `scripts/compose.sh`, and `scripts/deploy.sh` entrypoints

## Backend Tree (`backend/`)

### Entry points and runtime
- `backend/app/main.py` - FastAPI app creation, middleware, startup checks
- `backend/app/api/v1/router.py` - registers all API endpoint routers
- `backend/app/db/session.py` - engine/sessionmaker lifecycle + `get_db` dependency (sessionmaker stored on `app.state`)

### Primary subdirectories
- `backend/app/api/v1/endpoints/` - 167 Python modules/packages (measured git-tracked `*.py` snapshot; extensively split into subrouters for maintainability)
- `backend/app/models/` - 34 model modules (measured git-tracked `*.py` snapshot)
- `backend/app/schemas/` - 33 schema modules (measured git-tracked `*.py` snapshot)
- `backend/app/services/` - 370 Python modules (measured repository `*.py` snapshot; business services + internal helper packages such as `_approval_queue`, `_governed_mutations`, `_issue_register`, `_vendor_links`, `_admin_telemetry`, `_issue_workflow`, `_kri_history`, `_vendor_workflow`, `_control_execution`, `_access_workflow`, `_riskhub_config`, `_orphaned_items`, `_quarterly_comparison`, `_risk_questionnaires`, `_auth_session_workflow`, `_graph_directory`, `_authorization_capabilities`, and `_identity_access_lifecycle`)
- `backend/app/core/` - configuration facade + segmented settings package, auth, permissions, logging, scheduler
- `backend/app/middleware/` - 11 Python modules (measured git-tracked `*.py` snapshot; security/logging/language/rate-limit middleware with facade-preserving splits)
- `backend/app/integrations/` - reserved integration package and vendor-signal package docs; current directory/Graph behavior lives in service-layer adapters
- `backend/alembic/` - migration environment and versioned migrations
- `backend/scripts/runtime/` - component-scoped backend runtime entrypoints (`dev`, `test`, `prod`)
- `backend/scripts/runtime/db/` - backend-owned DB runtime entrypoints (`dev`, `test`, `prod`)
- `tests/backend/pytest/` - 508 tracked test files (470 Python) in the measured repository snapshot

## Frontend Tree (`frontend/`)

### Entry points
- `frontend/src/main.tsx` - React bootstrap
- `frontend/src/App.tsx` - provider composition and route tree

### Primary subdirectories
- `frontend/src/pages/` - 242 tracked files (measured repository snapshot; route-level pages + colocated helpers/tests and shared detail/admin/user workflow modules)
- `frontend/src/components/` - 324 tracked files (measured repository snapshot; components + tests, including split linking, remediation, questionnaire workflow state, governance, dashboard, KRI modal, and control-loading-overlay modules)
- `frontend/src/services/` - API client, auth transport, session state packages, domain service wrappers, and split runtime schema modules
- `frontend/src/contexts/` - auth/theme/filter context providers
- `frontend/src/authz/` - authz policy derivation hooks
- `frontend/src/routing/` - centralized route metadata and sidebar navigation manifests
- `frontend/src/hooks/` - shared hooks
- `frontend/src/i18n/` - locale resources and typed translation hooks
- `frontend/scripts/runtime/` - component-scoped frontend runtime entrypoints (`dev`, `test`, `prod`)
- `tests/frontend/unit/src/test/` - MSW handlers and test utilities
- `tests/frontend/e2e/` - 79 E2E specs (measured repository snapshot; domain-focused test suites plus setup/helpers/fixtures and the dialog render-site harness)

## Planning and Documentation Structure

- `docs/DOCUMENTATION_OWNERSHIP.md` - authority and conflict-resolution contract
- `.planning/ROADMAP.md` - versioned phase intent at the current commit, not live priority or closure
- `.planning/STATE.md` - versioned technical-state snapshot at the current commit, not live assignment or execution status
- `.planning/phases/` - historical plans/summaries; an active plan provides implementation detail only after the corresponding live work item is confirmed applicable
- `.planning/codebase/` - generated/versioned codebase reference docs
- `docs/BUSINESS_LOGIC.md` - durable domain behavior contract
- `docs/development/README.md` - canonical development startup/runbook
- `docs/TESTING.md` - testing guidance and workflows
- `docs/deployment/` - deployment runbooks for supported docker/linux operations and migration guidance

Live scope, assignment, priority, review state, blocking, and closure are tracked
in the applicable GitHub Issue, pull request, or Project item.

## Build/Test/Automation Artifacts

- `.tool-versions` - canonical Python 3.13 and Node 24 development baseline
- `.github/workflows/e2e.yml` - CI E2E flow
- `.github/workflows/security.yml` - security scanning flow
- `.github/workflows/python-dev-lock-refresh.yml` - scheduled exact Python resolver refresh PR workflow
- `docker-compose.yml` - development service topology consumed by `scripts/compose.sh`
- `scripts/Makefile` - convenience command aliases around `scripts/install.sh`, `scripts/dev.sh`, and `scripts/compose.sh`
- `scripts/install_lib/` - 14 Python modules (measured git-tracked `*.py` snapshot; installer control-plane helpers split by release input, secrets/scaffolding, lifecycle execution, and summary/verify responsibilities)

## Generated or Heavy Directories (avoid manual edits)

- `frontend/node_modules/`
- `frontend/dist/`
- `backend/venv/`
- `tests/results/backend/coverage_html/`
- `tests/results/`, `tests/results/frontend/playwright/playwright-report/`, `tests/results/legacy/coverage_html/`

---

*Structure audit refreshed on 2026-08-30*
