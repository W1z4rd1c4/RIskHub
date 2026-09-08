# RiskHub Documentation Tree

English-first master index for repository documentation topology.

Authority, ownership, and conflict resolution are defined in
[`docs/DOCUMENTATION_OWNERSHIP.md`](./DOCUMENTATION_OWNERSHIP.md).

## Root Entry Points

- [`README.md`](../README.md): Repository quick start and canonical startup commands.
- [`AGENTS.md`](../AGENTS.md): Canonical general agent policy and navigation;
  [`docs/agent/EXECUTION_PROTOCOL.md`](./agent/EXECUTION_PROTOCOL.md) owns the
  detailed execution procedure.
- [`docs/README.md`](./README.md): Product and engineering documentation index.
- [`docs/DOCUMENTATION_OWNERSHIP.md`](./DOCUMENTATION_OWNERSHIP.md): Authority matrix for live work, versioned planning, durable docs, and archives.
- [`.planning/README.md`](../.planning/README.md): Versioned planning snapshots, codebase maps, and phase archive entry.

## Tree Map

```text
AGENTS.md
├── docs/README.md
│   ├── docs/DOCUMENTATION_TREE.md (this file)
│   ├── docs/DOCUMENTATION_OWNERSHIP.md
│   ├── docs/agent/README.md
│   ├── docs/development/README.md
│   ├── docs/security/README.md
│   ├── docs/adr/README.md
│   ├── docs/audits/README.md
│   ├── docs/dora-ict-register/README.md
│   ├── docs/deployment/README.md
│   ├── docs/migrations/README.md
│   ├── docs/reference/README.md
│   ├── docs/quality/README.md
│   ├── docs/assets/README.md
│   │   └── docs/assets/readme/README.md
│   ├── docs/admin/README.md
│   ├── docs/admin-cs/README.md
│   ├── docs/user/README.md
│   └── docs/user-cs/README.md
└── .planning/README.md
    ├── .planning/PROJECT.md
    ├── .planning/STATE.md
    ├── .planning/ROADMAP.md
    ├── .planning/codebase/*.md
    └── .planning/phases/README.md
        └── .planning/phases/* (archival records)
```

## Navigation By Intent

- Documentation and work-tracking authority:
  - [`docs/DOCUMENTATION_OWNERSHIP.md`](./DOCUMENTATION_OWNERSHIP.md)
- Product/business behavior:
  - [`docs/BUSINESS_LOGIC.md`](./BUSINESS_LOGIC.md)
  - [`docs/user/README.md`](./user/README.md)
  - [`docs/admin/README.md`](./admin/README.md)
  - Dedicated user ICT manuals:
    [`docs/user/processes.md`](./user/processes.md),
    [`docs/user/assets.md`](./user/assets.md),
    [`docs/user/threats.md`](./user/threats.md),
    [`docs/user-cs/processes.md`](./user-cs/processes.md),
    [`docs/user-cs/assets.md`](./user-cs/assets.md), and
    [`docs/user-cs/threats.md`](./user-cs/threats.md).
  - Dedicated admin ICT runbooks:
    [`docs/admin/processes.md`](./admin/processes.md),
    [`docs/admin/assets.md`](./admin/assets.md),
    [`docs/admin/threats.md`](./admin/threats.md),
    [`docs/admin-cs/processes.md`](./admin-cs/processes.md),
    [`docs/admin-cs/assets.md`](./admin-cs/assets.md), and
    [`docs/admin-cs/threats.md`](./admin-cs/threats.md).
  - Current workflow coverage includes directory lifecycle and break-glass recovery, cross-entity link management, KRI history/value governance, risk questionnaires, issue remediation, report export scope/as-of behavior, committee snapshots, and approval execution semantics.
  - User manuals are task-oriented product content. Admin docs are operator runbooks. Engineering details belong in `docs/`, `.planning/codebase/`, and frontmatter metadata rather than user-facing manual body text.
- Security posture and audits:
  - [`docs/security/README.md`](./security/README.md)
  - [`docs/security/authorization-capability-contract.md`](./security/authorization-capability-contract.md)
  - [`docs/security/SECURITY.md`](./security/SECURITY.md)
- Architecture decisions:
  - [`docs/adr/README.md`](./adr/README.md)
- Point-in-time subsystem audits:
  - [`docs/audits/README.md`](./audits/README.md)
- ICT Register (DORA) build — specs, captures, audit + remediation:
  - [`docs/dora-ict-register/README.md`](./dora-ict-register/README.md)
  - [`docs/dora-ict-register/ICT-GOV-00-BASELINE-2026-07-15.md`](./dora-ict-register/ICT-GOV-00-BASELINE-2026-07-15.md)
  - [`docs/dora-ict-register/SHARED-REGISTER-CONTRACT.md`](./dora-ict-register/SHARED-REGISTER-CONTRACT.md)
  - [`docs/dora-ict-register/REGISTER-LISTING-CONTRACTION-2026-07-16.md`](./dora-ict-register/REGISTER-LISTING-CONTRACTION-2026-07-16.md)
  - [`docs/dora-ict-register/FRONTEND-DIALOG-INTERACTION-INVENTORY.md`](./dora-ict-register/FRONTEND-DIALOG-INTERACTION-INVENTORY.md)
  - [`docs/dora-ict-register/FRONTEND-UX-MANUAL-AT-VERIFICATION-2026-07-12.md`](./dora-ict-register/FRONTEND-UX-MANUAL-AT-VERIFICATION-2026-07-12.md)
  - [`docs/dora-ict-register/RELEASE-HARDENING-RETROSPECTIVE-2026-08-08.md`](./dora-ict-register/RELEASE-HARDENING-RETROSPECTIVE-2026-08-08.md)
- Development startup and local workflows:
  - [`docs/development/README.md`](./development/README.md)
- Documentation screenshots and support assets:
  - [`docs/assets/README.md`](./assets/README.md)
  - [`docs/assets/readme/README.md`](./assets/readme/README.md)
- Generated report artifacts:
  - [`docs/reports/README.md`](./reports/README.md) — checked-in third-party dependency/license report.
- DORA ICT-register specifications:
  - [`docs/dora-ict-register/README.md`](./dora-ict-register/README.md)
- Deployment and operations:
  - [`docs/deployment/README.md`](./deployment/README.md)
- Migration notes:
  - [`docs/migrations/README.md`](./migrations/README.md)
- Agent governance and execution:
  - [`docs/agent/README.md`](./agent/README.md)
  - [`docs/agents/README.md`](./agents/README.md) — agent domain glossary, issue-tracker workflow, and triage-label vocabulary.
  - [`AGENTS.md`](../AGENTS.md)
- Architecture Locks:
  - `tests/backend/pytest/architecture/`
  - `make -f scripts/Makefile test-architecture-locks`
  - `tests/backend/pytest/architecture/_capabilities_all_allowlist.toml`
  - `tests/backend/pytest/architecture/_endpoint_commit_allowlist.toml`
  - `tests/backend/pytest/architecture/_archive_allowlist.toml`
  - `tests/backend/pytest/architecture/_naming_allowlist.toml`
  - `backend/app/core/audit/_audit_matrix.toml`
- Authorization Capability Contract:
  - [`docs/security/authorization-capability-contract.md`](./security/authorization-capability-contract.md)
  - [`docs/security/authorization-capability-contract.json`](./security/authorization-capability-contract.json)
  - [`docs/security/capability-catalog.json`](./security/capability-catalog.json)
  - `backend/app/api/v1/endpoints/_reserved_modules.toml`
  - `tests/frontend/unit/src/authz/useAuthz.invariant.test.ts`
  - `tests/backend/pytest/test_risks.py`
- Transaction and archive decisions:
  - `backend/app/services/outbox/dispatcher.py`
  - `ControlStatus.inactive`
  - `Vendor.is_archived`
- Architecture decisions:
  - [`docs/adr/ADR-001-capabilities-module-unification.md`](./adr/ADR-001-capabilities-module-unification.md)
  - [`docs/adr/ADR-002-service-owned-transactions.md`](./adr/ADR-002-service-owned-transactions.md)
  - [`docs/adr/ADR-005-archivable-mixin-schema-contract.md`](./adr/ADR-005-archivable-mixin-schema-contract.md)
  - [`docs/adr/ADR-010-postgres-migration-rehearsal-contract.md`](./adr/ADR-010-postgres-migration-rehearsal-contract.md)
  - [`docs/adr/ADR-016-governed-mutation-proposals.md`](./adr/ADR-016-governed-mutation-proposals.md)
- client_factory:
  - `tests/backend/pytest/conftest.py`
  - `tests/backend/pytest/_get_db_override_whitelist.toml`
- Versioned planning context (live status remains in GitHub):
  - [`.planning/STATE.md`](../.planning/STATE.md)
  - [`.planning/ROADMAP.md`](../.planning/ROADMAP.md)
  - [`.planning/codebase/STRUCTURE.md`](../.planning/codebase/STRUCTURE.md)
- Historical planning archives:
  - [`.planning/phases/README.md`](../.planning/phases/README.md)
  - [`docs/reference/LEGACY_PATH_MAP.md`](./reference/LEGACY_PATH_MAP.md) (historical path/archive reference)

## Canonical vs Archival Boundary

- Authority and conflict-resolution contract:
  - [`docs/DOCUMENTATION_OWNERSHIP.md`](./DOCUMENTATION_OWNERSHIP.md)
- Canonical versioned documentation surfaces:
  - `AGENTS.md`
  - `docs/`
  - `.planning/README.md`
  - `.planning/PROJECT.md`, `.planning/STATE.md`, `.planning/ROADMAP.md`
  - `.planning/codebase/*.md`
  - `.planning/phases/README.md` (archive index only)
- Live delivery state:
  - the applicable GitHub Issue, pull request, or Project item owns assignment,
    priority, blocking, review, acceptance evidence, and closure.
- Archival records:
  - `.planning/phases/*` plans and summaries are historical snapshots unless a
    confirmed open live item explicitly designates one as its implementation plan.
  - Legacy or absolute `file:///...` links may exist in archival bodies and are preserved as-is.

## Validation

Run topology validation from repo root:

```bash
python3 scripts/tools/validate_documentation_ownership.py
python3 scripts/tools/docs_tree_audit.py --scope canonical --max-root-hops 3 --fail-on-unreachable
python3 scripts/tools/docs_tree_audit.py --scope full
python3 scripts/tools/structure_metrics_guard.py
```

## Reachability Contract

- Canonical leaf documents under `docs/` and `.planning/codebase/` must be reachable through markdown links from at least one root entrypoint (`AGENTS.md`, `docs/README.md`, `.planning/README.md`) within 3 hops.

Latest audit report location pattern:

- `tests/results/docs/docs-tree-audit-<timestamp>/docs-tree-audit.json`
- `tests/results/docs/docs-tree-audit-<timestamp>/docs-tree-audit.md`

### Identity foundations (group 1)

- [ADR-018](./adr/ADR-018-identity-foundations.md)
- [Developer/operator handoff](./security/identity-foundations.md)
- [Reserved local API contract](./security/identity-local-auth.openapi.json)
