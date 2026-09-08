# ADR-007 Bounded Context Taxonomy

## Status

Accepted

## Context

RiskHub architecture work touches many workflow packages. Broad sweeps across all services create merge risk and make rollback difficult.

## Decision

Architecture sweeps use seven bounded contexts: `_riskhub_config`, `_identity_access_lifecycle`, `_vendor_governance`, `_register_listings`, `_approval_execution`, `_entity_mutation_lifecycle`, and `_kri_history`. Each context owns its exception, transaction, listing, and audit cleanup for its files before the next context begins. See Amendment 1 (below) for secondary categories applied to remaining packages.

## Alternatives Rejected

- Sweep by technical layer: rejected because service workflows cross layers and would split one behavior across many checkpoints.
- One full-repo sweep: rejected because rollback and review risk are too high.
- Per-file cleanup: rejected because it misses workflow-level ordering and atomicity.

## Migration Impact

Each context adds its own characterization tests, exception ban, transaction atomicity test, and invariant lock. Context order should follow the execution plan unless a dependency forces a change.

## Rollback Strategy

Rollback by bounded-context checkpoint. Contexts should avoid cross-context edits except documented adapters.

## Invariant Tests

- Per-context `HTTPException` ban once migrated.
- Per-context transaction atomicity tests.
- File-disjointness check before starting the next context.

## Amendment 1 — Read-Shape, Workflow-Paired, Adapter, and Cross-cutting Contexts

### Status

Accepted

### Context

ADR-007 names seven write-side bounded contexts but the codebase carries 31 underscore-prefixed packages plus the `_monitoring_response.py` file entry under `backend/app/services/`, totaling 32 classified entries. The unnamed remainder falls into four coherent shapes: read-shape projections, workflow-paired companions, adapter contexts that translate external systems, and a small set of cross-cutting modules that supply policy primitives to every other context. Without an explicit secondary taxonomy, reviewers read the seven-context list as exhaustive and misclassify new packages.

### Decision

ADR-007's taxonomy is extended with three secondary categories (read-shape, workflow-paired, adapter) and one cross-cutting category. The seven-context list at ADR-007 §Decision remains the canonical write-side enumeration. Each package has a PRIMARY classification and may additionally appear as the right-half of a workflow pair when paired with another context; the disjointness lock permits this many-to-one membership for workflow-pair right-halves. Each allowlist must be atomic: entries are written as a single contiguous list per TOML file and may not span multiple lists.

1. **Read-shape contexts** project pre-existing rows. They inherit transaction rules from the underlying write-side context and may not commit. Read-shape contexts are not separate sweep units. Examples: `_register_listings` (dual-classed, also write-side), `_monitoring_status`, `_dashboard_metrics`, `_quarterly_comparison`, `_reporting`, `_org_chart`. The single-file `backend/app/services/_monitoring_response.py` is the read-shape complement of `_monitoring_status` and is registered in the read-shape allowlist as a file, not a package.

2. **Workflow-paired contexts** sweep together as one rollback unit. A sweep that touches one half must also cover the other. The pairs are:
   - `_approval_queue` ↔ `_approval_execution`
   - `_issue_register` ↔ `_issue_workflow`
   - `_vendor_links` ↔ `_vendor_governance`
   - `_access_workflow` ↔ `_identity_access_lifecycle`
   - `_control_execution` ↔ `_entity_mutation_lifecycle`
   - `_deadline_execution` ↔ `_kri_history`
   - `_auth_session_workflow` ↔ `_auth_session`
   - `_risk_questionnaires` ↔ `_vendor_governance`
   - `_vendor_workflow` ↔ `_vendor_governance`
   - `_orphaned_items` ↔ `_identity_access_lifecycle`
   - `_notification_inbox` ↔ `_identity_access_lifecycle`
   - `_ict_register_lifecycle` ↔ `_vendor_governance`

3. **Adapter contexts** are exempt from the per-context `HTTPException` ban only at the adapter boundary. Translation from external-system exceptions to RiskHub `DomainError` subclasses is the adapter's job per ADR-003. Adapters: `_directory_identity`, `_graph_directory` (after the package move planned under finding 61), `_admin_telemetry`, `_activity_log_query`, `_auth_session`.

4. **Cross-cutting contexts** are policy modules reached by every other context. They own canonical primitives (capability builders, configuration defaults) and are subject to ADR-001 and ADR-008 SSOT discipline rather than the per-context atomicity sweeps. Cross-cutting contexts: `_authorization_capabilities`, `_config`.

### Classification Table

The full classification covers the 31 underscore-prefixed packages plus the `_monitoring_response.py` file entry. Workflow-pair right-halves carry their PRIMARY classification where applicable; their workflow-pair membership is recorded separately in `_bounded_context_workflow_pairs.toml`.

| Package | Category | Rationale | Enforcement TOML |
|---|---|---|---|
| `_riskhub_config` | Write-side | ADR-007 §Decision context #1 | `_bounded_context_write_side.toml` |
| `_identity_access_lifecycle` | Write-side | ADR-007 §Decision context #2 | `_bounded_context_write_side.toml` |
| `_vendor_governance` | Write-side | ADR-007 §Decision context #3 | `_bounded_context_write_side.toml` |
| `_register_listings` | Write-side + Read-shape (dual; explicitly allowed) | ADR-007 + listing planner | `_bounded_context_write_side.toml` + `_bounded_context_read_shape.toml` |
| `_approval_execution` | Write-side | ADR-007 §Decision context #5 | `_bounded_context_write_side.toml` |
| `_entity_mutation_lifecycle` | Write-side | ADR-007 §Decision context #6 | `_bounded_context_write_side.toml` |
| `_kri_history` | Write-side | ADR-007 §Decision context #7 | `_bounded_context_write_side.toml` |
| `_monitoring_status` | Read-shape | Status projection, no commits | `_bounded_context_read_shape.toml` |
| `_dashboard_metrics` | Read-shape | Dashboard metric projection | `_bounded_context_read_shape.toml` |
| `_quarterly_comparison` | Read-shape | Quarterly metric projection | `_bounded_context_read_shape.toml` |
| `_reporting` | Read-shape | Reporting export projection | `_bounded_context_read_shape.toml` |
| `_org_chart` | Read-shape | Org-chart traversal | `_bounded_context_read_shape.toml` |
| `_monitoring_response.py` | Read-shape (file entry) | File-level read-shape complement of `_monitoring_status` | `_bounded_context_read_shape.toml` |
| `_approval_queue` | Workflow-paired (`_approval_execution`) | Queue side of approval | `_bounded_context_workflow_pairs.toml` |
| `_issue_register` | Workflow-paired (`_issue_workflow`) | Register side | `_bounded_context_workflow_pairs.toml` |
| `_issue_workflow` | Workflow-paired (`_issue_register`) | Workflow side | `_bounded_context_workflow_pairs.toml` |
| `_vendor_links` | Workflow-paired (`_vendor_governance`) | Link mutators | `_bounded_context_workflow_pairs.toml` |
| `_access_workflow` | Workflow-paired (`_identity_access_lifecycle`) | Identity workflow | `_bounded_context_workflow_pairs.toml` |
| `_control_execution` | Workflow-paired (`_entity_mutation_lifecycle`) | Control execution | `_bounded_context_workflow_pairs.toml` |
| `_deadline_execution` | Workflow-paired (`_kri_history`) | Deadline jobs | `_bounded_context_workflow_pairs.toml` |
| `_local_auth` | Workflow-paired (`_auth_session_workflow`) | Native credential/factor lifecycle; common session authority retained | `_bounded_context_workflow_pairs.toml` |
| `_auth_session_workflow` | Workflow-paired (`_auth_session`) | Session workflow | `_bounded_context_workflow_pairs.toml` |
| `_risk_questionnaires` | Workflow-paired (`_vendor_governance`) | Questionnaire lifecycle | `_bounded_context_workflow_pairs.toml` |
| `_vendor_workflow` | Workflow-paired (`_vendor_governance`) | Vendor workflow | `_bounded_context_workflow_pairs.toml` |
| `_orphaned_items` | Workflow-paired (`_identity_access_lifecycle`) | Orphan detection during deactivation | `_bounded_context_workflow_pairs.toml` |
| `_notification_inbox` | Workflow-paired (`_identity_access_lifecycle`) | Notification dispatch on identity events | `_bounded_context_workflow_pairs.toml` |
| `_ict_register_lifecycle` | Workflow-paired (`_vendor_governance`) | ICT Register write-side lifecycles (Process, later Asset/Threat); the register graph shares link tables and sweeps with vendor governance | `_bounded_context_workflow_pairs.toml` |
| `_directory_identity` | Adapter | External directory identity | `_bounded_context_adapters.toml` |
| `_graph_directory` | Adapter | Microsoft Graph adapter | `_bounded_context_adapters.toml` |
| `_admin_telemetry` | Adapter | Admin telemetry projection | `_bounded_context_adapters.toml` |
| `_activity_log_query` | Adapter | Activity-log query adapter | `_bounded_context_adapters.toml` |
| `_auth_session` | Adapter | Session-token primitive | `_bounded_context_adapters.toml` |
| `_authorization_capabilities` | Cross-cutting | ADR-001 capability builder SSOT | `_bounded_context_cross_cutting.toml` |
| `_config` | Cross-cutting | ADR-008-style config defaults SSOT | `_bounded_context_cross_cutting.toml` |

### Alternatives Rejected

- Expand the seven-context list to all service packages: rejected because it loses sweep meaning and produces separate atomicity tests for what are really seven transaction-owning contexts plus secondary roles.
- Document elsewhere (`CONVENTIONS.md`, `AGENTS.md`): rejected because Loop 3 review showed reviewers read ADR-007 as exhaustive when classifying new packages.
- Merge workflow-paired contexts into a single context per pair: rejected because the splits reflect real read-vs-write boundaries (queue vs execution, register vs workflow, links vs governance).
- Three categories without `Cross-cutting`: rejected because `_authorization_capabilities` and `_config` would be force-fit into adapter or read-shape, neither of which captures their cross-cutting policy role; the lock would either fire on day 1 or accept silent miscategorization.
- Naming the fifth category `Core` instead of `Cross-cutting`: rejected because `Core` overloads "domain core" used elsewhere in DDD vocabulary; `Cross-cutting` precisely names the role (policy primitives reached by every other context).
- "EXACTLY ONE" disjointness without many-to-one for workflow-pair right-halves: rejected because it would force right-halves out of their primary write-side or adapter allowlist, breaking sweep semantics. The corrected formulation is PRIMARY classification plus the workflow-pair right-half exception.

### Migration Impact

Five TOMLs under `tests/backend/pytest/architecture/` enforce the taxonomy: `_bounded_context_write_side.toml`, `_bounded_context_read_shape.toml`, `_bounded_context_workflow_pairs.toml`, `_bounded_context_adapters.toml`, and `_bounded_context_cross_cutting.toml`. Existing per-context boundary tests (`test_w4_bc_a_riskhub_config_boundaries_red.py` through `test_w4_bc_g_kri_history_boundaries_red.py`) continue to operate on the seven canonical write-side contexts. Adapter contexts and cross-cutting contexts gain new exception-ban exemption holders; existing adapters did not raise `HTTPException` at adapter boundaries because they were not previously in scope of the per-context ban. `_graph_directory` was created by finding #61 when the four `graph_directory_*.py` modules moved into that package.

### Rollback Strategy

Rollback of this amendment removes this text. The TOMLs and the disjointness lock are owned by the #74a taxonomy census and remain valid for the seven-context core plus secondary classifications.

### Invariant Tests

- `tests/backend/pytest/architecture/test_w7_bounded_context_disjointness.py` validates that every underscore-prefixed package under `backend/app/services/` (excluding `__pycache__`) has a PRIMARY classification in an allowlist, with the documented exception of `_register_listings` which is dual-classed (write-side and read-shape) for sweep-order reasons. Workflow-pair right-halves additionally appear in the workflow-pair allowlist; the lock permits this many-to-one membership only for documented pairs. New packages must be classified at introduction; the lock fails on unclassified packages.
- `_bounded_context_write_side.toml` enumerates the seven canonical contexts.
- `_bounded_context_read_shape.toml` enumerates read-shape secondaries plus the `_monitoring_response.py` file entry.
- `_bounded_context_workflow_pairs.toml` enumerates ordered pairs `(left, right)` and records sweep coupling.
- `_bounded_context_adapters.toml` enumerates adapter packages and binds adapter exception translation back to ADR-003.
- `_bounded_context_cross_cutting.toml` enumerates cross-cutting packages and binds them to ADR-001 (capabilities) and ADR-008 (config-default SSOT) lock chains.
- Per-allowlist atomicity is asserted by parsing each TOML file as a single contiguous list; entries spanning multiple files trigger lock failure.
- Cross-reference: ADR-003 `DomainError` taxonomy governs adapter exception translation; ADR-001 governs `_authorization_capabilities` SSOT; ADR-008 governs the `_config` SSOT pattern.

## Native credential lifecycle amendment (#197–#200)

`_local_auth` is workflow-paired with `_auth_session_workflow`. It owns restricted
credential/factor/grant transitions and encrypted delivery orchestration, not a
new application-session model. The existing auth transaction boundary, User
identity and shared JWT/refresh issuer remain authoritative. Its limited status
projection serves the same lifecycle. `_bounded_context_workflow_pairs.toml`
classifies the package; all disjointness and endpoint-commit locks remain intact.

Cross-context invalidation acquires User then grant/factor/refresh state inside one
caller-owned transaction. See `docs/security/identity-local-credentials.md` for the
native context's exact lock order, expiry and recovery boundaries.
