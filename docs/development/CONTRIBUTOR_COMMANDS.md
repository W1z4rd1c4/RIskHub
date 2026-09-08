# Contributor Command and CI Contract

> **Owner**: RiskHub Maintainer
>
> **Audience**: Contributors, reviewers, CI maintainers
> **Change rule**: update this document, its machine contract, validator, and
> evidence together whenever command meaning or workflow topology changes.

RiskHub retains a broad internal automation surface for database, browser,
security, release, migration, and evidence workflows. Routine contributors use a
small stable façade:

```bash
./scripts/riskhub.sh <command>
```

The façade delegates to existing supported scripts and `scripts/Makefile`
targets. It does not reimplement their logic.

## Stable Commands

| Command | Canonical delegate | Meaning and side effects |
|---|---|---|
| `setup` | `./scripts/install.sh doctor --mode dev --repair` | Repairs dependency state, starts DB-only infrastructure, and starts daemonized backend/frontend services. It does not reset application data. |
| `dev [options]` | `./scripts/install.sh dev [options]` | Starts the supported local contributor workflow and forwards options such as `--backend`. |
| `lint` | `make -f scripts/Makefile lint lint-types` | Runs frontend lint/type/build/debt checks, backend Ruff and suppression checks, and backend mypy. |
| `test` | `make -f scripts/Makefile test` | Runs the default backend regression contract, excluding PostgreSQL-only and benchmark markers. |
| `e2e` | `make -f scripts/Makefile test-e2e` | Runs the guarded Playwright matrix and retains the explicit test-database safeguards. |
| `release-check` | `make -f scripts/Makefile release-parity-audit` | Runs the full local release-parity audit. It stops local development processes and tears down the active Compose stack before exercising runtime paths, so it may interrupt the current environment. It writes evidence under `tests/results/`. |
| `clean` | `make -f scripts/Makefile clean` | Tears down Compose volumes and removes Python/pytest caches, `node_modules`, frontend build output, coverage, and test results. It intentionally keeps `backend/venv`. |
| `help` | façade help | Prints this stable command set and the advanced-target discovery command. |

Environment variables pass through to the delegate. The façade does not bypass
safety guards, change exit codes, or supply alternate defaults.

## Advanced Surface

Specialized targets remain discoverable through:

```bash
make -f scripts/Makefile help
```

Use them for PostgreSQL-only tests, architecture locks, documentation topology,
security probes, deployment verification, migration rehearsals, release
publication, and benchmark lanes. Do not add a specialized target to the stable
façade unless it is a frequent end-to-end task with durable semantics.

## CI Gate Map

[`ci-gate-contract.json`](./ci-gate-contract.json) is the executable inventory.
It records exact workflow event filters, every governed job, protected-main
placement, owner, purpose, runtime budget, first-triage action, exact job
conditions, and blocking/advisory semantics. The validator compares these facts
to the actual YAML and rejects duplicate providers for protected check names;
generic event-name and substring checks are insufficient.

`release.yml` is additionally bound to the reviewed Git blob SHA recorded in the
machine contract. Any change to release publication, image builds, Linux bundle
verification, actions, jobs, or triggers changes that identity and requires an
explicit contract refresh after review.

Runtime ranges are maintained review budgets, not SLAs. Three consecutive
successful runs above an upper bound trigger owner review; product, security,
database, or release assurance must not be removed merely to meet the budget.

`Required` reflects the protected-`main` settings snapshot recorded during this
review. A required check must have exactly one pull-request provider that emits
that context for every applicable PR.

| Check | Workflow | Execution lane | Budget | Owner | Purpose | First triage action |
|---|---|---|---|---|---|---|
| `Frontend Unit Tests` | `lint.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop` | 3-10 min | Frontend | Enforce frontend unit behavior and coverage floor. | Run `cd frontend && npm run test:coverage`. |
| `PR Merge Result Build` | `lint.yml` | PR to `main`/`develop` only; required; exact condition `github.event_name == 'pull_request'` | 2-6 min | Frontend/Release | Build the synthetic merge result and catch integration-only failures. | Update the branch and reproduce the merge-candidate build. |
| `Backend Quality` | `lint.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; required | 2-8 min | Backend | Enforce Ruff, mypy, and suppression budgets. | Run `./scripts/riskhub.sh lint`. |
| `Frontend + Repo Contracts` | `lint.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; required | 6-15 min | Repository | Enforce frontend lint/type/build and repository/documentation/policy contracts. | Run the named failing command from `lint.yml`. |
| `Backend SQLite Regression` | `backend-postgres.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop` | 8-20 min | Backend | Run the default fast backend regression contract on SQLite. | Run `make -f scripts/Makefile test`. |
| `Backend Postgres Regression` | `backend-postgres.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop` | 20-35 min | Backend/Data | Verify migrations, constraints, locking, and PostgreSQL behavior. | Run `make -f scripts/Makefile test-postgres-ci` against the test DB. |
| `Classify Playwright E2E Scope` | `e2e.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; manual | 1-3 min | Product/QA | Decide whether the changed paths require the desktop Playwright suite. | Inspect the changed-path base and classifier output. |
| `Playwright E2E Shard ${{ matrix.shard }}/4` | `e2e.yml` | Product-affecting changes; four isolated serial shards | 8-30 min | Product/QA | Run one isolated quarter of the desktop Playwright suite. | Download the failing shard artifacts and reproduce the named tests. |
| `Playwright E2E Tests` | `e2e.yml` | Always-run shard aggregator; required | 15-35 min | Product/QA | Require successful shards and verify accessibility execution across their reports. | Open the failing shard and reproduce only the named tests. |
| `Production Profile Smoke` | `e2e.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; manual | 5-20 min | Backend/Security | Verify production-profile startup, headers, SSO, Redis, and disabled docs. | Inspect `prod-smoke-backend.log` and reproduce the profile. |
| `Docker Onboarding Smoke` | `startup-smoke-pr.yml` | PR to `main`/`develop`/`feat/identity-group-*`; sole protected-context provider; required | 8-20 min | Deployment/Operations | Verify the public Docker onboarding path against the exact PR head. | Download `startup-smoke-pr` and inspect Compose/service logs. |
| `Docker Onboarding Smoke (Scheduled)` | `startup-smoke.yml` | Push to `main`/`develop`; `45 2 * * *`; manual; not a PR provider | 8-20 min | Deployment/Operations | Verify public Docker onboarding outside the PR lane. | Download `startup-smoke` and inspect Compose/service logs. |
| `Frontend Container Injected Finding Contract` | `frontend-container-gate-contract.yml` | Path-filtered PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; manual; blocking workflow but not required on protected `main` | 1-5 min | Security/Supply Chain | Prove the production frontend container gate rejects an injected qualifying CRITICAL Trivy finding. | Download `frontend-container-injected-finding-evidence`, inspect its SARIF/status JSON, then run the frontend gate validator and focused contract tests. |
| `Public Repo Hygiene` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule; required | 1-5 min | Security/Repository | Prevent tracked privacy, path, and public-repository hygiene regressions. | Run `make -f scripts/Makefile public-repo-hygiene`. |
| `Workflow Pin Validation` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 1-5 min | Security/Repository | Enforce immutable workflow, service-image, and scanner references. | Run workflow-pin and repository-hardening validators. |
| `Authorization Capability Contract` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 1-5 min | Security/Authorization | Prevent authorization and capability-contract drift. | Run the authorization contract validator and reconcile both mirrors. |
| `Python Security (Bandit + pip-audit)` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 3-12 min | Backend/Security | Block high-severity Python SAST and dependency findings. | Download Bandit and pip-audit JSON. |
| `Frontend Security (npm audit)` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 2-8 min | Frontend/Security | Block high-severity frontend dependency vulnerabilities. | Run `cd frontend && npm audit --audit-level=high`. |
| `Frontend i18n (Parity + Hardcoded Scan)` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 2-8 min | Frontend | Enforce locale parity and prevent hardcoded user-facing strings. | Run `cd frontend && npm run i18n:test`. |
| `Redis Resilience Integration (non-blocking)` | `security.yml` | Schedule only; exact condition `github.event_name == 'schedule'`; advisory | 5-15 min | Backend/Resilience | Exercise Redis failure/recovery behavior without blocking PRs. | Inspect the scheduled pytest artifact and reproduce the Redis marker. |
| `Container Scan (Trivy + SBOM Correlation)` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 8-25 min | Security/Supply Chain | Evaluate built images and correlate backend SBOM findings. | Download container reports and separate Trivy, Grype, and infrastructure outcomes. |
| `Secrets Detection (Gitleaks)` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; push to `main`/`develop`; nightly/weekly schedule | 1-5 min | Security | Detect committed credentials and secret material across history. | Inspect the exact fingerprint and rotate genuine secrets. |
| `Security Headers Verification` | `security.yml` | PR to `main`/`develop`/`feat/identity-group-*`; exact condition `github.event_name == 'pull_request'` | 2-8 min | Backend/Security | Verify required response-security headers. | Run the security-header tests and inspect middleware configuration. |
| `Docs Governance` | `maintenance-governance.yml` | Path-filtered PR to `main`/`develop`/`feat/identity-group-*`; `30 1 * * *`; manual | 2-10 min | Maintainer/Docs | Enforce docs topology, production-contract docs, deprecated imports, and ratchet docs. | Run `make -f scripts/Makefile docs-topology-consistency`. |
| `Frontend Maintenance Contracts` | `maintenance-governance.yml` | Path-filtered PR to `main`/`develop`/`feat/identity-group-*`; `30 1 * * *`; manual | 5-20 min | Frontend/Maintainer | Enforce debt, dead-code, inline-style, and generated-artifact budgets. | Run the debt and cleanup validators. |
| `Backend Maintenance (Informational)` | `maintenance-governance.yml` | Path-filtered PR to `main`/`develop`/`feat/identity-group-*`; `30 1 * * *`; manual; advisory | 5-20 min | Backend/Maintainer | Report backend lint/type/suppression drift without acting as a merge gate. | Review Ruff, mypy, and suppression evidence. |
| `Python Dev Lock Refresh` | `python-dev-lock-refresh.yml` | Monthly `17 6 1 * *` or manual; `main` only; not required on protected `main`; 20-minute timeout; fails closed without the automation token; opens a refresh PR only when generated locks change and otherwise succeeds without a PR | 2-15 min | Backend/Dependency Maintenance | Regenerate the exact Python 3.13 development lock and propose changed resolver output for normal review. | Confirm `RISKHUB_AUTOMATION_PR_TOKEN` has Contents and Pull requests write access, then inspect the permission preflight, resolver output, and change detection. |
| `Release Parity Contract` | `release-parity-pr.yml` | Manual dispatch only | 2-8 min | Release | Run low-cost release docs, pinning, hardening, and deprecated-import contracts. | Run the named contract validator. |
| `Fast Parity Audit (Non-Blocking)` | `release-parity-fast.yml` | Push to `main`; `15 2 * * *`; manual; advisory | 20-60 min | Release | Exercise a reduced release-parity loop without blocking delivery. | Download the parity artifact and inspect fingerprints/decision. |
| `Workflow Pin Validation` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 1-5 min | Release/Security | Revalidate immutable workflow and image references before publication. | Run the workflow-pin validator. |
| `Prepare Release Metadata` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 1-3 min | Release | Resolve and validate the release version. | Inspect the tag or manual version input. |
| `Release Parity Gate` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 45-120 min | Release | Run full release parity and require a GO decision. | Inspect the parity artifact and `decision.json`. |
| `Publish Docker Images` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 15-45 min | Release/Operations | Build and publish versioned runtime images to GHCR. | Inspect GHCR auth and the first failing build/push. |
| `Build Linux Bundle` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 10-30 min | Release/Operations | Build the versioned offline Linux installation bundle. | Run the bundle builder and inspect manifest/build output. |
| `Verify Linux Bundle` | `release.yml` | Tag push `v*`; manual input `version`; release file bound by Git blob SHA | 15-45 min | Release/Operations | Verify contents, offline installation, rendered services, nginx, and deploy dry run. | Reproduce the failing bundle assertion. |
| `Create GitHub Release` | `release.yml` | Tag push `v*`; exact condition `startsWith(github.ref, 'refs/tags/')`; release file bound by Git blob SHA | 2-10 min | Release | Publish changelog-backed release notes and attach the verified Linux bundle. | Verify tag, changelog section, bundle, and release action output. |
| `Identity source provenance` | `identity-foundations.yml` | Path-filtered PR to `main` or `feat/identity-group-*`; blocking execution, not a protected-main required-name snapshot | 1-5 min | Backend/Security | Bind reviewed source artifacts to the exact PR head and tree without publishing credentials. | Compare the source artifact commit/tree with the current PR head. |
| `Identity foundation PostgreSQL regression` | `identity-foundations.yml` | Path-filtered PR to `main` or `feat/identity-group-*`; blocking execution, not a protected-main required-name snapshot | 1-25 min | Backend/Security | Exercise identity authority, lifecycle and session regressions against PostgreSQL. | Inspect the first failing identity test and rerun with a disposable TEST_DATABASE_URL. |
| `Native identity PostgreSQL and Redis regression` | `identity-local.yml` | Path-filtered PR, including stacked identity branches; blocking execution, not a protected-main required-name snapshot | 1-25 min | Backend/Security | Verify native credentials, MFA, recovery, real TLS mail, Redis limits and independent PostgreSQL races. | Inspect native-regression.log and identity-regression.log for the exact candidate; skips are not backend evidence. |
| `Native generated-type and frontend build compatibility` | `identity-local.yml` | Path-filtered PR, including stacked identity branches; blocking execution, not a protected-main required-name snapshot | 1-15 min | Frontend | Check native API declaration compatibility with the existing frontend build. | Reproduce npm ci and npm run build against the tested head; this is not a new native UI journey. |
Identity stack PRs use the same standard gates as PRs to `main`/`develop`; only
the base-branch admission filter is broader. Push, schedule, release publication,
severity thresholds and the protected-main required-name snapshot are unchanged.
The identity-specific budgets above are initial review envelopes bounded by their
configured job timeouts, not measured completion promises. Required branch
protection must be verified live by a maintainer before merge; this file is a
versioned snapshot, not authority to bypass missing reviews.

The full local `release-check` command is not equivalent to either hosted parity
job. It performs the comprehensive audit and has the disruptive local side
effects documented above.

## Change Policy

A change to this façade or CI map must:

1. remain a thin delegate to an existing canonical implementation;
2. preserve underlying environment variables, safety guards, and exit codes;
3. avoid a second implementation of test, install, or release logic;
4. update this document, `ci-gate-contract.json`, `CONTRIBUTING.md`, and
   `scripts/README.md` when their contract changes;
5. update the validator and focused tests;
6. reconcile exact workflow events, branch/tag filters, path filters, job names,
   exact job conditions, the release workflow Git blob SHA, and protected-branch
   settings;
7. describe command side effects and every CI job’s owner, purpose, runtime
   budget, execution lane, and first triage action.

## Validation

```bash
bash -n scripts/riskhub.sh
python3 scripts/tools/validate_contributor_command_contract.py
cd backend
venv/bin/pytest ../tests/backend/pytest/test_contributor_command_contract.py -q
```
