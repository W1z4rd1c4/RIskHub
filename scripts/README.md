# scripts

## Purpose

Operational and development automation for RiskHub.

## Supported entrypoints

- `./scripts/riskhub.sh <command>`
  - Stable contributor façade for `setup`, `dev`, `lint`, `test`, `e2e`, `release-check`, and `clean`.
  - Delegates to the canonical install and Make targets without duplicating their logic, guards, or exit behavior.
  - `release-check` is disruptive: the release-parity runtime audit stops local development processes and tears down the active Compose stack before exercising its paths.
  - `clean` removes Compose volumes, `node_modules`, caches, build output, and test evidence but intentionally retains `backend/venv`.
  - Contract and executable CI ownership map: [`docs/development/CONTRIBUTOR_COMMANDS.md`](../docs/development/CONTRIBUTOR_COMMANDS.md) and [`docs/development/ci-gate-contract.json`](../docs/development/ci-gate-contract.json).
- `./scripts/install.sh`
  - Public first-run and lifecycle installer for demo, local contributor, and guided production flows.
  - Thin shell wrapper over `./scripts/install_cli.py` and `./scripts/install_lib/`.
  - Covers `production`, `upgrade`, `status`, `logs`, `doctor`, and `verify` on top of the lower-level script layer.
- `./scripts/dev.sh`
  - Advanced/manual local contributor startup.
  - Starts Docker-backed DB + Redis, performs local backend setup/schema preflight, and runs backend or backend+frontend locally.
- `./scripts/compose.sh`
  - Advanced/manual Docker onboarding and packaged development startup.
  - Supports `up`, `down`, `logs`, and deterministic `reset`.
- `./scripts/deploy.sh`
  - Advanced/manual production deployment/admin CLI used underneath `./scripts/install.sh production`, `upgrade`, `status`, `logs`, `doctor`, and `verify`.
- `make -f scripts/Makefile <target>`
  - Advanced convenience wrapper around the supported scripts above plus specialized validation/test helpers.

## Directory map

- `deploy/`
  - Shared library helpers used by `./scripts/deploy.sh`.
- `install_lib/`
  - Stdlib-only Python control plane used by `./scripts/install_cli.py` and the public `./scripts/install.sh` wrapper.
  - Production lifecycle internals are now split into release-input, secret/scaffold, lifecycle-action, and summary/verify helpers to keep the public wrapper contract stable while reducing single-file sprawl.
- `prod/`
  - Retained internal production runtime/install helpers behind the supported deploy CLI.
- `security/`
  - Security probes, parity audits, and resilience harnesses.
- `tools/`
  - Documentation topology, README coverage, and repository guard utilities.
- `quality/`
  - Quality-budget configuration and related support files.
- `release/`
  - Release packaging helpers.
- `runtime-artifacts/`
  - Generated/runtime-owned artifacts tracked by dedicated README guidance.

## Notable standalone utilities

- `backend/scripts/import_ict_register_workbook.py`
  - Manifest-pinned, PostgreSQL-only offline ICT Register cutover importer. Apply mode requires an explicit distinct active CRO (`--cutover-authorized-by`), authorization reference `#53`, and the committed digest-pinned `--accountability-map`; verify mode requires and validates that map but remains read-only and policy-neutral. The combined sidecar contains all 148 Process and 183 Asset natural keys with their exact legacy owner text. It is explicitly synthetic demo accountability: every Process Owner and every Asset Business/ICT Owner resolves to the seeded Risk Manager, every Owning Department resolves to Risk Management, and none of those assignments is evidence of real ownership. Verification preserves the immutable raw-workbook DQ profile and derives a separate post-enrichment profile from the validated map plus the production Risk-model disposition; its non-zero tally is recomputed from all 52 adjusted checks. The importer accepts only a fresh or exact-manifest target, uses an audited row-locked policy window around all service-layer phases in one transaction, pins the map digest into audit/completion evidence, stops before dependent phases on the first finding, restores exact scenario state before its sole commit, rejects same-key or map drift before an exact re-run, and rolls back on findings or interruption.
- `check_docs_contract.py`
  - Enforces documentation frontmatter and topology rules.
- `run_playwright_with_watchdog.sh`
  - Wraps Playwright execution with artifact/watchdog handling.
- `verify_security_headers.py`
  - Verifies expected security headers for deployed/frontend targets.
- `install_cli.py`
  - Internal Python entrypoint behind the public `./scripts/install.sh` wrapper.

## Startup notes

- `./scripts/riskhub.sh` is the stable day-to-day contributor command façade.
- `./scripts/install.sh` is the public first-run entrypoint.
- `./scripts/install.sh` stays the public entrypoint even though the lifecycle control plane now lives in Python under `./scripts/install_cli.py` and `./scripts/install_lib/`.
- `./scripts/dev.sh` is local-only.
- `./scripts/compose.sh` remains the advanced/manual Docker development entrypoint.
- If the local database is behind the Alembic head, `./scripts/dev.sh` exits early and prints the recovery command:

```bash
cd backend
./venv/bin/alembic upgrade head
```

- Production deployment remains separate and is guided through `./scripts/install.sh production` or the lower-level `./scripts/deploy.sh`.
- Day-2 production lifecycle is wrapper-first through `./scripts/install.sh status`, `logs`, `doctor`, and `upgrade`.

Identity stack PRs also run the standard CI gates; the authoritative trigger,
owner and triage inventory is `docs/development/ci-gate-contract.json`.

## Common verification commands

```bash
./scripts/riskhub.sh lint
./scripts/riskhub.sh test
./scripts/riskhub.sh e2e
./scripts/riskhub.sh release-check
make -f scripts/Makefile verify
make -f scripts/Makefile quality-repo-contracts
make -f scripts/Makefile verify-startup-scripts
make -f scripts/Makefile docs-topology-consistency
make -f scripts/Makefile security-contract-probe
```

Security probe outputs are written under `tests/results/security/`.
Documentation audit outputs are written under `tests/results/docs/`.
Local doctor checks warn when ignored local artifacts such as `backend/logs/` or `tests/results/` grow beyond the maintenance budget. Use `rm -rf backend/logs/* tests/results/*` when those artifacts are no longer needed.
