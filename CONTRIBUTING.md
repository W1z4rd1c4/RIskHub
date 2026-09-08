# Contributing to RiskHub

RiskHub accepts public contributions through forks, issues, and pull requests.

## Ground Rules

- Open issues for bugs, UX gaps, docs fixes, and well-scoped feature proposals.
- Use a fork for code changes. Do not push directly to `main`.
- Keep pull requests focused. Small, reviewable changes move faster.
- All merges to `main` are maintainer-controlled. Opening a PR does not imply merge approval.

The authority for live work status, versioned planning, durable documentation,
and historical evidence is defined in
[docs/DOCUMENTATION_OWNERSHIP.md](./docs/DOCUMENTATION_OWNERSHIP.md). Do not
create a second live tracker or duplicate a normative rule without naming its
canonical source.

## Development Setup

For public evaluation and first-run Docker onboarding:

```bash
./scripts/install.sh demo
```

For routine contributor work, use the stable command façade:

```bash
./scripts/riskhub.sh setup
./scripts/riskhub.sh dev
```

`setup` repairs dependencies and starts local development services without
resetting application data. `./scripts/install.sh` remains the supported public
first-run and lifecycle surface; `./scripts/compose.sh`, `./scripts/dev.sh`, and
specialized `scripts/Makefile` targets remain available for advanced workflows.

The stable command meanings and CI gate ownership map are documented in
[docs/development/CONTRIBUTOR_COMMANDS.md](./docs/development/CONTRIBUTOR_COMMANDS.md).
For onboarding, local runtime expectations, and demo-auth behavior, read
[docs/development/README.md](./docs/development/README.md). For local hook setup
and security checks, use [docs/security/SECURITY.md](./docs/security/SECURITY.md).

## Branch and PR Workflow

1. Fork the repository.
2. Create a branch from `main`.
3. Make the smallest change that fully solves the issue.
4. Run the smallest relevant verification for the surface you changed.
5. Open a pull request against `main`.

For the explicitly planned identity stack, follow-up PRs may target
`feat/identity-group-*`. The same standard CI gates run on those base branches.
Retarget and rerun checks after the parent is accepted; a green child does not
authorize merging an unaccepted parent. See the canonical CI ownership map above.

## Verification Expectations

Run the smallest relevant checks before opening a PR:

```bash
./scripts/riskhub.sh test
./scripts/riskhub.sh lint
./scripts/riskhub.sh e2e
```

You do not need to run every command for every change, but your PR should explain what you ran and why that coverage matches the touched surface. Specialized contracts remain discoverable with `make -f scripts/Makefile help`.

For docs-only changes, verify links, commands, referenced file paths, and any documented behavior against the current code path. When changing user-facing behavior, update `docs/BUSINESS_LOGIC.md`, relevant user/admin docs, and Czech parity docs where the workflow is documented in both languages.

## Pull Request Checklist

- Describe the problem and the user-facing or operator-facing impact.
- Call out any risk hotspots touched, especially auth, approvals, RBAC, timezone handling, or deployment behavior.
- Update behavior documentation when the change affects workflows, API contracts, RBAC, admin operations, or user guidance.
- Note the verification you ran.
- Keep generated artifacts, local secrets, and runtime logs out of the diff.

## Review and Merge Policy

- Public PRs are welcome.
- Maintainer review is required before merge.
- `main` is protected and merges are intentionally limited to the maintainer.
- Closing a PR without merge is acceptable if the change is out of scope, unverified, or conflicts with current product direction.

## Security Issues

Do not open public issues for exploitable vulnerabilities. Use the process in [SECURITY.md](./SECURITY.md).
