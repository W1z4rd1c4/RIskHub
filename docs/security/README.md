# docs/security

Back to tree: [`docs/DOCUMENTATION_TREE.md`](../DOCUMENTATION_TREE.md)

## Purpose

Canonical security policy and reporting documentation for RiskHub.

## Contents

- [`authorization-capability-contract.md`](./authorization-capability-contract.md): Canonical authorization and capability contract, including backend authority, frontend gates, test evidence, and gap register.
- [`authorization-capability-contract.json`](./authorization-capability-contract.json): Machine-readable mirror used by the repo contract validator.
- [`frontend-container-vulnerability-policy.md`](./frontend-container-vulnerability-policy.md): Blocking severity, evidence retention, triage, and exception requirements for the built frontend image.
- [`SECURITY.md`](./SECURITY.md): Security scanning standards, CI gates, and vulnerability response policy.
- [`reports/README.md`](./reports/README.md): Time-stamped security scan and remediation reports.

## Notes

- Historical reports remain immutable records.
- If a report cycle is remediated later, add a supersession note in the original report pointing to the remediation report.
- Machine-readable findings indexes are emitted under `tests/results/security/<run-id>/findings-*.json`; parity/closure cycles may publish a consolidated index that updates status without mutating base-run findings.
- Release-parity gate reports may be tracked under `docs/security/reports/`. Generated `tests/results/release-parity-audit-<run-id>/` evidence is gitignored run output; its uploaded copy is retained by the release workflow for 14 days. Recorded commit/tree identities and artifact hashes establish which bytes were verified, but they do not make expired artifact bytes retrievable.
- Authorization-sensitive code changes must update the authorization/capability contract and pass `python3 scripts/security/validate_authz_capability_contract.py`.
- Keep this README updated when responsibilities or structure in this folder change.

## Native identity delivery

[Native credentials and MFA](identity-local-credentials.md) documents group 2 inputs,
proof/session boundaries, delivery, verification and the still-closed production gate.
