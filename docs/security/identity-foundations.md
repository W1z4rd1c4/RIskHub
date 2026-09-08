# Identity foundations — group 1 developer and operator handoff

Scope: #193–#196 in PR #209, under #192. Follow-up groups are #197–#200,
#201–#204, and #205–#208. This is not native production enablement.

## Before adopting this schema

Use the approved change window. Back up the database and installed configuration;
stop/drain old API workers and the scheduler. Apply migrations using the existing
release DB task. Do not leave a pre-change writer running beside the new eligibility
model. Configure the existing Entra production tuple and secrets; do not turn on DEBUG.

From the backend environment using the normal production secret-file configuration:

```bash
python -m scripts.identity_installation eligibility-report
# Empty fresh DB, after required schema/reference seeding and before user bootstrap:
python -m scripts.identity_installation initialize --maintenance-confirmed --source 'operator/change-reference' --dry-run
python -m scripts.identity_installation initialize --maintenance-confirmed --source 'operator/change-reference'
# Existing, reviewed Entra installation (never a demo-to-production shortcut):
python -m scripts.identity_installation adopt-entra --maintenance-confirmed --source 'operator/change-reference' --dry-run
python -m scripts.identity_installation adopt-entra --maintenance-confirmed --source 'operator/change-reference'
python -m scripts.identity_installation verify
```

Choose initialize **or** adopt-entra, not both as an improvised repair. Verify requires
an existing binding and writes nothing. Dry-run establishes no row. Repeating an equal
establishment is idempotent; conflicting profile/tenant/version fails. Exit 2 means
refused input/identity state; exit 3 means unavailable verification infrastructure.
No command creates/rekeys a User or forces provider conversion. Graph outage or a
missing/deleted/unlinked object blocks adoption until an operator reconciles the
trusted mapping. Source identifies accountability, not a credential. Never include
secrets in CLI arguments or the source reference.

Review inactive users and their audit/deprovision history before adoption. The
backfill preserves known upstream denials and explicitly suspends unexplained/manual
inactivity. Ambiguous or incomplete historical intent needs a conservative suspension
and explicit reviewed resumption; do not infer consent from a healthy directory record.
The same operation never rewrites ownership, role, scope or the audit identity.

After verification, start only consistent new API/scheduler instances. An unbound
or mismatched production instance fails before runtime services/jobs; this is deliberate,
not a reason to remove the guard. Validate an existing admin login and scoped business
read before reopening normal traffic. Versionless access credentials require login
again; already modern current-version authority retains its existing semantics.

## Writer and lock inventory

| Writer | Transaction owner / shared behavior |
|---|---|
| Manual `/users/{id}` and `/access/users/{id}` | Lifecycle locks, field policy, last-admin guard, actual-change invalidation and mutation audit in `log_user_update_and_commit` |
| Directory import | Same lifecycle lock for existing users; explicit role/link changes invalidate authority; disabled records enter common deprovisioning |
| Scheduled/manual directory check | Fetch upstream before locking; preserve local suspension; per-user service commit and explicit unavailable/missing outcomes |
| Password login | KDF/lockout work, then locked hash/version/eligibility recheck, shared issuance, auth workflow commit |
| SSO exchange | Verified token/challenge, locked User recheck/profile reconciliation, shared issuance, auth workflow commit |
| Refresh and replay | Existing single-winner rotation/User lock; common version+refresh invalidation on newly confirmed replay; existing audit and commit |
| Logout/admin revoke | Locked User, common revocation, existing audit and service commit |
| Manager cleanup | Org guard plus already ordered subordinate User locks; affected manager assignments invalidate subordinate authority |
| SSO bootstrap | Operator-only bootstrap; production binding must be established first; normal web administration cannot invoke it |
| Demo/seed commands | Existing explicit non-production surfaces; not an accepted adoption path or production credential policy |

Lock details and preserved exceptions are in [ADR-018](../adr/ADR-018-identity-foundations.md).
Only the common workflow primitive advances token_version in application code. It
does not commit: callers retain mutation/audit transaction ownership. Display-only
changes and unchanged access assignments do not create a security transition. Ordinary
manual resumption cannot bypass directory denial, local enrollment or last-admin rules.

## Reserved local HTTP contracts

The generated [OpenAPI catalogue](./identity-local-auth.openapi.json) is **not the live
application OpenAPI**. It documents the future local handlers without registering stubs.
Requests/responses and frontend types originate in `app.schemas.local_auth`; run:

```bash
python -m scripts.export_local_auth_contract
python -m scripts.export_local_auth_contract --check
```

All catalogue actions are POST, exclusively local-profile operations, and use existing
service-owned transaction boundaries. The catalogue gives path, input/output schema,
proof/capability requirement, response status and owning implementation issue. A
password-set enrollment remains anonymous. Recent authentication requires current
password+factor and a typed intended operation; the returned proof is single-use,
version/actor/target/intent bound. Factor recovery for a privileged target is operator-
controlled under #201, not an admin web override.

The ordinary login final 200 TokenResponse and SSO contract are unchanged by group 1.
Future `/auth/login` 202 challenges must be handled separately by #199/#205. Public
reset requests return generic 202 for all syntactically valid accounts. Disabled
methods use 403 `AUTH_METHOD_DISABLED`; invalid/expired/replayed proof uses generic
401; authority denial 403; state/last-admin conflict 409; input validation 422;
throttling 429; unavailable security-state enforcement 503. Existing endpoints retain
existing details except the explicitly changed strict-version/last-admin decisions.

## Threat/control ownership

| Threat | Control and owner |
|---|---|
| Wrong mode/tenant or mixed replicas | Explicit binding + startup validation (#194); installer/restore integration #204/#207 |
| Dormant directory password | Production local resolution rejects linked rows (#194/#195); no provider fallback |
| Old-token resurrection after credential/access change | Shared version/refresh transition and locked issuance (#195) |
| Sync undoes operator suspension / all admins removed | Independent eligibility + serialized last-platform-admin guard (#196) |
| Invitation theft, replay, mailbox enumeration | Purpose-limited grants, non-enumerating responses, bounded delivery #198/#200 |
| Password guessing/KDF exhaustion | Shared offline policy and resource admission #197; shared limits #198/#199 |
| Partial login mistaken for authentication | Restricted challenge vs final session schemas #193; enforced #199/#205 |
| Factor/reset takeover and lost-admin lockout | Recent proof and dual-controlled recovery #199–#201 |
| Secret leakage / key loss | Secret-file keyrings, encrypted factor/delivery state, rotation #198/#199/#201 |
| Restore resurrects newer-revoked credentials | Signing cutover and current-security-state reconciliation #207 |
| Browser leaks previous principal state | Existing principal isolation preserved; full journeys #205/#206/#208 |
| An incomplete custom profile goes live | Non-configurable release-admission guard until #208 |

Trust assumptions: protected host/root administration and secrets, reviewed Entra
configuration, TLS at the public boundary, and independently accountable human recovery
approvers. TOTP is not claimed phishing-resistant. No claim of regulatory certification.

## Verification and closure

Capture public pre-change failures, then run focused HTTP/state tests and the dedicated
PostgreSQL file. PostgreSQL skips are not passes. The PR's foundation workflow executes
both new files and the existing auth/directory regressions against a real database.
Generated-schema parity, production docs, authorization capability parity, architecture
locks, frontend schema/type checks and applicable hosted gates must all be reviewed.

This handoff records requirements and commands, not an assertion that every gate or
independent security review has already passed. The PR description is the candidate-
specific evidence ledger. Do not close the four issues solely because a draft exists.
Do not remove native admission denial or merge/deploy without the normal approval.
