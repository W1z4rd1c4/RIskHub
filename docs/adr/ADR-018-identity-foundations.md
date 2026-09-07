# ADR-018 — Deployment identity foundations

## Status

Proposed implementation in PR #209, group 1 of umbrella #192 (#193–#196).
Native production admission remains closed until #208. This ADR does not assert
completed MFA, password recovery, deployment selection, or independent review.

## Decision

Keep one stable RiskHub User, local authorization/capabilities, and ADR-011's
access/rotating-refresh/token-version model. The intended production tuples are
`microsoft_sso/graph` and `password/none`. `AUTH_MODE` and `DIRECTORY_PROVIDER`
remain the configuration authority; the installer will translate its friendly
choice to them. `resolve_identity_profile` validates the intended tuple.
`enforce_identity_release_admission` separately refuses native production until
the final candidate is verified under #208. No environment override exists.

Production still requires the existing 30/15-minute ordinary/platform-admin
access lifetimes, strict refresh claims, non-debug/non-mock execution, and the
existing host/origin/cookie/secret safeguards. Hybrid, emulator and auto directory
selection remain non-production. No outage enables another authentication method.

A singleton `installation_identity` row binds a database to a stable installation
UUID, profile, tenant (Entra only), contract version and establishment provenance.
Only explicit operator initialization/adoption writes it. API lifespan and enabled
scheduler startup validate it before admitting traffic/jobs. Existing Entra
adoption checks every linked object ID through the configured tenant's directory;
unlinked/missing/conflicting users require operator reconciliation. It never
links by email or changes User IDs, roles, ownership or passwords. Ordinary
same-tenant credential rotation is not identity migration. Provider/tenant
conversion is excluded from v1.

`local_suspended` is independent of upstream directory eligibility. Its timestamp
and the existing actor-attributed mutation audit record local suspension/resumption.
`local_enrollment_state` reserves `invited`, `password_set`, `enrolled` for subsequent
native implementation. NULL is existing Entra/legacy-development state, **not**
proof of native production enrollment. `is_active` remains a compatibility
projection. Authentication requires both this stored projection and current
underlying eligibility; expired directory break-glass cannot continue authentication
merely because the scheduler has not updated the projection yet.

Entra owns name, email, job title, external identity and organizational business-role
metadata. RiskHub owns role, scope, department, manager and business ownership.
Imported department can seed a new user, never overwrite an existing local assignment.
Directory synchronization may clear its own denial, never local suspension.

Actual credential and effective access changes advance User.token_version and revoke
refresh rows within the same service-owned transaction as the mutation and audit.
Password, SSO and refresh issuance recheck the locked User before granting authority.
Production signed bearer/refresh claims require genuine integer User/version values;
versionless legacy bearer tokens require reauthentication, not a production grace flag.
The shared invalidation implementation lives in `_auth_session_workflow.authority`.
Existing logout, admin revocation and confirmed replay audits retain their owners.

Manual destructive transitions preserve the last effective active global platform
administrator, not merely an admin-or-CRO. Upstream-mandated revocation still disables
the last administrator and emits an operator-recovery incident. No fallback account
or local-password bypass is created.

## Wire contract and implementation boundary

`app.schemas.local_auth` owns reserved request/response schemas and a documentation
catalogue, not a dynamic route registry. `scripts.export_local_auth_contract` exports
[OpenAPI](../security/identity-local-auth.openapi.json) and matching frontend types.
New handlers belong to #198–#201; importing their types registers no route.
A future password login can return a 202 `mfa_required`/`enrollment_required` challenge;
only existing TokenResponse represents a completed app session. Partial authority
must never contain an access token, refresh cookie or protected UserBrief.

The policy floor is invitations 24h; reset/email grants 30m; partial/recent-auth proofs
5m; full local password+factor age 8h; password length 15–128 code points; mandatory
native MFA. These are product decisions, not regulatory claims. A recent-auth proof
binds actor, target, operation, current authority, and exact intended change. Password
intent uses a keyed commitment, never a stored fast unkeyed password digest. Request
secrets use redacted representations. Cryptography and handlers are not implemented
by this contract ticket.

## Lock and transaction contract

The reviewed acquisition order is:

1. The transaction-scoped `riskhub.identity.administration` advisory guard.
2. Existing Threat, Process, Asset, Vendor identity advisory guards for the target.
3. Existing `org_chart` advisory guard.
4. Actor, target and affected subordinate User rows in ascending ID order.
5. Refresh rows and required business-resource/ownership rows.

Authentication/refresh/logout/replay take only User then refresh rows, never acquire
ownership/org guards while holding a User row. Existing ownership assignment writers
take their own identity advisory guard before resource rows. Lifecycle writers take
those guards before User rows, preserving the ordering at their shared boundary.
No KDF or directory request occurs inside the critical section. Directory check-all
commits each user's completed reconciliation before fetching the next upstream record;
it reports partial outcomes rather than retaining cross-user locks during network I/O.

The administration guard serializes the last-admin count and mutation. PostgreSQL
is authoritative; SQLite lock helpers are intentionally no-ops and prove no row-lock
safety. Failed transactions publish neither account changes nor revocation. Requests
already authorized before a transition are not retroactively cancelled; subsequent
authentication after commit must reject old authority.

## Migration and rollback

Migration `t9u0v1w2x3y4` is additive and forward-only under ADR-010. Inactive accounts
without a trusted automatic directory reason (or without an external identity) become
locally suspended. Known automatic denials retain their upstream provenance; existing
active users are not re-granted privileges. No binding is inferred during migration.
Operators must review ambiguous historical inactivity in the dry-run inventory and
reconcile it before adoption; missing historical intent cannot be reconstructed from
`is_active` alone.

See [the operating handoff](../security/identity-foundations.md) before deployment.
Maintain the suspension/binding and strict authority guards in any rollback. Never
remove a binding to bypass drift, decrement versions, or revive refresh rows. Old
binaries do not understand the new eligibility projection; use a compatible build or
maintenance/roll-forward. Group 4 owns the complete credential-aware restore drill.

## Verification

Public HTTP regressions cover password invalidation, deactivate/reactivate, local
suspension through directory changes, last-admin denial, strict claims and capabilities.
The migration test checks existing IDs/inactivity and unchanged ownership references.
Independent PostgreSQL transactions cover binding races, last-admin removal and
issuance/account-change races; existing replay tests remain required. Evidence and
unexecuted gates are recorded against the actual PR candidate, not asserted here.
