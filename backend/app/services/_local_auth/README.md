# Native credential lifecycle

The native `password` + `none` profile uses the existing RiskHub User, capabilities,
transaction boundary, JWT issuer and refresh lineage. Production admission remains
closed until #208. There is no separate app-session model here.

| Module | Responsibility |
|---|---|
| `common.py` | Validated installation/key/rate-limit context; transaction and audit adapters |
| `keys.py` | Strict secret files, versioned independent purpose keys, AES-GCM and keyed intent binding |
| `limiter.py` | Atomic shared Redis admission; no memory fallback |
| `artifacts.py` | Purpose-bound opaque grant issuance, locked one-time consumption and revocation |
| `enrollment.py` | Admin invitations and password-only restricted enrollment |
| `factors.py` | TOTP/backup codes, locked MFA completion and recent-auth action proofs |
| `credentials.py` | Reset/change and verified address changes using common authority revocation |
| `delivery.py` | Encrypted delivery envelopes dispatched through the existing outbox over verified TLS SMTP |
| `admin.py` | Admin reset-link requests and nonsecret delivery/enrollment status |
| `sessions.py` | Validate native authentication metadata on the common JWT/refresh lineage |

Lock order: lifecycle administration/ownership guards (only when needed) → User
rows → grants → factor/code → refresh rows. No network or KDF under these locks.
MFA HTTP adapters retain the transaction through the existing session issuer and
commit using the auth service boundary. Failed single-use attempts either mutate
nothing or explicitly commit a failure/revocation before returning generic denial.

See `docs/security/identity-local-credentials.md` for operational inputs, limitations,
rate limits, status meanings, key-handling requirements and developer handoff.
