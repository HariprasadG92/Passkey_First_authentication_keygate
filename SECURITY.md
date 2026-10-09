# Security policy

Keygate is an identity provider, so security reports are welcome and taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability reporting).

Include what you can:

- the affected component (API, UI, OIDC provider, Notes demo, deployment config) and version/commit;
- steps to reproduce or a proof of concept;
- the impact you think it has.

You can expect an acknowledgement within **3 business days** and an assessment within
**10 business days**. Fixes are developed privately and released with a security advisory that
credits you, unless you'd rather stay anonymous.

## Supported versions

| Version | Supported |
| ------- | --------- |
| `main` (latest) | ✅ |
| Older commits | ❌ please reproduce on `main` |

## Scope

In scope: everything in this repository: authentication and session handling, WebAuthn,
MFA and recovery, social login, RBAC, the audit log, the OpenID Connect provider, the Notes
demo and the shipped container and gateway configuration.

Out of scope: the Mailpit dev mail catcher, findings that require a compromised host or
database superuser, missing hardening that's already listed as a residual risk in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#5-residual-risks-and-accepted-trade-offs), and
volumetric denial of service.

## Safe harbour

Good-faith research that respects users' privacy, avoids data destruction and service
disruption, and only tests accounts you own is welcome. We won't pursue legal action for it.

## For operators

Before running Keygate in production, read the deployment notes in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#deployment-notes). In short: TLS, `production`
mode (it refuses insecure settings), unique secrets (ideally from a KMS), a database role
without `TRUNCATE`/`DELETE` on `audit_events`, and periodic signing-key rotation.
