# Architecture Decision Records

Lightweight ADRs: each records a decision, why it was made, what else was considered, and
what it costs. New decisions are appended; superseded ones are marked, never deleted.

| #   | Decision                                                        | Status   | Phase |
| --- | --------------------------------------------------------------- | -------- | ----- |
| 001 | Monorepo with independent per-app toolchains                    | Accepted | 0     |
| 002 | Single origin for UI and API via a reverse-proxy gateway        | Accepted | 0     |
| 003 | Trust `X-Forwarded-For` only from the gateway                   | Accepted | 0     |
| 004 | Per-request nonce CSP with `'strict-dynamic'`                   | Accepted | 0     |
| 005 | Structured logs with redaction and no query strings             | Accepted | 0     |
| 006 | Fail closed on weak credentials in production                   | Accepted | 0     |
| 007 | Separate liveness and readiness health checks                   | Accepted | 0     |
| 008 | Supply-chain hygiene from day one                               | Accepted | 0     |
| 009 | Server-side sessions in Postgres with hashed tokens and levels  | Accepted | 1     |
| 010 | Session-bound signed double-submit CSRF, default-deny           | Accepted | 1     |
| 011 | Magic-link token in the URL fragment, consumed by explicit click | Accepted | 1     |
| 012 | Email can never bypass a passkey                                | Accepted | 1     |
| 013 | Account-enumeration resistance                                  | Accepted | 1     |
| 014 | WebAuthn policy: UV required, discoverable preferred, no attestation | Accepted | 1  |
| 015 | Sign-counter check after signature verification                 | Accepted | 1     |
| 016 | Non-`Secure`, unprefixed cookies on `http://localhost` in dev   | Accepted | 1     |
| 017 | Audit events in their own transaction, append-only in the DB    | Accepted | 1     |
| 018 | No test-only bypasses in the API                                | Accepted | 1     |

---

## ADR-001: Monorepo with independent per-app toolchains

**Decision.** One repository (`apps/api`, `apps/web`, later `apps/demo-notes`), but each app
keeps its own lockfile and toolchain: `uv` + `pyproject.toml` for the API, `pnpm` +
`package.json` for each Next.js app. A root `Makefile` is the single entry point.

**Context.** Reviewers should be able to read the whole system in one place, and phases touch
several apps at once. But the API and the UIs share no code, and the demo app must behave like a
_third-party_ relying party that only talks to Keygate over OIDC.

**Alternatives.** Separate repos (harder to review, no atomic cross-app changes); a pnpm
workspace or Turborepo (shared node_modules couples the demo app to the Keygate UI, which defeats
its purpose).

**Consequences.** Docker builds use each app's directory as context, with small images and no
cross-app leakage. Some tooling config is duplicated per app.

## ADR-002: Single origin for UI and API via a reverse-proxy gateway

**Decision.** A Caddy gateway serves everything at `http://localhost`: `/api/*` goes to FastAPI
(prefix stripped; FastAPI's `root_path` is `/api`), everything else to Next.js.

**Context.** WebAuthn credentials are scoped to an RP ID and every ceremony checks the page's
origin. Session cookies with `SameSite=Lax` and the `__Host-` prefix are simplest and safest
when the API is same-origin. Two origins would need CORS with credentials, a wider attack surface
and a common source of misconfiguration.

**Alternatives.** Next.js `rewrites` as a proxy (baked in at build time for standalone output,
and it puts the UI server on the API's request path); CORS between `:3000` and `:8000`
(more config, more ways to get it wrong).

**Consequences.** One more container (Caddy, ~50 MB). The local setup mirrors a real deployment,
where a load balancer or ingress would play the gateway's role.

## ADR-003: Trust `X-Forwarded-For` only from the gateway

**Decision.** The compose network has a fixed subnet and the gateway a fixed IP
(`172.30.42.10`). Uvicorn's `FORWARDED_ALLOW_IPS` is set to exactly that address. Caddy
ignores client-supplied `X-Forwarded-For` and sets it from the real peer address.

**Context.** Client IP feeds rate limiting (Phase 4), the audit log and the session list. If any
caller could set `X-Forwarded-For`, an attacker could dodge per-IP rate limits and forge audit
trails.

**Alternatives.** `FORWARDED_ALLOW_IPS=*` (spoofable by anything that can reach the API);
ignoring proxy headers (every request appears to come from the gateway, so per-IP rate limiting
is useless).

**Consequences.** The subnet `172.30.42.0/24` must not collide with an existing Docker network
on the host. The API port is not published, so the gateway is the only way in.

## ADR-004: Per-request nonce CSP with `'strict-dynamic'`

**Decision.** Next.js middleware generates a fresh nonce for every request and sends
`script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`, `base-uri 'none'`,
`frame-ancestors 'none'`. Pages render dynamically so each response carries its own nonce. The
API sends `default-src 'none'` since it only returns JSON.

**Context.** An identity provider's UI is a top XSS target: script injection there means
account takeover (e.g. registering an attacker passkey). A nonce CSP is the strongest practical
defence, and an allow-list CSP is routinely bypassable.

**Alternatives.** Static allow-list CSP (bypassable via JSONP or gadget hosts); hash-based CSP
(impractical with Next's inline bootstrap scripts).

**Consequences / trade-offs.**

- No static prerendering. Acceptable: auth pages are per-user anyway.
- `style-src` allows `'unsafe-inline'` because Radix UI positions popovers with inline `style`
  attributes. Style injection can leak little and cannot run code. Revisit if Radix stops
  needing it.
- Dev mode adds `'unsafe-eval'` for React fast refresh. Playwright tests run against the
  production build and assert it is absent.

## ADR-005: Structured logs with redaction and no query strings

**Decision.** `structlog` emits JSON lines with a request ID bound to every line. A redaction
processor masks values whose key contains a sensitive segment (`token`, `secret`, `password`,
`cookie`, `session`, `verifier`, `challenge`, …). Access logs record method, path, status and
duration, never the query string. SQLAlchemy runs with `hide_parameters=True`.

**Context.** Auth systems handle bearer secrets constantly: OAuth codes and magic-link tokens
arrive in query strings, and session IDs arrive in cookies. Logs are retained longer and seen
by more people than the database, so a leaked token in logs can become an account takeover.

**Alternatives.** Rely on discipline alone (one mistake leaks); log full requests for debugging
(unacceptable for an IdP).

**Consequences.** Redaction is a safety net, not a licence: code still must not log secrets.
Segment matching avoids false positives such as `status_code`. Inbound `X-Request-ID` values
are only accepted if they match `^[A-Za-z0-9._-]{8,64}$`, which prevents log injection.

## ADR-006: Fail closed on weak credentials in production

**Decision.** With `KEYGATE_ENVIRONMENT=production`, settings validation refuses to start if
the Postgres or Redis password is empty, a known development value, or shorter than 16
characters. Production also disables `/docs`, `/redoc` and `/openapi.json` and enables HSTS.

**Context.** Copying `.env.example` to production is a common real-world incident. The first
version of this check only matched the hard-coded default and missed the `.env.example` value.
A test caught this.

**Consequences.** Slightly more friction for production deploys, by design.

## ADR-007: Separate liveness and readiness health checks

**Decision.** `GET /health` (liveness) has no dependencies. `GET /health/ready` checks Postgres
and Redis with a 2-second timeout and returns 503 if either is down. Responses contain only
`ok`/`unavailable` per dependency.

**Context.** If liveness depended on the database, a DB blip would make the orchestrator
restart every healthy API container. Health endpoints are unauthenticated, so they must not
reveal hostnames, versions or error text.

**Consequences.** Failure details go to the logs (`error_type` only), not to callers.

## ADR-008: Supply-chain hygiene from day one

**Decision.**

- Exact versions locked (`uv.lock`, `pnpm-lock.yaml`); Docker builds use `--frozen` and
  `--frozen-lockfile`.
- pnpm 11's default-deny for dependency lifecycle scripts is kept, with explicit decisions in
  `pnpm-workspace.yaml`.
- Fonts are self-hosted (the `geist` package), so there are no build-time or runtime calls to
  Google Fonts and nothing to add to the CSP.
- Base and service images are pinned to exact versions. Digest pinning and Dependabot follow in
  Phase 6.
- Containers run as a dedicated non-root user (uid 10001). Runtime images contain no compilers
  or package-manager caches.
- Gitleaks runs on every commit (staged changes) and every push (full history).

**Consequences.** Upgrades are deliberate and show up as reviewable lockfile diffs.

---

## ADR-009: Server-side sessions in Postgres with hashed tokens and levels

**Decision.** A session is a row in `sessions`. The cookie holds a 256-bit random token, and
only its SHA-256 is stored. Sessions have a **level**: `registration` (issued after email
verification, lives 15 minutes, can only enrol the first passkey) or `full`. The session is
rotated (old row revoked, new token issued) on every sign-in and on the registration-to-full
upgrade. There is an idle timeout (30 min) and an absolute timeout (12 h). `last_seen_at` is
written at most once a minute.

**Context.** The spec forbids JWTs in localStorage. Server-side state makes revocation instant,
which Phase 2's "revoke all other sessions" needs. Hashing the token means a database leak
(backup, SQL injection, replica) yields no usable cookies.

**Alternatives.** Redis-only sessions (fast, but listing and auditing sessions per user needs a
secondary index anyway, and Redis is configured as a cache that may evict); signed stateless
cookies (no server-side revocation).

**Consequences.** One indexed lookup per authenticated request. SHA-256 rather than a slow hash
is correct here: the input is 256 bits of randomness, so there's nothing to brute-force.

## ADR-010: Session-bound signed double-submit CSRF, default-deny

**Decision.** The CSRF cookie is `nonce.HMAC(secret, session-binding, nonce)`, readable by JS
and `SameSite=Strict`. Every non-GET request must echo it in `X-CSRF-Token`, and the MAC must
verify against the *current* session cookie (or `anon`). The check is a global FastAPI
dependency: new routes are protected unless explicitly exempted.

**Context.** `SameSite=Lax` blocks most cross-site POSTs but not all (same-site subdomains,
browser quirks, top-level GET-to-POST tricks). The naive double-submit pattern is weak if an
attacker can plant cookies; binding the MAC to the session closes that gap. Tokens are
re-issued on every login and logout.

**Alternatives.** Synchronizer token stored server-side (an extra lookup per request);
`Origin` header checks only (good defence in depth, but some privacy tools strip the header).

## ADR-011: Magic-link token in the URL fragment, consumed by explicit click

**Decision.** Links look like `/verify-email#token=...`. The page reads the fragment, removes
it from the address bar with `history.replaceState`, and only spends the token when the user
clicks **Confirm email** (a POST). Tokens are 32 random bytes, stored as SHA-256, single-use
(atomic `UPDATE ... WHERE used_at IS NULL`), valid for 15 minutes. Requesting a new link
invalidates older ones.

**Context.** Query strings end up in server logs, proxy logs, browser history sync and
`Referer` headers. Fragments are never sent to a server. Requiring a click stops email
security scanners and link previews (which GET every URL) from burning or using the token.

**Consequences.** One extra click for the user.

## ADR-012: Email can never bypass a passkey

**Decision.** Magic links are only issued for addresses whose account has **no** passkey, and
this is checked again when the token is consumed. The registration session they create can
only enrol the *first* passkey. Account recovery (Phase 2) uses recovery codes, not email.

**Context.** If email could sign you in, the account would only be as strong as the mailbox,
and the phishing resistance of passkeys would be lost.

## ADR-013: Account-enumeration resistance

**Decision.**

- `POST /auth/signup` always returns the same 202 body. New addresses get a link; existing
  accounts get a "you already have an account" notice. The email is sent as a background task
  so response timing doesn't differ.
- Email-first sign-in options for unknown addresses contain a **decoy** credential ID:
  `HMAC(secret, email)`, stable per address and the same length as a real one.

**Trade-offs.** A user with several passkeys gets several `allowCredentials` entries while a
decoy shows one, so a determined attacker can still distinguish *some* accounts. Usernameless
sign-in, the primary flow, reveals nothing.

## ADR-014: WebAuthn policy: UV required, discoverable preferred, no attestation

**Decision.** `userVerification: "required"` on every ceremony (enforced server-side too),
`residentKey: "preferred"`, `attestation: "none"`, ES256/EdDSA/RS256 accepted (library
defaults). User handles are 32 random bytes, never the email or primary key. `excludeCredentials`
prevents double registration. Challenges are 32 bytes, stored in Redis keyed by session
(registration) or by a random ceremony ID (sign-in), with a 5-minute TTL and `GETDEL`.

**Alternatives.** `residentKey: "required"` (would refuse older security keys); requesting
attestation (only useful with FIDO MDS verification, listed in the roadmap; without it,
attestation adds privacy cost and no assurance).

## ADR-015: Sign-counter check after signature verification

**Decision.** py_webauthn checks the sign counter *before* the signature and raises a generic
error. We pass `credential_current_sign_count=0` to skip that check, then compare counters
ourselves *after* the signature has verified. If the counter didn't increase (and isn't 0/0),
sign-in is refused and a `credential.sign_count_regression` audit event with severity **high**
is written. The stored counter is not overwritten.

**Context.** Only a correctly signed assertion should be able to raise a "cloned authenticator"
alarm; otherwise anyone could spam alarms with garbage. Synced passkeys (iCloud Keychain, Google
Password Manager) always report 0, which is allowed.

**Consequences.** The credential isn't disabled automatically, since a false positive would lock
the user out. An admin reviews the high-severity event (auditor view, Phase 4).

## ADR-016: Non-`Secure`, unprefixed cookies on `http://localhost` in dev

**Decision.** `KEYGATE_COOKIE_SECURE` defaults to `true` only in production. Secure cookies get
the `__Host-` prefix (`__Host-kg_session`, `__Host-kg_csrf`). In development on plain
`http://localhost` they're `kg_session` / `kg_csrf` without `Secure`. Production refuses to
start with non-Secure cookies or non-https origins.

**Context.** `__Host-` requires `Secure`, and not every browser stores `Secure` cookies over
`http://localhost`. Dev convenience is confined to dev by the fail-closed production check.

## ADR-017: Audit events in their own transaction, append-only in the DB

**Decision.** `AuditLog.record()` opens its own short transaction, so failures that roll back
the request (rejected sign-ins, invalid links) are still recorded. A `BEFORE UPDATE OR DELETE`
trigger on `audit_events` raises an error. Audit rows have no foreign keys, so history survives
user deletion. Details never include tokens, codes, signatures or credential material.

**Consequences.** In production the app's DB role should also lack `TRUNCATE` on the table,
since triggers don't fire on `TRUNCATE` (documented for Phase 6 hardening).

## ADR-018: No test-only bypasses in the API

**Decision.** There are no "test mode" switches that weaken security (no rate-limit bypass,
fixed challenges or fake verification). API tests use a software authenticator that produces
real signatures. Browser E2E tests use Chrome's CDP virtual authenticator. The E2E global
setup resets rate-limit counters *from outside* (`redis-cli` in the Redis container).

**Context.** Test hooks have a habit of shipping to production. See the many "debug
parameter" authentication bypasses in CVE history.
