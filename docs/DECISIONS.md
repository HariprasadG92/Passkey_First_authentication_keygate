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
| 019 | Step-up re-authentication ("sudo mode")                         | Accepted | 2     |
| 020 | TOTP as an encrypted, replay-protected, phishable fallback      | Accepted | 2     |
| 021 | Recovery codes: Argon2id, single-use, a recovery not a method   | Accepted | 2     |
| 022 | Last-sign-in-method protection under a row lock                 | Accepted | 2     |
| 023 | Security notification emails for every credential change        | Accepted | 2     |
| 024 | Email change: verify new address, notify old, same user only    | Accepted | 2     |
| 025 | Owner-scoped lookups: other users' objects are a 404            | Accepted | 2     |
| 026 | Authlib protocol primitives + httpx + joserfc for the OAuth client | Accepted | 3   |
| 027 | Server-side OAuth state with PKCE, nonce and a browser binding  | Accepted | 3     |
| 028 | Account linking: match by subject, never merge, confirm explicitly | Accepted | 3   |
| 029 | Social sign-up allowed; social counts as a sign-in method       | Accepted | 3     |
| 030 | Permission-based RBAC, evaluated live on every request          | Accepted | 4     |
| 031 | Admin guardrails: step-up, no self-change, never zero admins    | Accepted | 4     |
| 032 | Granting a role forces a fresh sign-in                          | Accepted | 4     |
| 033 | First admin only via an operator CLI                            | Accepted | 4     |
| 034 | Audit log API: read-only, keyset-paginated, denials audited     | Accepted | 4     |
| 035 | Rate-limit policy: one table, every limit tested                | Accepted | 4     |
| 036 | OIDC: Authorization Code + PKCE (S256) only, exact redirect URIs | Accepted | 5    |
| 037 | Codes in Redis, single-use, replay revokes issued tokens        | Accepted | 5     |
| 038 | JWT access tokens (RFC 9068), audience-restricted, 10 minutes   | Accepted | 5     |
| 039 | Rotating refresh tokens with family-wide reuse detection        | Accepted | 5     |
| 040 | ES256 signing keys, encrypted at rest, rotated via CLI          | Accepted | 5     |
| 041 | Consent per user and client; RP-initiated logout without open redirects | Accepted | 5 |
| 042 | Notes demo: confidential client using the BFF pattern           | Accepted | 5     |
| 043 | CSRF token is reused while valid (fixes a token-rotation race)  | Accepted | 5     |
| 044 | CI scanning policy: block on fixable HIGH/CRITICAL              | Accepted | 6     |
| 045 | Minimal runtime images, pinned by digest                        | Accepted | 6     |
| 046 | E2E in CI runs the production images                            | Accepted | 6     |
| 047 | Dependabot with a 7-day cooldown; Actions pinned to SHAs         | Accepted | 6     |

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

---

## ADR-019: Step-up re-authentication ("sudo mode")

**Decision.** Each session records `reauthenticated_at`, the last time the user proved a
sign-in factor. Adding or removing passkeys, setting up or removing TOTP, regenerating recovery
codes and changing email require it to be under **5 minutes** old; otherwise the API returns
`403 {"code": "step_up_required"}` and the UI shows a "Confirm it's you" dialog (passkey, or
TOTP if enabled) and retries the action. A successful step-up **rotates the session**.
Signing in counts as fresh authentication. A registration session from email verification does
not, because email isn't a sign-in factor.

**Context.** Without step-up, a stolen session cookie (malware, an unlocked laptop) becomes
permanent account takeover: add your own passkey, done. GitHub's "sudo mode" and Google's
re-prompt use the same pattern.

**Alternatives.** Re-prompt on every sensitive call (annoying when doing several changes in a
row); no step-up (as above).

## ADR-020: TOTP as an encrypted, replay-protected, phishable fallback

**Decision.**

- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) is a *fallback* sign-in method. The UI says it can
  be phished and steers users to passkeys.
- 160-bit secrets are encrypted with **AES-256-GCM**. The ciphertext carries a key ID for
  rotation, and the user ID is the associated data, so a ciphertext copied to another user's
  row won't decrypt.
- **±1 step** window. All steps are compared in constant time without early exit.
- **Replay protection** by a single conditional `UPDATE ... SET last_used_step = :s WHERE
  last_used_step < :s`. Any code at or before the last accepted step is rejected, even under
  concurrency.
- One per-account rate-limit budget (5 per 15 minutes) shared by sign-in, step-up and enrolment
  confirmation, so total guesses per account are bounded.

**Alternatives.** Hashing the secret (impossible: the server needs the plaintext to compute
codes); a KMS (the right production answer, and the key-ID format makes swapping one in easy).

**Consequences.** A phished TOTP code yields a full session, and with step-up via TOTP an
attacker could add a passkey. That's inherent to offering TOTP; the mitigations are notification
emails (ADR-023), audit events and the session list.

## ADR-021: Recovery codes: Argon2id, single-use, a recovery not a method

**Decision.** 10 codes of 10 characters from a 31-symbol alphabet without look-alikes (about
49.5 bits each), formatted `XXXXX-XXXXX`, shown once, served with `Cache-Control: no-store`.
They are stored as **Argon2id** hashes using the RFC 9106 low-memory profile (t=3, 64 MiB, p=4),
hashed in a worker thread. Each code works once, with rows locked while one is spent.
Regenerating deletes all previous codes. Unknown emails still pay for one dummy Argon2 check, to
keep timing similar. A recovery sign-in creates a fresh full session, so the user can add a
passkey immediately, and triggers a notification email with the number of codes left.

Recovery codes don't count as a "sign-in method" for last-method protection: they're a
one-shot way back in, not a way to keep using the account.

**Alternatives.** SHA-256 hashes (fine for 256-bit tokens, too weak for about 50-bit codes if
the database leaks); fewer, longer codes (worse to type).

## ADR-022: Last-sign-in-method protection under a row lock

**Decision.** Sign-in methods = passkeys + confirmed TOTP. Removing a passkey or TOTP is refused
(`409 last_sign_in_method`) if it's the last one. The check and delete run after
`SELECT ... FOR UPDATE` on the user row.

**Context.** Without the lock, two parallel `DELETE` requests for an account's two passkeys can
each see "2 methods" and both succeed, leaving zero (a classic time-of-check/time-of-use race).
There's a test that fires both deletes concurrently and expects exactly one 204 and one 409.

## ADR-023: Security notification emails for every credential change

**Decision.** Adding or removing a passkey, enabling or disabling TOTP, regenerating recovery
codes, using a recovery code, and requesting or completing an email change each send a
notification to the account's email address, with time, IP and user agent. They're sent as
background tasks.

**Context.** Defence in depth for the cases where an attacker *does* get in (phished TOTP
code, stolen recovery code): the owner finds out in minutes and can revoke sessions.

## ADR-024: Email change: verify new address, notify old, same user only

**Decision.** Changing email requires step-up. A link goes to the **new** address and a notice to
the **old** one. The link only works while signed in **as the same user** (the token row
stores `user_id`). The response is identical whether or not the new address is already taken
(no enumeration), and nothing is sent to an address that already has an account.

**Alternatives.** Changing email immediately (one stolen session plus a typo-squatted address
would mean losing the account); confirming from the old address too (stronger, more friction;
reasonable for high-value deployments).

## ADR-025: Owner-scoped lookups: other users' objects are a 404

**Decision.** Every account endpoint that takes an object ID (`/account/passkeys/{id}`,
`/account/sessions/{id}`) queries with `WHERE id = :id AND user_id = :current_user`. A foreign
ID is a 404, never a 403, so IDs can't be probed for existence. Tests cover rename, delete and
revoke against another user's objects.

---

## ADR-026: Authlib protocol primitives + httpx + joserfc for the OAuth client

**Decision.** Use Authlib for the OAuth *protocol* pieces (`prepare_grant_uri`,
`create_s256_code_challenge`), the app's existing `httpx` client for HTTP, and **joserfc**
(the JOSE library that succeeds `authlib.jose`, same author) to verify Google ID tokens.

**Context.** Authlib 1.8's `httpx_client` integration is deprecated in favour of a new `httpx2`
package. Pulling a second HTTP client into an identity provider's dependency tree to silence a
deprecation warning wasn't worth it. The protocol surface we need is small and every step is
explicit and tested.

**Consequences.** If Authlib's httpx2 integration matures, swapping in `AsyncOAuth2Client` is
a local change in `social/service.py`.

## ADR-027: Server-side OAuth state with PKCE, nonce and a browser binding

**Decision.** `POST /auth/social/{provider}/start` (CSRF-protected JSON) creates `state`,
a PKCE **S256** `code_verifier`, an OIDC `nonce` (Google) and a random **browser-binding**
value. They are stored in Redis under `sha256(state)`, single-use (`GETDEL`), with a 10-minute
TTL. The binding is set as an HttpOnly `SameSite=Lax` cookie, and only its hash is stored. The
callback requires the state, a matching provider, and the binding cookie from *the same browser*.
Google ID tokens are verified against Google's JWKS (RS256 only, refetched once on unknown
`kid`) with `iss`, `aud`, `exp`, `sub`, `nonce` and (multi-audience) `azp` checks.

**Context.** `state` alone stops forged callbacks but not **login CSRF via a stolen-but-valid
state**: an attacker starts a flow, stops at the callback, and gets a victim's browser to load
that URL, signing the victim into the attacker's account. The browser binding defeats this.
PKCE makes an intercepted authorization code worthless. The nonce ties the ID token to this
specific login.

**Consequences.** The callback is a state-changing `GET`. That's inherent to OAuth redirects,
and it's protected by the above rather than by the CSRF header.

## ADR-028: Account linking: match by subject, never merge, confirm explicitly

**Decision.**

- Identities are matched only by `(provider, subject)`: GitHub's numeric user ID, Google's
  `sub`. **Never by email**: emails change and get reassigned.
- If an unlinked identity's verified email belongs to an existing account, sign-in is
  **refused** with guidance ("sign in with your passkey, then link from settings").
- Linking needs a full, **stepped-up** session, then a provider round trip, then an
  **explicit confirmation** page showing the identity, then `POST /account/social/confirm`.
  The pending link is single-use, expires in 10 minutes, and only the user who started it can
  redeem it.
- Unverified provider emails (GitHub: no *primary verified* address; Google:
  `email_verified != true`) can't create or link accounts.

**Context.** Auto-linking by email is a well-known takeover path: register an account at a
provider that doesn't verify emails using the victim's address, then "sign in with X" and land
in the victim's account.

## ADR-029: Social sign-up allowed; social counts as a sign-in method

**Decision.** A new, verified social identity may create an account (no passkey yet). The UI
immediately prompts the user to add one, and a fresh social sign-in satisfies step-up so they
can. Linked social accounts count toward last-method protection. Social re-authentication is
also a step-up option (`intent=stepup`), and it must return an identity already linked to the
current user.

**Trade-offs.** A social-only account's security is the provider account's security. That's
acceptable as an on-ramp, and the passkey nudge is prominent.

---

## ADR-030: Permission-based RBAC, evaluated live on every request

**Decision.** Tables `roles`, `permissions`, `role_permissions` and `user_roles`, seeded by
migration: `user` (no extra permissions), `auditor` (`audit:read`, `users:read`) and `admin`
(all). Routes depend on **permissions** via `require_permission("users:read")`, never on role
names. Permissions are resolved from the database on **every** request: nothing is cached in
the session.

**Context.** Checking role names in code couples every endpoint to today's role design.
Permissions let roles be reshaped without touching endpoints. Live evaluation means revoking a
role takes effect on the next request, with no stale "admin" claim living on in a session or
token.

**Alternatives.** Permissions embedded in a session or JWT (fast, but revocation waits for
expiry); ABAC/policy engine (overkill for three roles; a natural evolution path).

**Consequences.** One extra indexed query per admin request. The API is the only enforcement
point: `GET /auth/session` returns `permissions` purely so the UI can hide links.

## ADR-031: Admin guardrails: step-up, no self-change, never zero admins

**Decision.**

- Every admin mutation needs the permission *and* step-up re-authentication. The permission is
  checked first, so non-admins get a plain 403.
- Admins can't change their own roles or suspend themselves.
- The last admin can't be demoted. Role changes take a lock on the `admin` role row, so two
  admins demoting each other concurrently can't leave zero (there's a test for exactly this
  race).
- Admin actions are rate-limited per admin (60/min) and audited with actor, target and a
  required reason for suspensions.
- Suspension revokes every session of the user immediately. Suspended users are refused by
  every sign-in path.

## ADR-032: Granting a role forces a fresh sign-in

**Decision.** When roles are **granted**, all of the target's sessions are revoked: elevated
access always starts from a new sign-in with a new session ID. When roles are **revoked**, no
session change is needed, since live evaluation (ADR-030) removes the access immediately.

**Context.** This is the spec's "rotate the session ID on privilege change" applied to
another user. A session that existed before the grant (possibly fixed, stolen or left open on
a shared machine) must not silently become an admin session.

## ADR-033: First admin only via an operator CLI

**Decision.** `make admin email=...` runs `python -m keygate.cli grant-role` inside the API
container. There is no web path to become an administrator when none exists (no "first user
is admin", no setup wizard). CLI grants are audited with `via: cli` and severity high.

**Context.** "First registered user becomes admin" is a classic takeover window on fresh
deployments.

## ADR-034: Audit log API: read-only, keyset-paginated, denials audited

**Decision.** `GET /admin/audit` (`audit:read`) filters by event type, severity, result, actor or
target user, and time range. It returns newest first with **keyset pagination** on
`(occurred_at, id)`, which stays stable while new events arrive (offset pagination would skip
or duplicate rows). There are no write endpoints (405), and the table itself is append-only
(ADR-017). Every authorization denial writes an `authz.denied` event, so probing for admin
endpoints is visible.

## ADR-035: Rate-limit policy: one table, every limit tested

**Decision.** All limits live in one table (`security/rate_limit.py`), keyed by IP (from the
trusted proxy, ADR-003) and/or by account (normalised email before sign-in, user or session
ID after). TOTP has one per-account budget shared by sign-in, step-up and enrolment. A test
sweeps every endpoint past its limit, and a guard test fails if a limit is added without a test
that exercises it.

| Limit                          | Key      | Allowance        |
| ------------------------------ | -------- | ---------------- |
| Sign-up                        | IP       | 10 / hour        |
| Sign-up                        | email    | 3 / 15 min       |
| Email-link verification        | IP       | 20 / 15 min      |
| Passkey sign-in options        | IP       | 30 / 5 min       |
| Passkey sign-in verify         | IP       | 20 / 5 min       |
| Passkey registration           | session  | 10 / 5 min       |
| TOTP (all uses)                | account  | 5 / 15 min       |
| TOTP sign-in                   | IP       | 20 / 15 min      |
| Recovery-code sign-in          | IP       | 10 / 15 min      |
| Recovery-code sign-in          | account  | 5 / hour         |
| Step-up                        | session  | 10 / 5 min       |
| Email change                   | account  | 3 / hour         |
| Social sign-in start           | IP       | 30 / 5 min       |
| Admin actions                  | admin    | 60 / min         |

**Trade-offs.** Fixed windows allow a burst of up to 2× the limit at a window boundary.
Acceptable here, since sliding windows cost more Redis work for little gain at these numbers.
Per-account limits can be used to lock a victim out for a window (a deliberate,
time-bounded trade-off). Passkey sign-in isn't limited per account: an assertion can't be
brute-forced.

---

## ADR-036: OIDC: Authorization Code + PKCE (S256) only, exact redirect URIs

**Decision.** Keygate's issuer is the site origin (`http://localhost` in dev). Discovery and
`/oauth2/*` are served at the root; the gateway routes them to the API. Only
`response_type=code` and `response_mode=query`. **PKCE is mandatory for every client,
confidential ones included**, and only `S256` (no `plain`). No implicit or hybrid flows, no
request objects. `redirect_uri` is compared by **exact string match** with no wildcards, prefix
or case-folding. An unknown client or unregistered redirect URI shows Keygate's own error page and
**never redirects**. Responses include `iss` (RFC 9207) against mix-up attacks. Repeated
parameters are rejected. This follows the OAuth 2.0 Security BCP (RFC 9700) and OAuth 2.1.

**Context.** Every relaxation here is a known attack path: implicit flow (tokens in URLs and
history), `plain` PKCE (verifier equals challenge), and lenient redirect matching (code theft
via attacker-controlled paths).

## ADR-037: Codes in Redis, single-use, replay revokes issued tokens

**Decision.** Authorization codes are 256 random bits, stored in Redis under their SHA-256 with
a **60-second TTL**, and redeemed with `GETDEL`. A code is bound to the client, the exact redirect
URI, the PKCE challenge, the nonce and the user. After redemption a "spent" marker records the
refresh-token family it produced. Presenting the code again revokes that family and logs a
high-severity `oauth.code_reuse` event (RFC 6749 §4.1.2).

## ADR-038: JWT access tokens (RFC 9068), audience-restricted, 10 minutes

**Decision.** Access tokens are ES256 JWTs with `typ: at+jwt`, `iss`, `sub`, `aud`, `scope`,
`client_id`, `jti` and a 10-minute `exp`. `aud` always contains the issuer (for userinfo), plus
`notes-api` **only** when a `notes:*` scope was granted, so a token for one API can't be
replayed at another. The `typ` header stops an ID token being used as an access token.
Resource servers validate locally with JWKS.

**Trade-offs.** Self-contained tokens can't be revoked instantly at third-party resource
servers. `/oauth2/revoke` adds the `jti` to a deny-list that Keygate's own userinfo honours,
and the 10-minute lifetime bounds the exposure elsewhere. Opaque tokens plus introspection
would revoke instantly but put Keygate on every API call's critical path.

## ADR-039: Rotating refresh tokens with family-wide reuse detection

**Decision.** Refresh tokens are opaque, stored as SHA-256, valid for 7 days (sliding within a
30-day family lifetime). Each use **rotates** the token: the old one is marked used and a
successor is issued in the same family. Presenting a used token means it was copied, so the
**entire family is revoked** (attacker and legitimate client alike) and a high-severity event is
written. Scopes can be narrowed on refresh, never widened. Suspended users can't refresh, and
their family is revoked.

## ADR-040: ES256 signing keys, encrypted at rest, rotated via CLI

**Decision.** Signing keys are ES256 (P-256). Private JWKs are encrypted with AES-256-GCM and
bound to their `kid` as associated data. Lifecycle: **active** (exactly one signs new tokens),
then **retired** (still published in JWKS so its tokens keep verifying), then **removed** (after twice
the longest token lifetime). `make rotate-keys` rotates. Every token header carries `kid`. The
first key is generated on first use.

**Consequences.** Clients that cache JWKS must refetch on an unknown `kid`. Mainstream
libraries (openid-client, jose) do.

## ADR-041: Consent per user and client; RP-initiated logout without open redirects

**Decision.** Consent is stored per (user, client) and re-asked whenever a client requests a
scope beyond what was approved, or sends `prompt=consent`. The consent screen shows the client
name, the host it will return to, and each scope in plain language. `prompt=none` returns
`login_required`/`consent_required` instead of showing UI. `prompt=login` and `max_age` force a
fresh sign-in (the return URL drops `prompt=login` so it can't loop).

RP-initiated logout ends the Keygate session (and that client's refresh tokens) only when the
`id_token_hint` is a valid Keygate ID token **for the signed-in user**. It redirects only to a
`post_logout_redirect_uri` registered by the client the hint was issued to. Anything else lands
on Keygate's own "Sign out?" page.

The sign-in page's `?next=` is accepted only if it is a relative `/oauth2/authorize?...` path,
so it can't be used for open redirects (an E2E test tries `//evil.example`).

## ADR-042: Notes demo: confidential client using the BFF pattern

**Decision.** `apps/demo-notes` is a confidential client using **openid-client**. Tokens live
only on its server, in an A256GCM-encrypted, HttpOnly, SameSite=Lax cookie (the
*backend-for-frontend* pattern). Browser JavaScript never sees a token. Its `/api/notes`
routes act as an independent **resource server**: they validate the bearer token with JWKS
(`typ`, `iss`, `aud=notes-api`, `exp`, scope `notes:read`/`notes:write`). The BFF forwards to
them with the access token, refreshing (and rotating) as needed. Notes runs on
`http://127.0.0.1:3001`: a different cookie *host* from `localhost`, since cookies ignore ports
and Keygate's session cookie must never reach an RP. Server-to-server calls go to Keygate's
internal URL while all validation still uses the public issuer (a `customFetch` rewrite).

**Alternatives.** A SPA public client with tokens in the browser (simpler, but tokens become
XSS loot); `notes.localhost` (Safari doesn't resolve `*.localhost`).

## ADR-043: CSRF token is reused while valid (fixes a token-rotation race)

**Decision.** `GET /auth/session` returns the browser's existing CSRF token if it's still valid
for the current session, and only issues a new one when it's missing or bound to a different
session. Tokens still change whenever the session changes (sign-in, step-up, sign-out).

**Context.** Found by the Phase 5 E2E suite. Minting a new token on every call let two
concurrent requests (the header nav and the consent page) race: one read the cookie, the other
replaced it, and the first then sent a header that no longer matched the cookie, giving a 403.

---

## ADR-044: CI scanning policy: block on fixable HIGH/CRITICAL

**Decision.** CI fails on any finding from Semgrep (Python, TypeScript, React, OWASP Top 10,
secrets, Dockerfile rules), Gitleaks (full history), pip-audit and `pnpm audit --prod`
(high and above), and on **fixable** HIGH/CRITICAL findings from Trivy (filesystem,
misconfiguration and every production image). Unfixed OS advisories are reported but don't
block: there is nothing to upgrade to, and blocking would only train people to ignore the gate.

**Context.** Phase 6 started by running every scanner locally. Fixes: overriding Next.js 15's
vulnerable postcss, moving the shadcn CLI out of production dependencies, removing npm from
Node runtime images, moving the API base to Debian trixie (57 → 44 unfixed advisories), and
adding a Dependabot cooldown flagged by Semgrep.

## ADR-045: Minimal runtime images, pinned by digest

**Decision.** Runtime images contain only what runs: the Python venv or Next.js standalone
output, run as uid 10001, with no compilers, no package-manager caches, and (for Node) no
npm, npx, corepack or yarn. Base and service images are referenced as `tag@sha256:digest`.
CI smoke-boots each image and asserts it serves while running as non-root.

**Context.** Smoke-booting the runtime image found a real bug: `httpx` was a dev-only
dependency although the app imports it, so the production image crashed while the dev
container (which installs dev dependencies) worked.

## ADR-046: E2E in CI runs the production images

**Decision.** CI's E2E job uses `docker-compose.ci.yml` to switch the API, UI and Notes to
their `runtime` targets with no source mounts. The tests therefore exercise exactly what would
be deployed. Local `make dev` keeps the hot-reload dev targets.

**Context.** The dev UI container (uid 1000) couldn't write to a CI checkout owned by uid 1001.
Running production images fixes that, removes `next dev`'s compile-on-demand delays, and is a
stronger test anyway.

## ADR-047: Dependabot with a 7-day cooldown; Actions pinned to SHAs

**Decision.** Dependabot proposes weekly, grouped updates for Python, both Node apps, Docker
images, Compose and GitHub Actions, but waits **7 days** after a release (security updates
aren't delayed). Third-party Actions are pinned to full commit SHAs, and the workflow token
is read-only.

**Context.** Malicious package releases and hijacked Action tags are usually detected and
pulled within days; a cooldown and immutable references keep CI out of that window.
