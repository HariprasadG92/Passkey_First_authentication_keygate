# Keygate: Passkey-First Authentication Platform

> **How to use this file:** Put it in an empty folder as `SPEC.md`, open Claude Code in that folder and say:
> *"Read SPEC.md fully. Then start Phase 0 and stop when Phase 0's checkpoint is done and the PR is open."*
> After each phase: review the pull request on GitHub, merge it yourself, then tell Claude Code *"PR merged, start Phase N."*

---

## 1. Role and working rules (read first)

You are a senior security engineer and full-stack developer helping me build a portfolio-grade, production-quality authentication platform. I am a cybersecurity master's student. I must be able to **explain every design decision in a job interview**, so how you work matters as much as what you build.

Follow these rules for the whole project:

1. **Work in phases.** Complete one phase at a time (Section 6). At the end of each phase, stop and give me:
   - a short summary of what was built,
   - the key security decisions and *why* (2–5 bullets),
   - how to run and test it,
   - 3 interview-style questions about this phase I should be able to answer.
2. **Small, meaningful commits.** Use Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `refactor:`, `ci:`). One logical change per commit. Never one giant commit.
3. **Plan before coding.** Before each phase, show a brief plan (files, endpoints, DB changes). Wait for my "go" unless I've said to proceed.
4. **Security over convenience.** If a shortcut weakens security, don't take it. Mention it as a trade-off instead.
5. **No secrets in code.** Everything sensitive goes in `.env` (git-ignored), with a documented `.env.example`.
6. **Tests are part of done.** A feature isn't complete without tests.
7. **Explain unfamiliar concepts briefly** in your summaries (e.g. what a WebAuthn challenge is, what PKCE protects against).
8. **Don't invent library APIs.** If unsure about a library's current API, check its documentation or installed source before using it.
9. Keep a running `docs/DECISIONS.md` (lightweight ADRs: decision, context, alternatives, consequences).
10. **Git and GitHub workflow (follow for every phase):**
    - GitHub is already authenticated via the GitHub CLI (`gh`) as `HariprasadG92`. Before the first push, run `gh auth status` and confirm `HariprasadG92` is the active account. If it isn't, stop and tell me.
    - **Repo setup (Phase 0 only):** if this folder isn't a git repo, run `git init -b main`. If no `origin` remote exists, create the GitHub repo with `gh repo create keygate --public --source=. --remote=origin`. Make an initial commit on `main` containing only `SPEC.md`, `.gitignore`, `LICENSE` and a README stub, and push it with `git push -u origin main`.
    - **Start of each phase:** `git checkout main && git pull origin main`, then create a branch `phase-N-<short-name>` (e.g. `phase-0-foundation`, `phase-1-passkeys`, `phase-2-mfa-recovery`, `phase-3-social-login`, `phase-4-rbac-audit`, `phase-5-oidc-provider`, `phase-6-hardening-ci-docs`).
    - **During the phase:** commit in small, logical steps on that branch. Push the branch to GitHub regularly (`git push -u origin <branch>`) so work is never only local.
    - **End of each phase:** once the checkpoint passes and tests/lint are green, push the final commits and open a pull request to `main` with `gh pr create --base main --title "Phase N: <name>" --body-file <file>`. The PR description must include: what was built, key security decisions, how to run and test it, and any known limitations.
    - **Never merge the PR yourself.** I review and merge it. Then wait for me to say "PR merged, start Phase N".
    - Never force-push to `main`, never rewrite pushed history, and never commit `.env` files, secrets, tokens or private keys. Run gitleaks before every push.
    - After opening the PR, give me the PR URL along with your phase summary.

---

## 2. Project overview

**Keygate** is a self-hostable identity service with:

- **Passwordless sign-in with passkeys (WebAuthn)** as the primary method. No passwords at all.
- **Email verification** via one-time magic links.
- **MFA and account recovery:** TOTP as a fallback factor, single-use recovery codes, multiple passkeys per account.
- **Social login** with GitHub (OAuth2) and Google (OIDC), with account linking.
- **RBAC** with roles and permissions, an admin dashboard and an audit log.
- **Keygate as an OpenID Connect Provider:** a separate demo app ("Notes") signs users in through Keygate using Authorization Code + PKCE, the same way apps use Okta or Entra ID.

The goal is a repo a security engineer would read and respect: clear architecture, real threat modeling, tests, CI with security scanning, and excellent documentation.

---

## 3. Tech stack (use these unless you raise a strong reason not to)

**Backend (auth service):**
- Python 3.12, **FastAPI**, Pydantic v2
- **SQLAlchemy 2.0** (async) + **Alembic** migrations
- **PostgreSQL 16**
- **Redis** for WebAuthn challenges, rate limiting and short-lived state
- `webauthn` (py_webauthn by Duo Labs) for passkey registration/authentication
- `Authlib` for the OAuth2/OIDC client (social login) and the OIDC provider
- `pyotp` for TOTP, `argon2-cffi` for hashing recovery codes
- `joserfc` or Authlib's JOSE for signing ID tokens (RS256 or ES256, with key rotation support)
- `structlog` for structured JSON logging
- Tooling: `uv` for dependency management, `ruff` (lint + format), `mypy` (strict), `pytest` + `pytest-asyncio` + `httpx`

**Frontend (Keygate UI):**
- **Next.js 15** (App Router), **TypeScript** (strict), **Tailwind CSS**, **shadcn/ui**
- `@simplewebauthn/browser` for WebAuthn in the browser
- Zod for client-side validation
- Tooling: ESLint, Prettier, **Playwright** for end-to-end tests

**Demo relying-party app ("Notes"):**
- Small Next.js app that logs in only through Keygate's OIDC endpoints, using Authorization Code + PKCE.

**Infrastructure:**
- **Docker Compose** for local dev: api, web, demo-app, postgres, redis, **Mailpit** (local email catcher)
- Multi-stage Dockerfiles, non-root users, minimal base images
- **GitHub Actions** CI

---

## 4. Repository structure

```
keygate/
├── apps/
│   ├── api/                 # FastAPI auth service
│   │   ├── src/keygate/
│   │   │   ├── main.py
│   │   │   ├── config.py
│   │   │   ├── db/          # models, session, migrations
│   │   │   ├── auth/        # passkeys, sessions, magic links
│   │   │   ├── mfa/         # totp, recovery codes
│   │   │   ├── social/      # github, google
│   │   │   ├── rbac/        # roles, permissions, dependencies
│   │   │   ├── oidc/        # OIDC provider
│   │   │   ├── audit/       # audit log
│   │   │   ├── security/    # rate limiting, csrf, headers
│   │   │   └── api/         # routers
│   │   ├── tests/
│   │   └── Dockerfile
│   ├── web/                 # Next.js Keygate UI
│   └── demo-notes/          # Next.js demo relying party
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── DECISIONS.md
│   ├── API.md
│   └── images/              # diagrams, screenshots, demo GIF
├── .github/workflows/
├── docker-compose.yml
├── .env.example
├── Makefile                 # make dev, make test, make lint, make migrate
├── SECURITY.md
├── LICENSE                  # MIT
└── README.md
```

---

## 5. Security requirements (non-negotiable)

### WebAuthn / passkeys
- Generate a cryptographically random **challenge** per ceremony. Store it server-side in Redis, bound to the user/session, **single-use, expiring after 5 minutes**.
- Strictly verify **RP ID** and **expected origin** (configurable via env).
- Require **user verification** (`userVerification: "required"`) and prefer **resident keys / discoverable credentials** so usernameless login works.
- Store per credential: credential ID, public key, sign count, transports, AAGUID, backup eligibility/state, friendly name, created_at, last_used_at.
- Check the **sign counter**. If it goes backwards (and isn't 0), flag a possible cloned authenticator and write a high-severity audit event.
- Use `excludeCredentials` during registration so the same authenticator can't be registered twice.
- Users can list, rename and delete passkeys, but **can never delete their last remaining sign-in method**.

### Sessions
- Server-side sessions (opaque random ID stored in Redis/Postgres), **not** JWTs in localStorage.
- Session cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefix in production.
- **Rotate the session ID** on login and on privilege change.
- Idle timeout (30 min) and absolute timeout (12 h), configurable.
- Users can view active sessions (device, IP, last active) and revoke any or all.
- **CSRF protection** on all state-changing requests (double-submit token or synchronizer token).

### Magic links and email
- Tokens: 32+ random bytes, **stored hashed**, single-use, 15-minute expiry.
- Email enumeration resistance: same response whether or not the email exists.

### MFA and recovery
- TOTP secrets encrypted at rest (key from env), with a ±1 step window and replay protection (reject a code already used in the same window).
- 10 recovery codes, shown **once**, stored as **Argon2id hashes**, each single-use. Regenerating invalidates old ones.
- Step-up re-authentication required for sensitive actions (adding/removing credentials, changing email, regenerating recovery codes).

### Social login
- Use `state` and **PKCE** for every OAuth flow, and `nonce` for OIDC (Google).
- Only link a social account to an existing account if the provider's email is **verified**, and the user must confirm the link while signed in. Never silently merge accounts.

### OIDC provider
- Support Authorization Code flow **with PKCE required (S256 only)**. No implicit flow.
- Endpoints: `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/jwks`, `/oauth2/revoke`, `/oauth2/logout` (RP-initiated logout).
- Exact-match redirect URI validation. No wildcards.
- Authorization codes: single-use, 60-second lifetime, bound to client + redirect URI + PKCE verifier.
- ID tokens signed with an asymmetric key; publish JWKS; support key rotation with a `kid`.
- Short-lived access tokens (10 min); refresh tokens with **rotation and reuse detection** (reuse revokes the whole token family).
- Consent screen showing requested scopes (`openid profile email`, plus a custom `notes:read` / `notes:write`).

### General hardening
- **Rate limiting** (Redis-backed) on login, registration, magic links, TOTP and token endpoints, by IP and by account.
- Security headers: strict CSP, HSTS (prod), `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`.
- Input validation on every endpoint with Pydantic. Consistent error format that never leaks internals.
- **Audit log** (append-only table) for: sign-in success/failure, credential added/removed, MFA changes, role changes, session revocation, token reuse, suspicious sign counter. Include actor, target, IP, user agent, timestamp, result.
- Logs must never contain secrets, tokens, codes or full credential data.
- Containers run as non-root; dependencies pinned.

---

## 6. Phases

### Phase 0: Foundation
- Monorepo structure, Docker Compose (api, web, postgres, redis, mailpit), Makefile.
- FastAPI app with `/health`, config via Pydantic Settings, structured logging, Alembic set up.
- Next.js app with Tailwind + shadcn/ui and a basic layout.
- Pre-commit hooks (ruff, mypy, eslint, prettier, gitleaks).
- Minimal README stub.

**Checkpoint:** `make dev` brings everything up; `make test` and `make lint` pass on both apps.

### Phase 1: Accounts, passkeys and sessions
- User model (UUID id, email, email_verified, display_name, status, timestamps).
- Sign-up: enter email → magic link (via Mailpit) → verify → register first passkey.
- Passkey sign-in: both **usernameless** (discoverable credentials) and email-first.
- Server-side sessions with all cookie/rotation/timeout rules from Section 5. CSRF protection.
- UI pages: sign up, sign in, verify email, account home.
- Tests: full registration and authentication ceremonies (mock authenticator responses), challenge expiry and reuse rejection, origin mismatch rejection, session rotation.

**Checkpoint:** I can create an account and sign in with a real passkey (Touch ID / Windows Hello / phone) at `http://localhost`.

### Phase 2: Credential management, MFA and recovery
- Security settings page: list/rename/delete passkeys, add another passkey, last-method protection.
- TOTP enrollment (QR code) as fallback factor; replay protection.
- Recovery codes (generate, view once, regenerate, use to regain access).
- Step-up re-authentication for sensitive actions.
- Active sessions page with revoke one / revoke all others.
- Tests for each, including the abuse cases (reused TOTP code, reused recovery code, deleting last credential).

### Phase 3: Social login
- GitHub (OAuth2) and Google (OIDC) sign-in.
- Account linking/unlinking from settings, following the verified-email + explicit-confirmation rules.
- Document in README how to create the GitHub/Google OAuth apps for local dev.
- Tests with mocked provider responses, including state/nonce mismatch.

### Phase 4: RBAC, admin and audit log
- Models: roles, permissions, role_permissions, user_roles. Seed roles: `admin`, `user`, `auditor`.
- FastAPI dependency like `require_permission("users:read")`.
- Admin dashboard: search users, view details, suspend/unsuspend, assign roles, revoke sessions.
- Auditor view: filterable audit log (read-only).
- Rate limiting on all sensitive endpoints, with tests that hit the limits.
- Tests proving each role can and can't do the right things (authorization matrix).

### Phase 5: Keygate as an OIDC Provider + demo app
- Implement the OIDC provider per Section 5, with client registration (admin UI) storing client_id, hashed client secret (for confidential clients), redirect URIs, allowed scopes.
- Consent screen.
- Build `apps/demo-notes`: a tiny notes app that signs in via Keygate (Authorization Code + PKCE), shows the user's profile from the ID token, and calls a notes API that validates Keygate access tokens and enforces `notes:read` / `notes:write` scopes.
- RP-initiated logout.
- Tests: full code flow, PKCE failures, redirect URI mismatch, code reuse, refresh token rotation and reuse detection, expired tokens, JWKS key rotation.

**Checkpoint:** I can open the Notes app, click "Sign in with Keygate", use my passkey, consent, and land back signed in.

### Phase 6: Hardening, CI and documentation
- **GitHub Actions** workflow on every push/PR:
  - lint + type check (ruff, mypy, eslint, tsc)
  - unit/integration tests (pytest with Postgres + Redis service containers), coverage report (aim ≥ 80% on the api)
  - Playwright E2E tests using a **virtual WebAuthn authenticator** (Chrome DevTools Protocol)
  - security scans: **Semgrep**, **Gitleaks**, **Trivy** (images + deps), `pip-audit`, `npm audit`
  - Docker image builds
- Dependabot config.
- Security headers verified by a test.
- `docs/THREAT_MODEL.md` using **STRIDE**: assets, trust boundaries, data flow diagram, threats per component, and the mitigation for each (link to the code).
- `docs/ARCHITECTURE.md` with **Mermaid** diagrams: system overview, passkey registration sequence, passkey sign-in sequence, OIDC Authorization Code + PKCE sequence.
- `SECURITY.md` (how to report vulnerabilities, supported versions).

---

## 7. README requirements

The README is the most important file in the repo. It must include:

1. Project name, one-line description, and badges (CI status, coverage, license).
2. A **demo GIF** (I'll record it; leave a placeholder and tell me exactly what to record).
3. **Features** list.
4. **Architecture** diagram (Mermaid) and a short explanation.
5. **Security design** section: the key decisions and threats mitigated, linking to THREAT_MODEL.md.
6. **Quick start** that works in under 5 minutes with Docker Compose.
7. How to set up GitHub/Google OAuth apps for local dev.
8. How to run tests and what CI checks.
9. **What I learned** section (draft bullets for me to rewrite in my own words).
10. Roadmap (e.g. WebAuthn attestation verification with FIDO MDS, SCIM provisioning, SAML, device-bound session credentials, admin MFA enforcement policies).

---

## 8. Definition of done (whole project)

- [ ] `docker compose up` gives a working system with no manual steps beyond copying `.env.example`.
- [ ] Real passkey sign-in works in Chrome and Safari.
- [ ] The Notes demo app signs in through Keygate via OIDC.
- [ ] All tests pass in CI; security scans are green or have documented, justified exceptions.
- [ ] No secrets in git history (verified with gitleaks).
- [ ] README, ARCHITECTURE, THREAT_MODEL, DECISIONS and SECURITY docs complete.
- [ ] Commit history shows clear, incremental progress.

---

## 9. Final deliverable from you after Phase 6

Give me an **interview prep sheet** (`docs/INTERVIEW_PREP.md`, which I may keep private) with:
- a 60-second project pitch,
- the 15 hardest questions an interviewer could ask about this project, with concise model answers,
- the 3 trade-offs I'd make differently at production scale and why.
