# Keygate

> Passkey-first, self-hostable identity platform: WebAuthn sign-in, MFA and recovery, social login, RBAC, and an OpenID Connect provider.

🚧 **Work in progress**: built in phases. See [`SPEC.md`](SPEC.md) for the full specification and
[`docs/DECISIONS.md`](docs/DECISIONS.md) for the design decisions so far.

| Phase | Scope                                       | Status         |
| ----- | ------------------------------------------- | -------------- |
| 0     | Foundation: stack, tooling, git hooks       | ✅ Done        |
| 1     | Accounts, passkeys, sessions                | ✅ Done        |
| 2     | Credential management, MFA, recovery        | ✅ Done        |
| 3     | Social login (GitHub, Google)               | ✅ Done        |
| 4     | RBAC, admin dashboard, audit log            | ✅ Done        |
| 5     | Keygate as an OIDC provider + demo app      | ✅ Done        |
| 6     | Hardening, CI, documentation                | ⏳ Planned     |

## Quick start

Requirements: Docker with Compose v2, and GNU Make.

```bash
make dev        # creates .env from .env.example on first run, then builds and starts everything
```

| URL                          | What                                |
| ---------------------------- | ----------------------------------- |
| http://localhost             | Keygate UI (Next.js)                |
| http://localhost/api/health  | API liveness                        |
| http://localhost/api/docs    | API docs (development only)         |
| http://localhost:8025        | Mailpit: emails sent by Keygate     |
| http://127.0.0.1:3001        | **Notes**: demo app that signs in with Keygate |
| http://localhost/.well-known/openid-configuration | OIDC discovery |

Port 80 already taken? Set `GATEWAY_PORT` in `.env` **and** `KEYGATE_PUBLIC_URL` to the
same origin (e.g. `http://localhost:8080`): WebAuthn checks the exact origin.

### Try it

1. Open http://localhost/signup and enter any email address.
2. Open Mailpit at http://localhost:8025 and click the confirmation link.
3. Click **Confirm email**, then **Create passkey** (Touch ID, Windows Hello, your phone, or a
   security key).
4. Sign out, then **Sign in with a passkey**: no username needed.
5. On the account page: add more passkeys, set up an authenticator app, generate recovery
   codes, review and revoke sessions. Sensitive changes ask you to re-confirm with your passkey.

## Keygate as an OpenID Connect provider

Apps sign users in through Keygate the way they would with Okta or Entra ID:
**Authorization Code + PKCE** (S256, required for every client), consent, ES256-signed ID
tokens, short-lived JWT access tokens, rotating refresh tokens with reuse detection, and
RP-initiated logout.

| Endpoint | Path |
| -------- | ---- |
| Discovery | `/.well-known/openid-configuration` |
| Authorize | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| JWKS | `/oauth2/jwks` |
| Revocation | `/oauth2/revoke` |
| End session | `/oauth2/logout` |

Scopes: `openid`, `profile`, `email`, `notes:read`, `notes:write`.

**Try the demo**: open <http://127.0.0.1:3001>, click **Sign in with Keygate**, use your
passkey, approve the consent screen, and you're back in Notes, signed in. Notes keeps tokens
server-side only and calls its own API with the access token (backend-for-frontend pattern).
**Sign out** ends both sessions.

Register your own apps under **Apps** in the header (admins), or rotate the signing key with
`make rotate-keys`.

## Roles and administration

| Role      | Can                                                                  |
| --------- | -------------------------------------------------------------------- |
| `user`    | Manage their own account (every account has this)                    |
| `auditor` | Read the audit log and the user directory                            |
| `admin`   | Everything: search users, suspend/unsuspend, assign roles, revoke sessions, read the audit log |

Make yourself the first admin (there's deliberately no web path to do this):

```bash
make admin email=you@example.com      # or: make auditor email=...
```

Then **Users** and **Audit log** appear in the header. Admin actions ask you to re-confirm
with your passkey and are recorded in the audit log.

## Social login setup (optional)

Keygate runs fine without social login; the buttons only appear once a provider is configured.
Put the values in `.env`, then run `docker compose up -d api` to apply them.

### GitHub

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**
   (<https://github.com/settings/applications/new>).
2. Fill in:
   - **Application name**: `Keygate (local)`
   - **Homepage URL**: `http://localhost`
   - **Authorization callback URL**: `http://localhost/api/auth/social/github/callback`
3. Click **Register application**, then **Generate a new client secret**.
4. Add to `.env`:
   ```bash
   KEYGATE_GITHUB_CLIENT_ID=<Client ID>
   KEYGATE_GITHUB_CLIENT_SECRET=<Client secret>
   ```

Keygate asks for `read:user user:email` and only trusts your **primary, verified** GitHub email.

### Google

1. Open the Google Cloud console (<https://console.cloud.google.com/>) and create or select a
   project.
2. **APIs & Services → OAuth consent screen**: choose **External**, fill in the app name and
   your email, add the scopes `openid`, `email` and `profile`, and add yourself as a **test
   user** (while the app is in "Testing").
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**:
   - **Application type**: Web application
   - **Authorized JavaScript origins**: `http://localhost`
   - **Authorized redirect URIs**: `http://localhost/api/auth/social/google/callback`
4. Add to `.env`:
   ```bash
   KEYGATE_GOOGLE_CLIENT_ID=<...>.apps.googleusercontent.com
   KEYGATE_GOOGLE_CLIENT_SECRET=<Client secret>
   ```

If you changed `KEYGATE_PUBLIC_URL` (e.g. a different port), use that origin in the callback
URLs instead. Providers require an **exact** match.

### How linking works

- **New email**: "Continue with GitHub/Google" creates an account. Add a passkey right after.
- **Email already belongs to a Keygate account**: sign-in is refused. Accounts are never
  merged silently. Sign in with your passkey, then use **Link GitHub/Google** on the account
  page (you'll confirm the specific identity before it's linked).

## Development

For running tests and linters on the host you also need [uv](https://docs.astral.sh/uv/),
Node.js 22 with [pnpm](https://pnpm.io/) 11, and [pre-commit](https://pre-commit.com/).

```bash
make install    # deps, Playwright browser, git hooks
make lint       # ruff, mypy --strict, eslint, prettier, tsc
make test       # pytest (real Postgres/Redis) + Playwright smoke + full-stack E2E
make test-e2e   # just the browser E2E (virtual WebAuthn authenticator via CDP)
make help       # everything else
```

After changing Python dependencies, run `docker compose restart api`: the dev container
syncs dependencies on start, while code changes hot-reload on their own.

## Repository layout

```
apps/api       FastAPI auth service (Python 3.12, SQLAlchemy 2 async, Alembic)
apps/web       Keygate UI (Next.js 15, Tailwind, shadcn/ui)
apps/demo-notes  Demo relying party (Next.js, openid-client, BFF)
infra/gateway  Caddy config: one origin for UI + API
docs/          Architecture decisions (more docs land in Phase 6)
```

## License

[MIT](LICENSE)
