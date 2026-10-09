# Keygate

> Passkey-first, self-hostable identity platform: WebAuthn sign-in, MFA and recovery, social login, RBAC, and an OpenID Connect provider.

🚧 **Work in progress**: built in phases. See [`SPEC.md`](SPEC.md) for the full specification and
[`docs/DECISIONS.md`](docs/DECISIONS.md) for the design decisions so far.

| Phase | Scope                                       | Status         |
| ----- | ------------------------------------------- | -------------- |
| 0     | Foundation: stack, tooling, git hooks       | 🔍 In review   |
| 1     | Accounts, passkeys, sessions                | ⏳ Planned     |
| 2     | Credential management, MFA, recovery        | ⏳ Planned     |
| 3     | Social login (GitHub, Google)               | ⏳ Planned     |
| 4     | RBAC, admin dashboard, audit log            | ⏳ Planned     |
| 5     | Keygate as an OIDC provider + demo app      | ⏳ Planned     |
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

Port 80 already taken? Set `GATEWAY_PORT` in `.env`.

## Development

For running tests and linters on the host you also need [uv](https://docs.astral.sh/uv/),
Node.js 22 with [pnpm](https://pnpm.io/) 11, and [pre-commit](https://pre-commit.com/).

```bash
make install    # deps, Playwright browser, git hooks
make lint       # ruff, mypy --strict, eslint, prettier, tsc
make test       # pytest (against compose Postgres/Redis) + Playwright E2E
make help       # everything else
```

## Repository layout

```
apps/api       FastAPI auth service (Python 3.12, SQLAlchemy 2 async, Alembic)
apps/web       Keygate UI (Next.js 15, Tailwind, shadcn/ui)
infra/gateway  Caddy config: one origin for UI + API
docs/          Architecture decisions (more docs land in Phase 6)
```

## License

[MIT](LICENSE)
