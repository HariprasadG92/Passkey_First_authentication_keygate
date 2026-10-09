# API reference

Base URL in development: `http://localhost/api` (the gateway strips `/api`). OpenID Connect
endpoints live at the site root (`/oauth2/*`, `/.well-known/*`). Interactive OpenAPI docs:
`http://localhost/api/docs` (development only; disabled in production).

## Conventions

- **JSON** request and response bodies, except the OAuth token/revocation endpoints
  (`application/x-www-form-urlencoded`, RFC 6749).
- **Sessions**: an HttpOnly cookie (`kg_session`, or `__Host-kg_session` in production).
- **CSRF**: every non-GET request needs `X-CSRF-Token` equal to the `kg_csrf` cookie (get one
  from `GET /auth/session`). The OAuth back-channel endpoints are exempt.
- **Errors**: `{"error": {"code": "...", "message": "...", "details"?: [...]}}` with a stable
  `code` (`unauthorized`, `forbidden`, `step_up_required`, `last_sign_in_method`,
  `too_many_requests`, `validation_error`, …). OAuth endpoints return RFC 6749 errors
  (`{"error": "invalid_grant", "error_description": "..."}`).
- **Step-up**: endpoints marked 🔐 need a sign-in or re-authentication within 5 minutes,
  otherwise `403 step_up_required`.
- **Rate limits**: `429` with `Retry-After`; see ADR-035 for the table.

## Health

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/health` | none | Liveness |
| GET | `/health/ready` | none | Postgres and Redis reachability (`503` if degraded) |

## Authentication

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/auth/session` | optional | Session state, CSRF token, permissions (UI hints only) |
| POST | `/auth/signup` | none | `{email}` → 202; emails a magic link (same response for any email) |
| POST | `/auth/email/verify` | none | `{token}` → registration session |
| POST | `/auth/passkeys/register/options` | registration session | WebAuthn creation options for the first passkey |
| POST | `/auth/passkeys/register/verify` | registration session | `{credential, friendly_name?}` → full session |
| POST | `/auth/passkeys/login/options` | none | `{email?}` → `{ceremony_id, options}` (omit email for usernameless) |
| POST | `/auth/passkeys/login/verify` | none | `{ceremony_id, credential}` → session |
| POST | `/auth/totp/login` | none | `{email, code}` → session (fallback) |
| POST | `/auth/recovery/login` | none | `{email, code}` → session; notifies the user |
| POST | `/auth/step-up/passkey/options` | session | Assertion options limited to the user's passkeys |
| POST | `/auth/step-up/passkey/verify` | session | `{credential}` → rotated session, step-up satisfied |
| POST | `/auth/step-up/totp` | session | `{code}` → rotated session, step-up satisfied |
| POST | `/auth/logout` | optional | Revokes the session |

## Social login

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/auth/social/providers` | none | Enabled providers |
| POST | `/auth/social/{provider}/start` | none / session 🔐 for `link` | `{intent: signin\|link\|stepup}` → `{authorize_url}`; sets the browser-binding cookie |
| GET | `/auth/social/{provider}/callback` | browser binding | Provider redirect target; redirects to the UI with the outcome |
| POST | `/account/social/pending` | session 🔐 | `{pending_id}` → identity about to be linked |
| POST | `/account/social/confirm` | session 🔐 | `{pending_id}` → link it |
| DELETE | `/account/social/{id}` | session 🔐 | Unlink (last-method protected) |

## Account (self-service)

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/account` | session | Profile, passkeys, linked accounts, MFA status, step-up expiry |
| PATCH | `/account/passkeys/{id}` | session | `{friendly_name}` |
| DELETE | `/account/passkeys/{id}` | session 🔐 | Remove (last-method protected) |
| POST | `/account/passkeys/register/options` · `/verify` | session 🔐 | Add another passkey |
| POST | `/account/totp/setup` | session 🔐 | → `{secret, otpauth_uri, qr_svg_data_uri}` |
| POST | `/account/totp/confirm` | session 🔐 | `{code}` → enable |
| DELETE | `/account/totp` | session 🔐 | Disable (last-method protected) |
| POST | `/account/recovery-codes` | session 🔐 | → `{codes: [10]}` shown once; replaces old codes |
| GET | `/account/sessions` | session | Active sessions |
| DELETE | `/account/sessions/{id}` | session | Revoke one of your sessions |
| POST | `/account/sessions/revoke-others` | session | Revoke all but the current one |
| POST | `/account/email` | session 🔐 | `{new_email}` → 202; link to new address, notice to old |
| POST | `/account/email/confirm` | session | `{token}` (same user only) |

## Administration (permission in brackets)

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/admin/users?q&status&role&limit&offset` | `users:read` | Search users |
| GET | `/admin/users/{id}` | `users:read` | User detail (no secrets) |
| POST | `/admin/users/{id}/suspend` | `users:write` 🔐 | `{reason}`; revokes all sessions |
| POST | `/admin/users/{id}/unsuspend` | `users:write` 🔐 | |
| PUT | `/admin/users/{id}/roles` | `roles:assign` 🔐 | `{roles: [...]}`; grants revoke the target's sessions |
| POST | `/admin/users/{id}/sessions/revoke` | `users:sessions:revoke` 🔐 | |
| GET | `/admin/roles` | `users:read` | Roles and permissions |
| GET | `/admin/audit?event_type&severity&result&user_id&since&until&cursor&limit` | `audit:read` | Read-only, keyset-paginated |
| GET | `/admin/clients` | `clients:read` | OIDC clients |
| POST | `/admin/clients` | `clients:write` 🔐 | Register; secret shown once |
| GET / PUT | `/admin/clients/{id}` | `clients:read` / `clients:write` 🔐 | View / update |
| POST | `/admin/clients/{id}/secret` | `clients:write` 🔐 | Rotate secret |
| POST | `/admin/clients/{id}/disable` | `clients:write` 🔐 | Disable |

## OpenID Connect provider

| Method | Path | Description |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/oauth2/jwks` | Public signing keys (ES256) |
| GET | `/oauth2/authorize` | Authorization Code + PKCE (S256 required); `prompt`, `max_age`, `nonce` |
| POST | `/oauth2/consent/details` · `/oauth2/consent` | First-party consent screen (session + CSRF) |
| POST | `/oauth2/token` | `authorization_code`, `refresh_token`; client auth: `client_secret_basic`, `client_secret_post`, `none` |
| GET / POST | `/oauth2/userinfo` | Bearer access token (header only) |
| POST | `/oauth2/revoke` | RFC 7009; refresh tokens (family) or access tokens (by `jti`) |
| GET | `/oauth2/logout` | RP-initiated logout: `id_token_hint`, `post_logout_redirect_uri`, `state` |

Scopes: `openid`, `profile`, `email`, `notes:read`, `notes:write`. Access tokens are JWTs with
`typ: at+jwt`, `aud` = issuer (+ `notes-api` when notes scopes are granted), 10-minute expiry.

## Operator CLI

Run inside the API container (`docker compose exec api python -m keygate.cli ...`):

| Command | Description |
| --- | --- |
| `grant-role --email E --role admin\|auditor` | Bootstrap admins/auditors (`make admin email=...`) |
| `ensure-client --client-id ... --secret-env VAR --redirect-uri ... --scopes "..."` | Register/update a confidential client with a known secret |
| `rotate-signing-key` | New active key; retired keys stay published until their tokens expire (`make rotate-keys`) |
