"""OpenID Connect provider endpoints.

Authorization Code flow only, with PKCE required for every client (S256 only). No
implicit or hybrid flows, no ``plain`` PKCE, no tokens in URLs.

The OAuth endpoints return RFC 6749 error bodies (``{"error": ..., "error_description":
...}``), not Keygate's usual envelope, because OAuth client libraries expect them.
"""

import time
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.api.deps import (
    DB,
    AuditDep,
    Client,
    FullSession,
    Limiter,
    OptionalSession,
    RedisDep,
    Sessions,
    SettingsDep,
)
from keygate.audit.models import AuditResult, Severity
from keygate.auth.models import SessionLevel, User, UserStatus
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.oidc.clients import (
    ClientAuthError,
    authenticate_client,
    get_client,
    redirect_uri_allowed,
)
from keygate.oidc.flow import (
    AuthorizationRequest,
    CodeGrant,
    GrantStore,
    RefreshTokens,
    pkce_matches,
)
from keygate.oidc.keys import ALG, KeyStore
from keygate.oidc.models import OAuthClient, OAuthConsent
from keygate.oidc.scopes import SCOPES, parse_scope
from keygate.oidc.tokens import (
    TokenError,
    issue_tokens,
    user_claims,
    verify_access_token,
    verify_id_token_hint,
)
from keygate.security.crypto import Encryptor
from keygate.security.csrf import CSRF_EXEMPT_PATHS
from keygate.security.rate_limit import LIMITS, RateLimitExceededError

router = APIRouter(tags=["oidc"])

# Back-channel endpoints called by client servers, not by browsers with our cookies.
CSRF_EXEMPT_PATHS.update({"/oauth2/token", "/oauth2/revoke", "/oauth2/userinfo"})

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
PROMPTS = {"none", "login", "consent", "select_account"}
FRESH_LOGIN_SECONDS = 120


def _keystore(settings: Settings) -> KeyStore:
    return KeyStore(Encryptor.from_settings(settings))


def oauth_error(
    error: str, description: str, status_code: int = 400, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={**NO_STORE, **(headers or {})},
    )


def _add_query(url: str, params: dict[str, str | None]) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query += [(k, v) for k, v in params.items() if v is not None]
    return urlunsplit(parts._replace(query=urlencode(query)))


def _see_other(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER, headers=NO_STORE)


# ------------------------------------------------------------------- discovery


@router.get("/.well-known/openid-configuration")
async def discovery(settings: SettingsDep) -> JSONResponse:
    issuer = settings.issuer
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth2/authorize",
            "token_endpoint": f"{issuer}/oauth2/token",
            "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
            "jwks_uri": f"{issuer}/oauth2/jwks",
            "revocation_endpoint": f"{issuer}/oauth2/revoke",
            "end_session_endpoint": f"{issuer}/oauth2/logout",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [ALG],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "revocation_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": list(SCOPES),
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "auth_time",
                "nonce",
                "at_hash",
                "name",
                "email",
                "email_verified",
            ],
            "prompt_values_supported": sorted(PROMPTS),
            "authorization_response_iss_parameter_supported": True,
        },
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.get("/oauth2/jwks")
async def jwks(db: DB, settings: SettingsDep) -> JSONResponse:
    store = _keystore(settings)
    await store.active_key(db)  # make sure at least one key exists
    await db.commit()
    keyset = await store.published(db)
    return JSONResponse(
        keyset.as_dict(private=False), headers={"Cache-Control": "public, max-age=300"}
    )


# ------------------------------------------------------------------- authorize


def _auth_time(ctx: Any) -> int:
    when = ctx.session.reauthenticated_at or ctx.session.created_at
    return int(when.timestamp())


async def _code_redirect(grants: GrantStore, settings: Settings, req: AuthorizationRequest) -> str:
    code = await grants.issue_code(
        CodeGrant(
            client_pk=req.client_pk,
            client_id=req.client_id,
            redirect_uri=req.redirect_uri,
            scopes=req.scopes,
            nonce=req.nonce,
            code_challenge=req.code_challenge,
            user_id=req.user_id,
            auth_time=req.auth_time,
        )
    )
    # `iss` defends clients that talk to several providers against mix-up attacks (RFC 9207).
    return _add_query(req.redirect_uri, {"code": code, "state": req.state, "iss": settings.issuer})


@router.get("/oauth2/authorize", include_in_schema=False)
async def authorize(
    request: Request,
    db: DB,
    redis: RedisDep,
    settings: SettingsDep,
    ctx: OptionalSession,
) -> Response:
    q = request.query_params
    duplicated = [k for k in set(q.keys()) if len(q.getlist(k)) > 1]

    client = await get_client(db, q.get("client_id"))
    redirect_uri = q.get("redirect_uri")
    # Never redirect to an unverified URI: show our own error page instead (RFC 6749 §4.1.2.1).
    if client is None:
        return _see_other("/oauth/error?error=invalid_client")
    if not redirect_uri_allowed(client, redirect_uri) or "redirect_uri" in duplicated:
        return _see_other("/oauth/error?error=invalid_redirect_uri")
    assert redirect_uri is not None  # noqa: S101 - narrowed by redirect_uri_allowed
    state = q.get("state")

    def fail(error: str, description: str) -> Response:
        return _see_other(
            _add_query(
                redirect_uri,
                {
                    "error": error,
                    "error_description": description,
                    "state": state,
                    "iss": settings.issuer,
                },
            )
        )

    if duplicated:
        return fail("invalid_request", f"Repeated parameter(s): {', '.join(sorted(duplicated))}.")
    if q.get("response_type") != "code":
        return fail("unsupported_response_type", "Only the authorization code flow is supported.")
    if q.get("response_mode", "query") != "query":
        return fail("invalid_request", "Only response_mode=query is supported.")
    if "request" in q or "request_uri" in q:
        return fail("request_not_supported", "Request objects are not supported.")

    challenge = q.get("code_challenge", "")
    if not challenge:
        return fail("invalid_request", "PKCE is required: send code_challenge.")
    if q.get("code_challenge_method") != "S256":
        return fail("invalid_request", "code_challenge_method must be S256.")
    if len(challenge) != 43 or not all(c.isalnum() or c in "-_" for c in challenge):
        return fail("invalid_request", "code_challenge must be a base64url SHA-256 (43 chars).")

    scopes = parse_scope(q.get("scope"))
    if "openid" not in scopes:
        return fail("invalid_scope", "The openid scope is required.")
    unknown = [s for s in scopes if s not in SCOPES or s not in client.allowed_scopes]
    if unknown:
        return fail("invalid_scope", f"Scope(s) not allowed for this client: {' '.join(unknown)}.")

    prompt = set((q.get("prompt") or "").split())
    if prompt - PROMPTS or ("none" in prompt and len(prompt) > 1):
        return fail("invalid_request", "Invalid prompt value.")
    max_age = q.get("max_age")
    if max_age is not None and (not max_age.isdigit() or len(max_age) > 9):
        return fail("invalid_request", "max_age must be a non-negative integer.")
    nonce = q.get("nonce")
    if nonce is not None and len(nonce) > 255:
        return fail("invalid_request", "nonce is too long.")

    # ---- authentication: send the browser to Keygate's sign-in, then back here.
    signed_in = ctx is not None and ctx.session.level is SessionLevel.FULL
    if signed_in:
        assert ctx is not None  # noqa: S101
        age = int(time.time()) - _auth_time(ctx)
        too_old = ("login" in prompt and age > FRESH_LOGIN_SECONDS) or (
            max_age is not None and age > int(max_age)
        )
    if not signed_in or too_old:
        if "none" in prompt:
            return fail("login_required", "The user is not signed in.")
        # Drop prompt=login from the return URL so a fresh sign-in doesn't loop.
        back = [(k, v) for k, v in q.multi_items() if k != "prompt" or v != "login"]
        next_url = "/oauth2/authorize?" + urlencode(back)
        return _see_other(
            f"/signin?next={quote(next_url, safe='')}" + ("&reauth=1" if signed_in else "")
        )
    assert ctx is not None  # noqa: S101

    req = AuthorizationRequest(
        client_pk=str(client.id),
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
        user_id=str(ctx.user.id),
        auth_time=_auth_time(ctx),
    )
    grants = GrantStore(settings, redis)

    # ---- consent: remembered per (user, client); more scopes means asking again.
    consent = await db.get(OAuthConsent, (ctx.user.id, client.id))
    needs_consent = "consent" in prompt or consent is None or not set(scopes) <= set(consent.scopes)
    if needs_consent:
        if "none" in prompt:
            return fail("consent_required", "The user hasn't approved this client.")
        request_id = await grants.save_request(req)
        return _see_other(f"/consent#request={request_id}")
    return _see_other(await _code_redirect(grants, settings, req))


class ConsentLookup(BaseModel):
    request_id: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class ConsentDecision(ConsentLookup):
    approve: bool


class ConsentScope(BaseModel):
    name: str
    description: str


class ConsentDetails(BaseModel):
    client_name: str
    client_id: str
    redirect_host: str
    scopes: list[ConsentScope]


class RedirectOut(BaseModel):
    redirect_to: str


async def _load_owned_request(
    grants: GrantStore, request_id: str, user_id: uuid.UUID, *, consume: bool
) -> AuthorizationRequest:
    req = await grants.load_request(request_id, consume=consume)
    if req is None or req.user_id != str(user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This sign-in request has expired.")
    return req


@router.post("/oauth2/consent/details", response_model=ConsentDetails)
async def consent_details(
    body: ConsentLookup, ctx: FullSession, db: DB, redis: RedisDep, settings: SettingsDep
) -> ConsentDetails:
    req = await _load_owned_request(
        GrantStore(settings, redis), body.request_id, ctx.user.id, consume=False
    )
    client = await db.get(OAuthClient, uuid.UUID(req.client_pk))
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This sign-in request has expired.")
    return ConsentDetails(
        client_name=client.name,
        client_id=client.client_id,
        redirect_host=urlsplit(req.redirect_uri).netloc,
        scopes=[ConsentScope(name=s, description=SCOPES[s]) for s in req.scopes],
    )


@router.post("/oauth2/consent", response_model=RedirectOut)
async def consent_decision(
    body: ConsentDecision,
    ctx: FullSession,
    db: DB,
    redis: RedisDep,
    settings: SettingsDep,
    audit: AuditDep,
    client: Client,
) -> RedirectOut:
    grants = GrantStore(settings, redis)
    req = await _load_owned_request(grants, body.request_id, ctx.user.id, consume=True)
    user_id = ctx.user.id
    if not body.approve:
        await audit.record(
            "oauth.consent",
            result=AuditResult.FAILURE,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"client_id": req.client_id, "decision": "denied"},
        )
        return RedirectOut(
            redirect_to=_add_query(
                req.redirect_uri,
                {
                    "error": "access_denied",
                    "error_description": "The user declined.",
                    "state": req.state,
                    "iss": settings.issuer,
                },
            )
        )
    client_pk = uuid.UUID(req.client_pk)
    consent = await db.get(OAuthConsent, (user_id, client_pk))
    if consent is None:
        db.add(OAuthConsent(user_id=user_id, client_id=client_pk, scopes=req.scopes))
    else:
        consent.scopes = sorted(set(consent.scopes) | set(req.scopes))
        consent.granted_at = utcnow()
    await db.commit()
    await audit.record(
        "oauth.consent",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"client_id": req.client_id, "scopes": req.scopes},
    )
    return RedirectOut(redirect_to=await _code_redirect(grants, settings, req))


# ----------------------------------------------------------------------- token


async def _form(request: Request) -> tuple[dict[str, str], list[str]]:
    form = await request.form()
    duplicated = [k for k in set(form.keys()) if len(form.getlist(k)) > 1]
    return {k: str(v) for k, v in form.items()}, duplicated


async def _rate_limit(limiter: Limiter, bucket: str, key: str) -> JSONResponse | None:
    try:
        await limiter.hit(bucket, key, LIMITS[bucket])
    except RateLimitExceededError as exc:
        return oauth_error("slow_down", "Too many requests.", 429, dict(exc.headers or {}))
    return None


async def _active_user(db: AsyncSession, user_id: str) -> User | None:
    user = await db.get(User, uuid.UUID(user_id))
    return user if user is not None and user.status is UserStatus.ACTIVE else None


def _token_response(payload: dict[str, Any]) -> JSONResponse:
    return JSONResponse({k: v for k, v in payload.items() if v is not None}, headers=NO_STORE)


@router.post("/oauth2/token", include_in_schema=False)
async def token(
    request: Request,
    db: DB,
    redis: RedisDep,
    settings: SettingsDep,
    limiter: Limiter,
    audit: AuditDep,
    client_info: Client,
) -> JSONResponse:
    if limited := await _rate_limit(limiter, "token:ip", client_info.ip or "unknown"):
        return limited
    form, duplicated = await _form(request)
    if duplicated:
        return oauth_error("invalid_request", "Repeated parameters are not allowed.")
    try:
        oauth_client = await authenticate_client(db, request, form)
    except ClientAuthError:
        return oauth_error(
            "invalid_client",
            "Client authentication failed.",
            401,
            {"WWW-Authenticate": 'Basic realm="keygate"'},
        )
    if limited := await _rate_limit(limiter, "token:client", oauth_client.client_id):
        return limited

    grants = GrantStore(settings, redis)
    refresh_tokens = RefreshTokens(settings)
    keystore = _keystore(settings)
    grant_type = form.get("grant_type")

    if grant_type == "authorization_code":
        code = form.get("code", "")
        grant, spent_family = await grants.redeem_code(code) if code else (None, None)
        if grant is None:
            if spent_family:
                # The code was already redeemed: someone replayed it. Revoke what it produced.
                await refresh_tokens.revoke_family(db, uuid.UUID(spent_family))
                await db.commit()
                await audit.record(
                    "oauth.code_reuse",
                    result=AuditResult.FAILURE,
                    severity=Severity.HIGH,
                    client=client_info,
                    details={"client_id": oauth_client.client_id},
                )
            return oauth_error("invalid_grant", "The code is invalid, expired or already used.")
        if grant.client_id != oauth_client.client_id:
            return oauth_error("invalid_grant", "The code was issued to another client.")
        if form.get("redirect_uri") != grant.redirect_uri:
            return oauth_error(
                "invalid_grant", "redirect_uri does not match the authorization request."
            )
        if not pkce_matches(form.get("code_verifier", ""), grant.code_challenge):
            return oauth_error("invalid_grant", "PKCE verification failed.")
        user = await _active_user(db, grant.user_id)
        if user is None:
            return oauth_error("invalid_grant", "The user is no longer active.")

        key = await keystore.active_key(db)
        issued = issue_tokens(
            settings,
            key,
            user=user,
            client_id=oauth_client.client_id,
            scopes=grant.scopes,
            auth_time=grant.auth_time,
            nonce=grant.nonce,
            include_id_token=True,
        )
        refresh, family_head = await refresh_tokens.issue(
            db,
            client_pk=oauth_client.id,
            user_id=user.id,
            scopes=grant.scopes,
            auth_time=_dt(grant.auth_time),
        )
        await grants.mark_spent(code, family_head.family_id)
        user_id = user.id
        await db.commit()
        await audit.record(
            "oauth.token",
            result=AuditResult.SUCCESS,
            client=client_info,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={
                "client_id": oauth_client.client_id,
                "grant": "authorization_code",
                "scopes": grant.scopes,
            },
        )
        return _token_response(
            {
                "access_token": issued.access_token,
                "token_type": "Bearer",
                "expires_in": issued.expires_in,
                "id_token": issued.id_token,
                "refresh_token": refresh,
                "scope": " ".join(grant.scopes),
            }
        )

    if grant_type == "refresh_token":
        row = await refresh_tokens.find(db, form.get("refresh_token", ""))
        if row is None or row.client_id != oauth_client.id or row.revoked_at is not None:
            return oauth_error("invalid_grant", "The refresh token is invalid.")
        if row.used_at is not None:
            # Rotated tokens are single-use: a second use means the token was copied.
            family, owner = row.family_id, row.user_id
            await refresh_tokens.revoke_family(db, family)
            await db.commit()
            await audit.record(
                "oauth.refresh_reuse",
                result=AuditResult.FAILURE,
                severity=Severity.HIGH,
                client=client_info,
                target_user_id=owner,
                details={"client_id": oauth_client.client_id, "family": str(family)},
            )
            return oauth_error("invalid_grant", "The refresh token was already used.")
        if row.expires_at <= utcnow():
            return oauth_error("invalid_grant", "The refresh token has expired.")
        requested = parse_scope(form.get("scope")) or row.scopes
        if not set(requested) <= set(row.scopes):
            return oauth_error("invalid_scope", "Cannot widen scope on refresh.")
        user = await _active_user(db, str(row.user_id))
        if user is None:
            await refresh_tokens.revoke_family(db, row.family_id)
            await db.commit()
            return oauth_error("invalid_grant", "The user is no longer active.")

        row.used_at = utcnow()
        key = await keystore.active_key(db)
        auth_time = int(row.auth_time.timestamp())
        issued = issue_tokens(
            settings,
            key,
            user=user,
            client_id=oauth_client.client_id,
            scopes=requested,
            auth_time=auth_time,
            nonce=None,
            include_id_token=True,
        )
        refresh, _ = await refresh_tokens.issue(
            db,
            client_pk=oauth_client.id,
            user_id=user.id,
            scopes=requested,
            auth_time=row.auth_time,
            family_id=row.family_id,
            family_expires_at=row.family_expires_at,
        )
        await db.commit()
        return _token_response(
            {
                "access_token": issued.access_token,
                "token_type": "Bearer",
                "expires_in": issued.expires_in,
                "id_token": issued.id_token,
                "refresh_token": refresh,
                "scope": " ".join(requested),
            }
        )

    return oauth_error("unsupported_grant_type", "Use authorization_code or refresh_token.")


def _dt(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp, UTC)


# -------------------------------------------------------------------- userinfo


def _bearer_error(error: str, description: str, status_code: int = 401) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers={**NO_STORE, "WWW-Authenticate": f'Bearer error="{error}"'},
    )


@router.api_route("/oauth2/userinfo", methods=["GET", "POST"], include_in_schema=False)
async def userinfo(
    request: Request, db: DB, redis: RedisDep, settings: SettingsDep
) -> JSONResponse:
    scheme, _, token_value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token_value:
        # Tokens only in the Authorization header: never in URLs (logs, Referer).
        return _bearer_error("invalid_request", "Send the access token as a Bearer header.")
    try:
        claims = verify_access_token(
            settings, await _keystore(settings).published(db), token_value, audience=settings.issuer
        )
    except TokenError:
        return _bearer_error("invalid_token", "The access token is invalid or expired.")
    if await GrantStore(settings, redis).is_jti_revoked(claims["jti"]):
        return _bearer_error("invalid_token", "The access token was revoked.")
    scopes = parse_scope(claims.get("scope"))
    if "openid" not in scopes:
        return _bearer_error("insufficient_scope", "The openid scope is required.", 403)
    user = await _active_user(db, claims["sub"])
    if user is None:
        return _bearer_error("invalid_token", "The user is no longer active.")
    return JSONResponse({"sub": str(user.id), **user_claims(user, scopes)}, headers=NO_STORE)


# ---------------------------------------------------------------------- revoke


@router.post("/oauth2/revoke", include_in_schema=False)
async def revoke(
    request: Request,
    db: DB,
    redis: RedisDep,
    settings: SettingsDep,
    limiter: Limiter,
    client_info: Client,
) -> Response:
    """RFC 7009. Always 200 for a well-formed request from an authenticated client, so
    the response doesn't reveal whether a token existed."""
    if limited := await _rate_limit(limiter, "token:ip", client_info.ip or "unknown"):
        return limited
    form, _ = await _form(request)
    try:
        oauth_client = await authenticate_client(db, request, form)
    except ClientAuthError:
        return oauth_error(
            "invalid_client",
            "Client authentication failed.",
            401,
            {"WWW-Authenticate": 'Basic realm="keygate"'},
        )
    value = form.get("token", "")
    refresh_tokens = RefreshTokens(settings)
    row = await refresh_tokens.find(db, value) if value else None
    if row is not None and row.client_id == oauth_client.id:
        await refresh_tokens.revoke_family(db, row.family_id)
        await db.commit()
    elif value:
        keys = await _keystore(settings).published(db)
        for audience in (settings.issuer, settings.oidc_notes_audience):
            try:
                claims = verify_access_token(settings, keys, value, audience=audience)
            except TokenError:
                continue
            if claims.get("client_id") == oauth_client.client_id:
                await GrantStore(settings, redis).revoke_jti(claims["jti"], int(claims["exp"]))
            break
    return Response(status_code=status.HTTP_200_OK, headers=NO_STORE)


# ---------------------------------------------------------------------- logout


@router.get("/oauth2/logout", include_in_schema=False)
async def logout(
    request: Request,
    db: DB,
    redis: RedisDep,
    settings: SettingsDep,
    ctx: OptionalSession,
    sessions: Sessions,
    audit: AuditDep,
    client_info: Client,
) -> Response:
    """RP-initiated logout (OIDC RP-Initiated Logout 1.0).

    We only redirect to a ``post_logout_redirect_uri`` registered by the client that the
    ``id_token_hint`` was issued to (no open redirect), and only end the session without
    asking if the hint belongs to the signed-in user. Otherwise the user lands on
    Keygate's own page and decides."""
    q = request.query_params
    keys = await _keystore(settings).published(db)
    hint = verify_id_token_hint(settings, keys, q.get("id_token_hint", ""))
    client_id = (hint or {}).get("aud") or q.get("client_id")
    oauth_client = await get_client(db, client_id if isinstance(client_id, str) else None)
    target = q.get("post_logout_redirect_uri")

    redirect_ok = (
        hint is not None
        and oauth_client is not None
        and target is not None
        and target in oauth_client.post_logout_redirect_uris
    )
    if hint is not None and ctx is not None and hint.get("sub") == str(ctx.user.id):
        user_id = ctx.user.id
        await sessions.revoke_token(db, ctx.token)
        if oauth_client is not None:
            await RefreshTokens(settings).revoke_for(db, user_id, oauth_client.id)
        await db.commit()
        await audit.record(
            "signout",
            result=AuditResult.SUCCESS,
            client=client_info,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"via": "rp_initiated_logout", "client_id": client_id},
        )
        if redirect_ok:
            assert target is not None  # noqa: S101
            response = _see_other(_add_query(target, {"state": q.get("state")}))
        else:
            response = _see_other("/signin?signed_out=1")
        sessions.clear_cookies(response)
        return response
    if redirect_ok and ctx is None:
        # Already signed out of Keygate: just send the user back.
        assert target is not None  # noqa: S101
        return _see_other(_add_query(target, {"state": q.get("state")}))
    return _see_other("/signout")
