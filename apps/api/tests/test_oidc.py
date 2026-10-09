"""Keygate as an OpenID Connect provider: Authorization Code + PKCE end to end."""

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.models import AuditEvent
from keygate.auth.email import InMemoryMailer
from keygate.auth.models import User, UserStatus
from keygate.config import Settings
from keygate.oidc.clients import build_client
from keygate.oidc.keys import KeyStore
from keygate.oidc.models import OAuthRefreshToken
from keygate.oidc.tokens import at_hash
from keygate.security.crypto import Encryptor
from tests.helpers import sign_in, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration

CLIENT_ID = "notes-test"
SECRET = "notes-test-secret-" + "x" * 30
REDIRECT = "http://127.0.0.1:3001/api/auth/callback"
POST_LOGOUT = "http://127.0.0.1:3001/"
ALL_SCOPES = ["openid", "profile", "email", "notes:read", "notes:write"]
ISSUER = "http://localhost"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    return verifier, challenge.decode()


@pytest.fixture
async def oauth_client(db_sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    async with db_sessionmaker() as db:
        db.add(
            build_client(
                name="Notes (test)",
                confidential=True,
                redirect_uris=[REDIRECT],
                post_logout_redirect_uris=[POST_LOGOUT],
                allowed_scopes=ALL_SCOPES,
                created_by=None,
                client_id=CLIENT_ID,
                secret=SECRET,
            ).client
        )
        db.add(
            build_client(
                name="SPA (test)",
                confidential=False,
                redirect_uris=["http://localhost:5173/callback"],
                post_logout_redirect_uris=[],
                allowed_scopes=["openid", "profile"],
                created_by=None,
                client_id="spa-test",
            ).client
        )
        await db.commit()


@pytest.fixture
async def user(
    client: httpx.AsyncClient, mailer: InMemoryMailer, oauth_client: None
) -> SoftAuthenticator:
    auth = SoftAuthenticator()
    await sign_up(client, mailer, auth, "ada@example.com")
    return auth


def authorize_params(challenge: str, **overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": " ".join(ALL_SCOPES),
        "state": "st-" + secrets.token_urlsafe(8),
        "nonce": "n-" + secrets.token_urlsafe(8),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(overrides)
    return {k: v for k, v in params.items() if v != ""}


async def authorize(client: httpx.AsyncClient, params: dict[str, str]) -> str:
    resp = await client.get("/oauth2/authorize", params=params, follow_redirects=False)
    assert resp.status_code == 303, resp.text
    location: str = resp.headers["location"]
    return location


async def approve(client: httpx.AsyncClient, location: str, approve: bool = True) -> str:
    assert location.startswith("/consent#request="), location
    request_id = location.split("#request=")[1]
    resp = await client.post("/oauth2/consent", json={"request_id": request_id, "approve": approve})
    assert resp.status_code == 200, resp.text
    redirect: str = resp.json()["redirect_to"]
    return redirect


def query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


async def get_code(client: httpx.AsyncClient, **overrides: str) -> tuple[str, str, dict[str, str]]:
    verifier, challenge = pkce()
    params = authorize_params(challenge, **overrides)
    location = await authorize(client, params)
    if location.startswith("/consent"):
        location = await approve(client, location)
    result = query(location)
    assert "code" in result, location
    return result["code"], verifier, params


async def exchange(
    client: httpx.AsyncClient, code: str, verifier: str, **overrides: str
) -> httpx.Response:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
        **overrides,
    }
    return await client.post("/oauth2/token", data=data, auth=(CLIENT_ID, SECRET))


async def jwks(client: httpx.AsyncClient) -> KeySet:
    return KeySet.import_key_set((await client.get("/oauth2/jwks")).json())


async def tokens(client: httpx.AsyncClient) -> dict[str, Any]:
    code, verifier, params = await get_code(client)
    resp = await exchange(client, code, verifier)
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    body["_params"] = params
    return body


# ---------------------------------------------------------------- discovery / JWKS


async def test_discovery_document(client: httpx.AsyncClient) -> None:
    doc = (await client.get("/.well-known/openid-configuration")).json()
    assert doc["issuer"] == ISSUER
    assert doc["authorization_endpoint"] == f"{ISSUER}/oauth2/authorize"
    assert doc["response_types_supported"] == ["code"]
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["id_token_signing_alg_values_supported"] == ["ES256"]
    assert "implicit" not in doc["grant_types_supported"]
    assert doc["authorization_response_iss_parameter_supported"] is True


async def test_jwks_publishes_public_keys_only(client: httpx.AsyncClient) -> None:
    keys = (await client.get("/oauth2/jwks")).json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "EC"
    assert keys[0]["alg"] == "ES256"
    assert "d" not in keys[0]  # never the private part


# ------------------------------------------------------------------- happy path


async def test_full_authorization_code_flow(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    verifier, challenge = pkce()
    params = authorize_params(challenge)
    location = await authorize(client, params)
    assert location.startswith("/consent#request=")  # first time: consent screen

    request_id = location.split("#request=")[1]
    details = (await client.post("/oauth2/consent/details", json={"request_id": request_id})).json()
    assert details["client_name"] == "Notes (test)"
    assert [s["name"] for s in details["scopes"]] == ALL_SCOPES

    redirect = await approve(client, location)
    assert redirect.startswith(REDIRECT + "?")
    result = query(redirect)
    assert result["state"] == params["state"]
    assert result["iss"] == ISSUER

    resp = await exchange(client, result["code"], verifier)
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 600
    assert body["scope"] == " ".join(ALL_SCOPES)

    keys = await jwks(client)
    id_token = jwt.decode(body["id_token"], keys, algorithms=["ES256"])
    claims = id_token.claims
    assert id_token.header["kid"] == keys.keys[0].kid
    assert claims["iss"] == ISSUER
    assert claims["aud"] == CLIENT_ID
    assert claims["nonce"] == params["nonce"]
    assert claims["email"] == "ada@example.com"
    assert claims["at_hash"] == at_hash(body["access_token"])
    assert claims["exp"] - claims["iat"] == 600

    access = jwt.decode(body["access_token"], keys, algorithms=["ES256"])
    assert access.header["typ"] == "at+jwt"
    assert access.claims["aud"] == [ISSUER, "notes-api"]
    assert access.claims["client_id"] == CLIENT_ID

    info = await client.get(
        "/oauth2/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert info.json() == {
        "sub": claims["sub"],
        "name": "ada",
        "email": "ada@example.com",
        "email_verified": True,
    }


async def test_consent_is_remembered_and_re_asked_for_new_scopes(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    _, challenge = pkce()
    await get_code(client, scope="openid profile")
    # Same scopes again: straight back to the client with a code.
    location = await authorize(client, authorize_params(challenge, scope="openid profile"))
    assert location.startswith(REDIRECT)
    # More scopes than approved: ask again.
    location = await authorize(client, authorize_params(challenge, scope="openid email"))
    assert location.startswith("/consent#")
    # prompt=consent always asks.
    location = await authorize(
        client, authorize_params(challenge, scope="openid profile", prompt="consent")
    )
    assert location.startswith("/consent#")


async def test_user_can_deny(client: httpx.AsyncClient, user: SoftAuthenticator) -> None:
    _, challenge = pkce()
    params = authorize_params(challenge)
    redirect = await approve(client, await authorize(client, params), approve=False)
    result = query(redirect)
    assert result["error"] == "access_denied"
    assert result["state"] == params["state"]


async def test_consent_request_belongs_to_its_user(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    user: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    _, challenge = pkce()
    location = await authorize(client, authorize_params(challenge))
    await sign_up(second_client, mailer, SoftAuthenticator(), "mallory@example.com")
    request_id = location.split("#request=")[1]
    resp = await second_client.post(
        "/oauth2/consent", json={"request_id": request_id, "approve": True}
    )
    assert resp.status_code == 404


# ------------------------------------------------------------- authentication


async def test_unauthenticated_user_is_sent_to_sign_in(
    client: httpx.AsyncClient, oauth_client: None
) -> None:
    _, challenge = pkce()
    location = await authorize(client, authorize_params(challenge))
    assert location.startswith("/signin?next=%2Foauth2%2Fauthorize%3F")


async def test_prompt_none_without_session(client: httpx.AsyncClient, oauth_client: None) -> None:
    _, challenge = pkce()
    result = query(await authorize(client, authorize_params(challenge, prompt="none")))
    assert result["error"] == "login_required"


async def test_prompt_none_without_consent(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    _, challenge = pkce()
    result = query(await authorize(client, authorize_params(challenge, prompt="none")))
    assert result["error"] == "consent_required"


async def test_prompt_login_and_max_age_force_fresh_sign_in(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from datetime import timedelta

    from keygate.auth.models import Session
    from keygate.db.types import utcnow

    async with db_sessionmaker() as db:
        await db.execute(
            update(Session).values(reauthenticated_at=utcnow() - timedelta(minutes=10))
        )
        await db.commit()
    _, challenge = pkce()
    for extra in ({"prompt": "login"}, {"max_age": "60"}):
        location = await authorize(client, authorize_params(challenge, **extra))
        assert location.startswith("/signin?next="), extra
        assert "prompt%3Dlogin" not in location  # no redirect loop after signing in


# -------------------------------------------------------- request validation


async def test_unknown_client_never_redirects(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    _, challenge = pkce()
    location = await authorize(client, authorize_params(challenge, client_id="nope"))
    assert location == "/oauth/error?error=invalid_client"


@pytest.mark.parametrize(
    "bad_uri",
    [
        "http://127.0.0.1:3001/api/auth/callback/",  # trailing slash
        "http://127.0.0.1:3001/api/auth/callback?x=1",  # extra query
        "http://127.0.0.1:3001/api/auth/callbackx",  # prefix match
        "http://evil.example/api/auth/callback",
        "HTTP://127.0.0.1:3001/api/auth/callback",  # case
    ],
)
async def test_redirect_uri_must_match_exactly(
    client: httpx.AsyncClient, user: SoftAuthenticator, bad_uri: str
) -> None:
    _, challenge = pkce()
    location = await authorize(client, authorize_params(challenge, redirect_uri=bad_uri))
    assert location == "/oauth/error?error=invalid_redirect_uri"


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"response_type": "token"}, "unsupported_response_type"),
        ({"response_type": "id_token token"}, "unsupported_response_type"),
        ({"code_challenge": ""}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge_method": ""}, "invalid_request"),
        ({"code_challenge": "short"}, "invalid_request"),
        ({"scope": "profile email"}, "invalid_scope"),
        ({"scope": "openid admin"}, "invalid_scope"),
        ({"prompt": "none login"}, "invalid_request"),
        ({"response_mode": "fragment"}, "invalid_request"),
    ],
)
async def test_invalid_requests_redirect_with_error(
    client: httpx.AsyncClient, user: SoftAuthenticator, overrides: dict[str, str], error: str
) -> None:
    _, challenge = pkce()
    params = authorize_params(challenge, **overrides)
    result = query(await authorize(client, params))
    assert result["error"] == error
    assert result["state"] == params["state"]
    assert "code" not in result


async def test_scope_not_allowed_for_client(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    _, challenge = pkce()
    params = authorize_params(
        challenge,
        client_id="spa-test",
        redirect_uri="http://localhost:5173/callback",
        scope="openid notes:read",
    )
    assert query(await authorize(client, params))["error"] == "invalid_scope"


# -------------------------------------------------------------- token endpoint


async def test_code_is_single_use_and_replay_revokes_tokens(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    code, verifier, _ = await get_code(client)
    first = await exchange(client, code, verifier)
    assert first.status_code == 200
    replay = await exchange(client, code, verifier)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    # The refresh token from the first exchange no longer works.
    refresh = await client.post(
        "/oauth2/token",
        data={"grant_type": "refresh_token", "refresh_token": first.json()["refresh_token"]},
        auth=(CLIENT_ID, SECRET),
    )
    assert refresh.json()["error"] == "invalid_grant"
    async with db_sessionmaker() as db:
        reuse = (
            await db.execute(select(AuditEvent).where(AuditEvent.event_type == "oauth.code_reuse"))
        ).scalar_one()
    assert reuse.severity.value == "high"


async def test_expired_code_rejected(
    client: httpx.AsyncClient, user: SoftAuthenticator, redis: Redis
) -> None:
    code, verifier, _ = await get_code(client)
    [key] = [k async for k in redis.scan_iter("oauth:code:*")]
    assert 0 < await redis.ttl(key) <= 60
    await redis.delete(key)
    assert (await exchange(client, code, verifier)).json()["error"] == "invalid_grant"


async def test_wrong_pkce_verifier_rejected(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    code, _, _ = await get_code(client)
    other_verifier, _ = pkce()
    resp = await exchange(client, code, other_verifier)
    assert resp.json() == {
        "error": "invalid_grant",
        "error_description": "PKCE verification failed.",
    }


async def test_missing_pkce_verifier_rejected(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    code, _, _ = await get_code(client)
    resp = await client.post(
        "/oauth2/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT},
        auth=(CLIENT_ID, SECRET),
    )
    assert resp.json()["error"] == "invalid_grant"


async def test_redirect_uri_must_match_at_token_endpoint(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    code, verifier, _ = await get_code(client)
    resp = await exchange(client, code, verifier, redirect_uri=REDIRECT + "/other")
    assert resp.json()["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "auth",
    [(CLIENT_ID, "wrong-secret"), ("unknown-client", SECRET), None],
)
async def test_client_authentication(
    client: httpx.AsyncClient, user: SoftAuthenticator, auth: tuple[str, str] | None
) -> None:
    code, verifier, _ = await get_code(client)
    resp = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            **({} if auth else {"client_id": CLIENT_ID}),
        },
        auth=auth or httpx.USE_CLIENT_DEFAULT,
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_client"
    assert resp.headers["www-authenticate"].startswith("Basic")


async def test_client_secret_post_supported(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    code, verifier, _ = await get_code(client)
    resp = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": SECRET,
        },
    )
    assert resp.status_code == 200


async def test_code_issued_to_another_client_rejected(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    verifier, challenge = pkce()
    params = authorize_params(
        challenge,
        client_id="spa-test",
        redirect_uri="http://localhost:5173/callback",
        scope="openid profile",
    )
    location = await authorize(client, params)
    code = query(await approve(client, location))["code"]
    resp = await exchange(client, code, verifier, redirect_uri="http://localhost:5173/callback")
    assert resp.json()["error"] == "invalid_grant"


async def test_public_client_uses_pkce_without_secret(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    verifier, challenge = pkce()
    params = authorize_params(
        challenge,
        client_id="spa-test",
        redirect_uri="http://localhost:5173/callback",
        scope="openid profile",
    )
    code = query(await approve(client, await authorize(client, params)))["code"]
    resp = await client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:5173/callback",
            "code_verifier": verifier,
            "client_id": "spa-test",
        },
    )
    assert resp.status_code == 200
    # No notes scopes requested: the access token isn't valid for the Notes API.
    access = jwt.decode(resp.json()["access_token"], await jwks(client), algorithms=["ES256"])
    assert access.claims["aud"] == [ISSUER]


async def test_unsupported_grant_types(client: httpx.AsyncClient, oauth_client: None) -> None:
    for grant in ("password", "client_credentials", "implicit"):
        resp = await client.post(
            "/oauth2/token", data={"grant_type": grant}, auth=(CLIENT_ID, SECRET)
        )
        assert resp.json()["error"] == "unsupported_grant_type"


# ------------------------------------------------------------- refresh tokens


async def _refresh(client: httpx.AsyncClient, token: str, **extra: str) -> httpx.Response:
    return await client.post(
        "/oauth2/token",
        data={"grant_type": "refresh_token", "refresh_token": token, **extra},
        auth=(CLIENT_ID, SECRET),
    )


async def test_refresh_token_rotation(client: httpx.AsyncClient, user: SoftAuthenticator) -> None:
    first = await tokens(client)
    second = (await _refresh(client, first["refresh_token"])).json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    third = await _refresh(client, second["refresh_token"])
    assert third.status_code == 200


async def test_refresh_token_reuse_revokes_family(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    first = await tokens(client)
    second = (await _refresh(client, first["refresh_token"])).json()
    # An attacker replays the stolen, already-rotated token...
    stolen = await _refresh(client, first["refresh_token"])
    assert stolen.json()["error"] == "invalid_grant"
    # ...which also kills the legitimate client's current token (the whole family).
    legit = await _refresh(client, second["refresh_token"])
    assert legit.json()["error"] == "invalid_grant"
    async with db_sessionmaker() as db:
        rows = list((await db.execute(select(OAuthRefreshToken))).scalars())
        reuse = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.event_type == "oauth.refresh_reuse")
            )
        ).scalar_one()
    assert all(r.revoked_at is not None for r in rows)
    assert reuse.severity.value == "high"


async def test_refresh_can_narrow_but_not_widen_scope(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    first = await tokens(client)
    narrow = (await _refresh(client, first["refresh_token"], scope="openid notes:read")).json()
    assert narrow["scope"] == "openid notes:read"
    wider = await _refresh(client, narrow["refresh_token"], scope="openid notes:write")
    assert wider.json()["error"] == "invalid_scope"


async def test_refresh_token_stored_hashed(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    body = await tokens(client)
    async with db_sessionmaker() as db:
        row = (await db.execute(select(OAuthRefreshToken))).scalar_one()
    assert row.token_hash != body["refresh_token"].encode()
    assert len(row.token_hash) == 32


async def test_suspended_user_cannot_refresh(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    body = await tokens(client)
    async with db_sessionmaker() as db:
        await db.execute(update(User).values(status=UserStatus.SUSPENDED))
        await db.commit()
    assert (await _refresh(client, body["refresh_token"])).json()["error"] == "invalid_grant"


# ------------------------------------------------------------ access tokens


async def test_expired_access_token_rejected(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    settings: Settings,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    body = await tokens(client)
    claims = jwt.decode(body["access_token"], await jwks(client), algorithms=["ES256"]).claims
    async with db_sessionmaker() as db:
        key = await KeyStore(Encryptor.from_settings(settings)).active_key(db)
    expired = jwt.encode(
        {"alg": "ES256", "kid": key.kid, "typ": "at+jwt"},
        {**claims, "iat": int(time.time()) - 1200, "exp": int(time.time()) - 600},
        key,
    )
    resp = await client.get("/oauth2/userinfo", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]


async def test_id_token_cannot_be_used_as_access_token(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    body = await tokens(client)
    resp = await client.get(
        "/oauth2/userinfo", headers={"Authorization": f"Bearer {body['id_token']}"}
    )
    assert resp.status_code == 401


async def test_userinfo_requires_bearer_header(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    body = await tokens(client)
    resp = await client.get("/oauth2/userinfo", params={"access_token": body["access_token"]})
    assert resp.status_code == 401


async def test_revoke_refresh_and_access_tokens(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    body = await tokens(client)
    for token in (body["refresh_token"], body["access_token"]):
        resp = await client.post("/oauth2/revoke", data={"token": token}, auth=(CLIENT_ID, SECRET))
        assert resp.status_code == 200
    assert (await _refresh(client, body["refresh_token"])).json()["error"] == "invalid_grant"
    info = await client.get(
        "/oauth2/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert info.status_code == 401
    # Unknown tokens: still 200 (no oracle).
    unknown = await client.post("/oauth2/revoke", data={"token": "nope"}, auth=(CLIENT_ID, SECRET))
    assert unknown.status_code == 200


# --------------------------------------------------------------- key rotation


async def test_signing_key_rotation(
    client: httpx.AsyncClient,
    user: SoftAuthenticator,
    settings: Settings,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from datetime import timedelta

    from keygate.oidc.models import SigningKey

    before = await tokens(client)
    old_kid = jwt.decode(before["id_token"], await jwks(client), algorithms=["ES256"]).header["kid"]

    store = KeyStore(Encryptor.from_settings(settings))
    async with db_sessionmaker() as db:
        new_kid = await store.rotate(db)
        await db.commit()

    published = {k["kid"] for k in (await client.get("/oauth2/jwks")).json()["keys"]}
    assert published == {old_kid, new_kid}  # old key still published for verification

    after = await tokens(client)
    keys = await jwks(client)
    assert jwt.decode(after["id_token"], keys, algorithms=["ES256"]).header["kid"] == new_kid
    # Tokens signed before the rotation still verify.
    old_info = await client.get(
        "/oauth2/userinfo", headers={"Authorization": f"Bearer {before['access_token']}"}
    )
    assert old_info.status_code == 200

    # Once the old key is removed (all its tokens expired), its tokens stop verifying.
    async with db_sessionmaker() as db:
        await db.execute(
            update(SigningKey)
            .where(SigningKey.kid == old_kid)
            .values(retired_at=SigningKey.retired_at - timedelta(hours=1))
        )
        assert await store.remove_retired(db, timedelta(minutes=20)) == 1
        await db.commit()
    assert {k["kid"] for k in (await client.get("/oauth2/jwks")).json()["keys"]} == {new_kid}
    stale = await client.get(
        "/oauth2/userinfo", headers={"Authorization": f"Bearer {before['access_token']}"}
    )
    assert stale.status_code == 401


async def test_private_keys_encrypted_at_rest(
    client: httpx.AsyncClient, oauth_client: None, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    from keygate.oidc.models import SigningKey

    await client.get("/oauth2/jwks")
    async with db_sessionmaker() as db:
        row = (await db.execute(select(SigningKey))).scalar_one()
    assert '"d"' not in row.encrypted_private_jwk
    assert '"d"' not in row.public_jwk


# --------------------------------------------------------------------- logout


async def test_rp_initiated_logout(client: httpx.AsyncClient, user: SoftAuthenticator) -> None:
    body = await tokens(client)
    resp = await client.get(
        "/oauth2/logout",
        params={
            "id_token_hint": body["id_token"],
            "post_logout_redirect_uri": POST_LOGOUT,
            "state": "bye",
        },
        follow_redirects=False,
    )
    assert resp.headers["location"] == POST_LOGOUT + "?state=bye"
    assert (await client.get("/account")).status_code == 401
    # The client's refresh tokens for this user are revoked too.
    assert (await _refresh(client, body["refresh_token"])).json()["error"] == "invalid_grant"


async def test_logout_never_redirects_to_unregistered_uri(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    body = await tokens(client)
    resp = await client.get(
        "/oauth2/logout",
        params={
            "id_token_hint": body["id_token"],
            "post_logout_redirect_uri": "https://evil.example/",
        },
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/signin?signed_out=1"


async def test_logout_without_valid_hint_asks_the_user(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    resp = await client.get(
        "/oauth2/logout",
        params={"id_token_hint": "garbage", "post_logout_redirect_uri": POST_LOGOUT},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/signout"
    assert (await client.get("/account")).status_code == 200  # still signed in


async def test_logout_hint_for_another_user_does_not_end_my_session(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    user: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    body = await tokens(client)  # Ada's ID token
    await sign_up(second_client, mailer, SoftAuthenticator(), "bob@example.com")
    resp = await second_client.get(
        "/oauth2/logout",
        params={"id_token_hint": body["id_token"], "post_logout_redirect_uri": POST_LOGOUT},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/signout"
    assert (await second_client.get("/account")).status_code == 200


async def test_sign_in_round_trip_after_oauth_redirect(
    client: httpx.AsyncClient, user: SoftAuthenticator
) -> None:
    """After signing out, authorize sends us to sign-in; signing in again lets the same
    authorize URL proceed."""
    await client.post("/auth/logout")
    _, challenge = pkce()
    params = authorize_params(challenge, scope="openid")
    assert (await authorize(client, params)).startswith("/signin?next=")
    await sign_in(client, user)
    assert (await authorize(client, params)).startswith("/consent#")
