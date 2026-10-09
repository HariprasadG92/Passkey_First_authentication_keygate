"""GitHub (OAuth 2.0) and Google (OpenID Connect) as identity providers.

Only protocol primitives come from Authlib (authorization URL, PKCE challenge); HTTP
goes through the app's single ``httpx`` client and ID tokens are verified with joserfc
(see ADR-026).
"""

import json
import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from redis.asyncio import Redis

from keygate.config import Settings
from keygate.logging_setup import get_logger

log = get_logger(__name__)

ProviderId = Literal["github", "google"]
HTTP_TIMEOUT = httpx.Timeout(10.0)
JWKS_CACHE_SECONDS = 3600
ID_TOKEN_LEEWAY_SECONDS = 60


class ProviderError(Exception):
    """The provider's response failed validation. ``reason`` is for the audit log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SocialIdentity:
    provider: ProviderId
    subject: str
    email: str | None
    email_verified: bool
    display_name: str | None


@dataclass(frozen=True)
class Provider:
    id: ProviderId
    name: str
    authorize_url: str
    token_url: str
    scope: str
    is_oidc: bool


GITHUB = Provider(
    id="github",
    name="GitHub",
    authorize_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",  # noqa: S106 - URL, not a secret
    scope="read:user user:email",
    is_oidc=False,
)
GITHUB_API = "https://api.github.com"

GOOGLE = Provider(
    id="google",
    name="Google",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",  # noqa: S106 - URL, not a secret
    scope="openid email profile",
    is_oidc=True,
)
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

PROVIDERS: dict[str, Provider] = {"github": GITHUB, "google": GOOGLE}


def client_credentials(settings: Settings, provider: Provider) -> tuple[str, str] | None:
    """(client_id, client_secret) if the provider is configured, else None."""
    if provider.id == "github":
        cid, secret = settings.github_client_id, settings.github_client_secret
    else:
        cid, secret = settings.google_client_id, settings.google_client_secret
    if not cid or secret is None:
        return None
    return cid, secret.get_secret_value()


def enabled_providers(settings: Settings) -> list[Provider]:
    return [p for p in PROVIDERS.values() if client_credentials(settings, p) is not None]


async def exchange_code(
    http: httpx.AsyncClient,
    provider: Provider,
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Authorization-code grant with the PKCE verifier (RFC 7636)."""
    resp = await http.post(
        provider.token_url,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": code_verifier,
        },
        headers={"Accept": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    try:
        token: dict[str, Any] = resp.json()
    except ValueError as exc:
        raise ProviderError("token_response_not_json") from exc
    # GitHub reports errors with HTTP 200 and an "error" field.
    if resp.status_code != httpx.codes.OK or "error" in token or "access_token" not in token:
        raise ProviderError(f"token_exchange_failed:{token.get('error', resp.status_code)}")
    return token


async def github_identity(http: httpx.AsyncClient, access_token: str) -> SocialIdentity:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    user_resp = await http.get(f"{GITHUB_API}/user", headers=headers, timeout=HTTP_TIMEOUT)
    emails_resp = await http.get(f"{GITHUB_API}/user/emails", headers=headers, timeout=HTTP_TIMEOUT)
    if user_resp.status_code != httpx.codes.OK or emails_resp.status_code != httpx.codes.OK:
        raise ProviderError("github_api_error")
    user = user_resp.json()
    # The profile email may be unverified or hidden; only trust the *primary verified* one.
    primary = next(
        (e for e in emails_resp.json() if e.get("primary") and e.get("verified")),
        None,
    )
    return SocialIdentity(
        provider="github",
        subject=str(user["id"]),  # numeric ID: stable even if the login is renamed
        email=primary["email"].lower() if primary else None,
        email_verified=primary is not None,
        display_name=user.get("name") or user.get("login"),
    )


async def _google_jwks(http: httpx.AsyncClient, redis: Redis, *, refresh: bool = False) -> KeySet:
    cache_key = "social:jwks:google"
    cached = None if refresh else await redis.get(cache_key)
    if cached is None:
        resp = await http.get(GOOGLE_JWKS_URL, timeout=HTTP_TIMEOUT)
        if resp.status_code != httpx.codes.OK:
            raise ProviderError("jwks_fetch_failed")
        cached = resp.content
        await redis.set(cache_key, cached, ex=JWKS_CACHE_SECONDS)
    return KeySet.import_key_set(json.loads(cached))


async def google_identity(
    http: httpx.AsyncClient,
    redis: Redis,
    token: dict[str, Any],
    *,
    client_id: str,
    nonce: str,
) -> SocialIdentity:
    """Validate the ID token: signature (Google's JWKS, RS256 only), issuer, audience,
    expiry and the nonce we generated for this flow (binds the token to this login)."""
    raw = token.get("id_token")
    if not isinstance(raw, str):
        raise ProviderError("missing_id_token")
    try:
        try:
            decoded = jwt.decode(raw, await _google_jwks(http, redis), algorithms=["RS256"])
        except JoseError:
            # Google rotates keys; refetch once in case the kid is new.
            decoded = jwt.decode(
                raw, await _google_jwks(http, redis, refresh=True), algorithms=["RS256"]
            )
        claims = decoded.claims
        jwt.JWTClaimsRegistry(
            now=int(time.time()),
            leeway=ID_TOKEN_LEEWAY_SECONDS,
            iss={"essential": True, "values": list(GOOGLE_ISSUERS)},
            aud={"essential": True, "value": client_id},
            exp={"essential": True},
            sub={"essential": True},
            nonce={"essential": True, "value": nonce},
        ).validate(claims)
    except (JoseError, ValueError) as exc:
        raise ProviderError(f"id_token_invalid:{type(exc).__name__}") from exc

    # If the token was issued to several audiences, `azp` must be us.
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != client_id:
        raise ProviderError("id_token_azp_mismatch")

    email = claims.get("email")
    return SocialIdentity(
        provider="google",
        subject=str(claims["sub"]),
        email=email.lower() if isinstance(email, str) else None,
        email_verified=claims.get("email_verified") is True,
        display_name=claims.get("name"),
    )
