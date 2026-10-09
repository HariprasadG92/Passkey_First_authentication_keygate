"""ID tokens and JWT access tokens (RFC 9068 profile).

* ID token: for the client. ``aud`` = client_id, carries ``nonce``, ``auth_time``,
  ``at_hash`` and identity claims for the granted scopes.
* Access token: for resource servers. ``typ: at+jwt`` (so an ID token can't be replayed
  as an access token), ``aud`` = the issuer (userinfo) plus ``notes-api`` only when notes
  scopes were granted (audience restriction), ``scope``, ``client_id`` and a ``jti`` for
  revocation. Lifetime: 10 minutes.
"""

import base64
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from keygate.auth.models import User
from keygate.config import Settings
from keygate.oidc.keys import ALG
from keygate.oidc.scopes import NOTES_SCOPES

ACCESS_TOKEN_TYP = "at+jwt"  # noqa: S105 - a JWT "typ" value, not a secret


class TokenError(Exception):
    pass


def at_hash(access_token: str) -> str:
    """Left half of SHA-256 (the hash matching ES256), base64url: binds the ID token to
    the access token issued with it (OIDC Core §3.1.3.6)."""
    digest = hashlib.sha256(access_token.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


def access_token_audience(settings: Settings, scopes: list[str]) -> list[str]:
    audience = [settings.issuer]
    if NOTES_SCOPES.intersection(scopes):
        audience.append(settings.oidc_notes_audience)
    return audience


def user_claims(user: User, scopes: list[str]) -> dict[str, Any]:
    claims: dict[str, Any] = {}
    if "profile" in scopes:
        claims["name"] = user.display_name
    if "email" in scopes:
        claims["email"] = user.email
        claims["email_verified"] = user.email_verified
    return claims


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    id_token: str | None
    expires_in: int


def issue_tokens(
    settings: Settings,
    key: Any,
    *,
    user: User,
    client_id: str,
    scopes: list[str],
    auth_time: int,
    nonce: str | None,
    include_id_token: bool,
) -> IssuedTokens:
    now = int(time.time())
    header = {"alg": ALG, "kid": key.kid}
    access_token = jwt.encode(
        {**header, "typ": ACCESS_TOKEN_TYP},
        {
            "iss": settings.issuer,
            "sub": str(user.id),
            "aud": access_token_audience(settings, scopes),
            "client_id": client_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + settings.oidc_access_token_ttl_seconds,
            "jti": secrets.token_urlsafe(16),
            "auth_time": auth_time,
        },
        key,
    )
    id_token = None
    if include_id_token and "openid" in scopes:
        claims: dict[str, Any] = {
            "iss": settings.issuer,
            "sub": str(user.id),
            "aud": client_id,
            "azp": client_id,
            "iat": now,
            "exp": now + settings.oidc_id_token_ttl_seconds,
            "auth_time": auth_time,
            "at_hash": at_hash(access_token),
            **user_claims(user, scopes),
        }
        if nonce:
            claims["nonce"] = nonce
        id_token = jwt.encode({**header, "typ": "JWT"}, claims, key)
    return IssuedTokens(
        access_token=access_token,
        id_token=id_token,
        expires_in=settings.oidc_access_token_ttl_seconds,
    )


def verify_access_token(
    settings: Settings, keys: KeySet, token: str, *, audience: str
) -> dict[str, Any]:
    """Signature, typ, issuer, audience and expiry (no leeway: 10-minute tokens)."""
    try:
        decoded = jwt.decode(token, keys, algorithms=[ALG])
        if decoded.header.get("typ") != ACCESS_TOKEN_TYP:
            raise TokenError("not an access token")
        jwt.JWTClaimsRegistry(
            now=int(time.time()),
            iss={"essential": True, "value": settings.issuer},
            aud={"essential": True, "value": audience},
            exp={"essential": True},
            sub={"essential": True},
            jti={"essential": True},
        ).validate(decoded.claims)
    except (JoseError, ValueError) as exc:
        raise TokenError(type(exc).__name__) from exc
    claims: dict[str, Any] = decoded.claims
    uuid.UUID(claims["sub"])
    return claims


def verify_id_token_hint(settings: Settings, keys: KeySet, token: str) -> dict[str, Any] | None:
    """For RP-initiated logout: our signature and issuer, expiry ignored (a hint may be
    an expired ID token, per the spec). Returns None if invalid."""
    try:
        decoded = jwt.decode(token, keys, algorithms=[ALG])
        if decoded.header.get("typ") == ACCESS_TOKEN_TYP:
            return None
        jwt.JWTClaimsRegistry(
            iss={"essential": True, "value": settings.issuer},
            aud={"essential": True},
            sub={"essential": True},
        ).validate(decoded.claims)
    except (JoseError, ValueError):
        return None
    claims: dict[str, Any] = decoded.claims
    return claims
