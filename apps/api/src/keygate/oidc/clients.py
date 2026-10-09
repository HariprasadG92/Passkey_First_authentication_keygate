"""Client lookup, authentication and registration."""

import base64
import hmac
import secrets
import uuid
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.oidc.models import OAuthClient
from keygate.security.tokens import hash_token


class ClientAuthError(Exception):
    pass


@dataclass(frozen=True)
class NewClientSecret:
    client: OAuthClient
    secret: str | None


async def get_client(db: AsyncSession, client_id: str | None) -> OAuthClient | None:
    if not client_id or len(client_id) > 64:
        return None
    client = (
        await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    ).scalar_one_or_none()
    if client is None or client.disabled_at is not None:
        return None
    return client


def redirect_uri_allowed(client: OAuthClient, redirect_uri: str | None) -> bool:
    """Exact string match against registered URIs: no wildcards, no prefix matching, no
    normalisation, so there's nothing for an attacker to bend (RFC 9700 §4.1)."""
    return redirect_uri is not None and redirect_uri in client.redirect_uris


def validate_redirect_uri(uri: str) -> str | None:
    """Registration-time checks. Returns an error message or None."""
    parts = urlsplit(uri)
    if parts.scheme not in ("https", "http"):
        return "Redirect URIs must use https (or http for loopback development)."
    if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "[::1]", "::1"):
        return "Plain http is only allowed for loopback addresses."
    if parts.fragment:
        return "Redirect URIs must not contain a fragment."
    if not parts.hostname:
        return "Redirect URI is missing a host."
    return None


def _basic_credentials(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "basic" or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode()
    except (ValueError, UnicodeDecodeError):
        return None
    cid, sep, secret = decoded.partition(":")
    if not sep:
        return None
    # RFC 6749 §2.3.1: both parts are form-urlencoded before base64.
    return unquote(cid), unquote(secret)


async def authenticate_client(
    db: AsyncSession, request: Request, form: dict[str, str]
) -> OAuthClient:
    """client_secret_basic, client_secret_post, or none (public clients)."""
    basic = _basic_credentials(request)
    if basic is not None:
        client_id, secret = basic
        if form.get("client_id") and form["client_id"] != client_id:
            raise ClientAuthError("client_id mismatch")
    else:
        client_id, secret = form.get("client_id", ""), form.get("client_secret", "")

    client = await get_client(db, client_id)
    if client is None:
        raise ClientAuthError("unknown client")
    if client.is_confidential:
        expected = client.client_secret_hash or b""
        if not secret or not hmac.compare_digest(hash_token(secret), expected):
            raise ClientAuthError("bad secret")
    elif secret:
        raise ClientAuthError("public clients must not send a secret")
    return client


def new_client_id() -> str:
    return "kg_" + secrets.token_urlsafe(18)


def new_client_secret() -> str:
    return secrets.token_urlsafe(32)


def build_client(
    *,
    name: str,
    confidential: bool,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str],
    allowed_scopes: list[str],
    created_by: uuid.UUID | None,
    client_id: str | None = None,
    secret: str | None = None,
) -> NewClientSecret:
    secret = (secret or new_client_secret()) if confidential else None
    client = OAuthClient(
        client_id=client_id or new_client_id(),
        name=name,
        is_confidential=confidential,
        client_secret_hash=hash_token(secret) if secret else None,
        redirect_uris=redirect_uris,
        post_logout_redirect_uris=post_logout_redirect_uris,
        allowed_scopes=allowed_scopes,
        created_by=created_by,
    )
    return NewClientSecret(client=client, secret=secret)
