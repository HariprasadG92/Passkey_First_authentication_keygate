"""Authorization requests, authorization codes and refresh tokens.

* **Authorization request**: a validated /authorize request waiting for consent, kept in
  Redis for 10 minutes and bound to the signed-in user who must approve it.
* **Authorization code**: 256 random bits; Redis key = its SHA-256; 60-second TTL;
  redeemed with GETDEL so it works exactly once. It is bound to the client, the exact
  redirect URI and the PKCE challenge. A redeemed code leaves a marker; presenting it
  again revokes every token issued from it (RFC 6749 §4.1.2).
* **Refresh token**: opaque, stored hashed, rotated on every use within a *family*;
  reusing an already-rotated token revokes the whole family.
"""

import base64
import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.oidc.models import OAuthRefreshToken
from keygate.security.tokens import generate_token, hash_token

AUTH_REQUEST_TTL = 600
SPENT_CODE_TTL = 600


@dataclass
class AuthorizationRequest:
    client_pk: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    state: str | None
    nonce: str | None
    code_challenge: str
    user_id: str
    auth_time: int


@dataclass
class CodeGrant:
    client_pk: str
    client_id: str
    redirect_uri: str
    scopes: list[str]
    nonce: str | None
    code_challenge: str
    user_id: str
    auth_time: int


def s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def pkce_matches(verifier: str, challenge: str) -> bool:
    # RFC 7636 §4.1: 43-128 chars from the unreserved set.
    if not 43 <= len(verifier) <= 128 or not all(c.isalnum() or c in "-._~" for c in verifier):
        return False
    return hmac.compare_digest(s256(verifier), challenge)


def _key(kind: str, value: str) -> str:
    return f"oauth:{kind}:{hashlib.sha256(value.encode()).hexdigest()}"


class GrantStore:
    def __init__(self, settings: Settings, redis: Redis) -> None:
        self._settings = settings
        self._redis = redis

    # ------------------------------------------------------ authorization requests

    async def save_request(self, request: AuthorizationRequest) -> str:
        request_id = secrets.token_urlsafe(32)
        await self._redis.set(
            _key("authreq", request_id), json.dumps(asdict(request)), ex=AUTH_REQUEST_TTL
        )
        return request_id

    async def load_request(self, request_id: str, *, consume: bool) -> AuthorizationRequest | None:
        key = _key("authreq", request_id)
        raw = await (self._redis.getdel(key) if consume else self._redis.get(key))
        return AuthorizationRequest(**json.loads(raw)) if raw else None

    # ------------------------------------------------------------------- codes

    async def issue_code(self, grant: CodeGrant) -> str:
        code = generate_token()
        await self._redis.set(
            _key("code", code), json.dumps(asdict(grant)), ex=self._settings.oidc_code_ttl_seconds
        )
        return code

    async def redeem_code(self, code: str) -> tuple[CodeGrant | None, str | None]:
        """Returns (grant, None) on first use, or (None, family_id) if this code was
        already redeemed (so the caller can revoke what it produced)."""
        raw = await self._redis.getdel(_key("code", code))
        if raw is not None:
            return CodeGrant(**json.loads(raw)), None
        spent = await self._redis.get(_key("spent", code))
        return None, (spent.decode() if isinstance(spent, bytes) else spent)

    async def mark_spent(self, code: str, family_id: uuid.UUID) -> None:
        await self._redis.set(_key("spent", code), str(family_id), ex=SPENT_CODE_TTL)

    # ------------------------------------------------- access-token revocation

    async def revoke_jti(self, jti: str, expires_at: int) -> None:
        ttl = max(1, expires_at - int(utcnow().timestamp()))
        await self._redis.set(f"oauth:revoked_jti:{jti}", "1", ex=ttl)

    async def is_jti_revoked(self, jti: str) -> bool:
        return bool(await self._redis.exists(f"oauth:revoked_jti:{jti}"))


class RefreshTokens:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def issue(
        self,
        db: AsyncSession,
        *,
        client_pk: uuid.UUID,
        user_id: uuid.UUID,
        scopes: list[str],
        auth_time: datetime,
        family_id: uuid.UUID | None = None,
        family_expires_at: datetime | None = None,
    ) -> tuple[str, OAuthRefreshToken]:
        now = utcnow()
        family_expires_at = family_expires_at or now + timedelta(
            days=self._settings.oidc_refresh_family_ttl_days
        )
        token = generate_token()
        row = OAuthRefreshToken(
            token_hash=hash_token(token),
            family_id=family_id or uuid.uuid4(),
            client_id=client_pk,
            user_id=user_id,
            scopes=scopes,
            auth_time=auth_time,
            expires_at=min(
                now + timedelta(days=self._settings.oidc_refresh_token_ttl_days), family_expires_at
            ),
            family_expires_at=family_expires_at,
        )
        db.add(row)
        await db.flush()
        return token, row

    async def find(self, db: AsyncSession, token: str) -> OAuthRefreshToken | None:
        return (
            await db.execute(
                select(OAuthRefreshToken)
                .where(OAuthRefreshToken.token_hash == hash_token(token))
                .with_for_update()
            )
        ).scalar_one_or_none()

    async def revoke_family(self, db: AsyncSession, family_id: uuid.UUID) -> int:
        result = await db.execute(
            update(OAuthRefreshToken)
            .where(OAuthRefreshToken.family_id == family_id, OAuthRefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        return int(result.rowcount)  # type: ignore[attr-defined]

    async def revoke_for(self, db: AsyncSession, user_id: uuid.UUID, client_pk: uuid.UUID) -> int:
        result = await db.execute(
            update(OAuthRefreshToken)
            .where(
                OAuthRefreshToken.user_id == user_id,
                OAuthRefreshToken.client_id == client_pk,
                OAuthRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )
        return int(result.rowcount)  # type: ignore[attr-defined]
