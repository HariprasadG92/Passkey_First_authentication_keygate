"""Signing-key management and JWKS publication (see ``SigningKey``).

ES256 (ECDSA P-256): short signatures, fast, and supported by every mainstream OIDC
client library. Private keys are encrypted at rest with the app's AES-GCM keys, bound to
the key ID.
"""

import json
import secrets
from datetime import timedelta

from joserfc.jwk import ECKey, KeySet
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.db.types import utcnow
from keygate.oidc.models import SigningKey
from keygate.security.crypto import Encryptor

ALG = "ES256"


def _aad(kid: str) -> bytes:
    return b"oidc-signing-key:" + kid.encode()


class KeyStore:
    def __init__(self, encryptor: Encryptor) -> None:
        self._encryptor = encryptor

    async def _create(self, db: AsyncSession) -> SigningKey:
        kid = secrets.token_urlsafe(12)
        key = ECKey.generate_key("P-256", parameters={"kid": kid, "use": "sig", "alg": ALG})
        row = SigningKey(
            kid=kid,
            alg=ALG,
            public_jwk=json.dumps(key.as_dict(private=False)),
            encrypted_private_jwk=self._encryptor.encrypt(
                json.dumps(key.as_dict(private=True)).encode(), _aad(kid)
            ),
        )
        db.add(row)
        await db.flush()
        return row

    async def active_key(self, db: AsyncSession) -> ECKey:
        """The key that signs new tokens; created on first use. Callers commit."""
        row = (
            await db.execute(
                select(SigningKey)
                .where(SigningKey.retired_at.is_(None), SigningKey.removed_at.is_(None))
                .order_by(SigningKey.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if row is None:
            row = await self._create(db)
        private = self._encryptor.decrypt(row.encrypted_private_jwk, _aad(row.kid))
        return ECKey.import_key(json.loads(private))

    async def published(self, db: AsyncSession) -> KeySet:
        """Every key a still-valid token might be signed with (active + retired)."""
        rows = (
            await db.execute(select(SigningKey).where(SigningKey.removed_at.is_(None)))
        ).scalars()
        return KeySet([ECKey.import_key(json.loads(r.public_jwk)) for r in rows])

    async def rotate(self, db: AsyncSession) -> str:
        """Retire the active key and start signing with a new one. The retired key stays
        in JWKS, so tokens it signed keep verifying until they expire."""
        await db.execute(
            update(SigningKey)
            .where(SigningKey.retired_at.is_(None), SigningKey.removed_at.is_(None))
            .values(retired_at=utcnow())
        )
        row = await self._create(db)
        return row.kid

    async def remove_retired(self, db: AsyncSession, older_than: timedelta) -> int:
        """Unpublish keys retired longer ago than the longest token lifetime."""
        result = await db.execute(
            update(SigningKey)
            .where(
                SigningKey.retired_at.is_not(None),
                SigningKey.removed_at.is_(None),
                SigningKey.retired_at < utcnow() - older_than,
            )
            .values(removed_at=utcnow())
        )
        return int(result.rowcount)  # type: ignore[attr-defined]
