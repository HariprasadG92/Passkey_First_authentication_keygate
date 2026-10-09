"""TOTP (RFC 6238) authenticator apps as a fallback sign-in factor.

* Secrets are 160-bit (RFC 4226 recommendation), encrypted at rest with AES-256-GCM and
  bound to the user ID as associated data.
* Codes are accepted for the current 30-second step and one step either side (clock
  drift), compared in constant time.
* **Replay protection**: the matched step must be greater than ``last_used_step``. The
  check-and-set is one conditional UPDATE, so two concurrent requests with the same code
  can't both succeed.
"""

import hmac
import re
import time
import uuid
from dataclasses import dataclass

import pyotp
import segno
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.auth.models import User
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.mfa.models import TotpCredential
from keygate.security.crypto import Encryptor

SECRET_BYTES = 20  # 160 bits
WINDOW = 1  # accept +/- one 30-second step
CODE_RE = re.compile(r"^\d{6}$")


class TotpError(Exception):
    pass


@dataclass(frozen=True)
class Enrolment:
    secret: str
    otpauth_uri: str
    qr_svg_data_uri: str


def _aad(user_id: uuid.UUID) -> bytes:
    return b"totp:" + user_id.bytes


def matching_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Return the time step ``code`` is valid for (within the window), else None."""
    if not CODE_RE.fullmatch(code):
        return None
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // totp.interval)
    match = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        # Check every step (no early exit) so timing doesn't reveal which one matched.
        if hmac.compare_digest(totp.generate_otp(step), code):
            match = step
    return match


class TotpService:
    def __init__(self, settings: Settings, encryptor: Encryptor) -> None:
        self._settings = settings
        self._encryptor = encryptor

    async def get(self, db: AsyncSession, user_id: uuid.UUID) -> TotpCredential | None:
        return await db.get(TotpCredential, user_id)

    async def is_enabled(self, db: AsyncSession, user_id: uuid.UUID) -> bool:
        row = await self.get(db, user_id)
        return row is not None and row.confirmed_at is not None

    async def begin_enrolment(self, db: AsyncSession, user: User) -> Enrolment:
        row = await self.get(db, user.id)
        if row is not None and row.confirmed_at is not None:
            raise TotpError("already_enabled")
        secret = pyotp.random_base32(length=32)  # 32 base32 chars = 160 bits
        encrypted = self._encryptor.encrypt(secret.encode(), _aad(user.id))
        if row is None:
            db.add(TotpCredential(user_id=user.id, encrypted_secret=encrypted))
        else:  # replace an abandoned, unconfirmed enrolment
            row.encrypted_secret = encrypted
            row.last_used_step = None
        await db.flush()

        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name=self._settings.totp_issuer
        )
        qr = segno.make(uri, error="m").svg_data_uri(scale=5, border=2)
        return Enrolment(secret=secret, otpauth_uri=uri, qr_svg_data_uri=qr)

    async def _accept(self, db: AsyncSession, row: TotpCredential, code: str) -> bool:
        secret = self._encryptor.decrypt(row.encrypted_secret, _aad(row.user_id))
        step = matching_step(secret.decode(), code)
        if step is None:
            return False
        claimed = await db.execute(
            update(TotpCredential)
            .where(
                TotpCredential.user_id == row.user_id,
                (TotpCredential.last_used_step.is_(None)) | (TotpCredential.last_used_step < step),
            )
            .values(last_used_step=step)
        )
        return int(claimed.rowcount) == 1  # type: ignore[attr-defined]

    async def confirm_enrolment(self, db: AsyncSession, user: User, code: str) -> None:
        row = await self.get(db, user.id)
        if row is None or row.confirmed_at is not None:
            raise TotpError("no_pending_enrolment")
        if not await self._accept(db, row, code):
            raise TotpError("invalid_code")
        row.confirmed_at = utcnow()

    async def verify(self, db: AsyncSession, user_id: uuid.UUID, code: str) -> bool:
        """Verify a sign-in/step-up code for a user with *confirmed* TOTP."""
        row = (
            await db.execute(
                select(TotpCredential).where(
                    TotpCredential.user_id == user_id, TotpCredential.confirmed_at.is_not(None)
                )
            )
        ).scalar_one_or_none()
        return row is not None and await self._accept(db, row, code)

    async def disable(self, db: AsyncSession, user_id: uuid.UUID) -> None:
        row = await self.get(db, user_id)
        if row is not None:
            await db.delete(row)
