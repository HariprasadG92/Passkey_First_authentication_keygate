"""Single-use recovery codes.

* 10 codes of 10 characters from a 31-symbol alphabet without look-alikes
  (no 0/O, 1/I/L): about 49.5 bits each, shown to the user exactly once.
* Stored as Argon2id hashes (RFC 9106 low-memory profile). Even with a database dump an
  attacker must brute-force each code against a memory-hard function, while online
  guessing is stopped by rate limits long before 2^49.
* Regenerating deletes every previous code.
* Hashing is CPU- and memory-heavy, so it runs in a worker thread to keep the event loop
  responsive.
"""

import asyncio
import secrets
import uuid
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.db.types import utcnow
from keygate.mfa.models import RecoveryCode

CODE_COUNT = 10
CODE_LENGTH = 10
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"  # 31 symbols: no 0/O, 1/I/L
_hasher = PasswordHasher()  # Argon2id, t=3, m=64 MiB, p=4


def generate_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))
    return f"{raw[:5]}-{raw[5:]}"


def normalize_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return _hasher.hash("dummy-recovery-code")


def _verify(code_hash: str, code: str) -> bool:
    try:
        return _hasher.verify(code_hash, code)
    except (VerificationError, InvalidHashError):
        return False


async def regenerate(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    codes = [generate_code() for _ in range(CODE_COUNT)]
    hashes = await asyncio.gather(
        *(asyncio.to_thread(_hasher.hash, normalize_code(c)) for c in codes)
    )
    await db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    db.add_all(RecoveryCode(user_id=user_id, code_hash=h) for h in hashes)
    await db.flush()
    return codes


async def remaining(db: AsyncSession, user_id: uuid.UUID) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(RecoveryCode)
            .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        )
    ).scalar_one()


async def consume(db: AsyncSession, user_id: uuid.UUID | None, code: str) -> bool:
    """Spend a code. Rows are locked so the same code can't be used twice concurrently.
    With no user (unknown email) a dummy hash is checked so timing is similar."""
    candidate = normalize_code(code)
    if user_id is None:
        await asyncio.to_thread(_verify, _dummy_hash(), candidate)
        return False
    rows = list(
        (
            await db.execute(
                select(RecoveryCode)
                .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
                .with_for_update()
            )
        ).scalars()
    )
    if not rows:
        await asyncio.to_thread(_verify, _dummy_hash(), candidate)
        return False
    for row in rows:
        if await asyncio.to_thread(_verify, row.code_hash, candidate):
            row.used_at = utcnow()
            await db.flush()
            return True
    return False
