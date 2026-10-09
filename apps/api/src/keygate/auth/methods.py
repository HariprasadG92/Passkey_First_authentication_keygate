"""Sign-in methods and last-method protection (ADR-022).

Sign-in methods are passkeys, a confirmed authenticator app and linked social accounts.
Recovery codes are a one-shot way back in, not a method.
"""

import uuid

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.auth.models import User, WebAuthnCredential
from keygate.errors import KeygateError
from keygate.mfa.models import TotpCredential
from keygate.social.models import SocialAccount


async def lock_user(db: AsyncSession, user_id: uuid.UUID) -> User:
    """Row-lock the user so concurrent changes to sign-in methods are serialised."""
    return (await db.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()


async def count_sign_in_methods(db: AsyncSession, user_id: uuid.UUID) -> int:
    passkeys = (
        await db.execute(
            select(func.count())
            .select_from(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user_id)
        )
    ).scalar_one()
    totp = (
        await db.execute(
            select(func.count())
            .select_from(TotpCredential)
            .where(TotpCredential.user_id == user_id, TotpCredential.confirmed_at.is_not(None))
        )
    ).scalar_one()
    social = (
        await db.execute(
            select(func.count()).select_from(SocialAccount).where(SocialAccount.user_id == user_id)
        )
    ).scalar_one()
    return int(passkeys + totp + social)


def last_method_error() -> KeygateError:
    return KeygateError(
        status.HTTP_409_CONFLICT,
        "last_sign_in_method",
        "You can't remove your only way to sign in. Add another passkey or sign-in method first.",
    )
