"""Sign-up via email magic link.

Flow: ``start_signup`` emails a single-use link -> the user opens it and confirms ->
``consume_signup_token`` marks the email verified and the caller issues a short-lived
*registration* session that can only enrol the first passkey.

Enumeration resistance: ``start_signup`` behaves identically from the caller's point of
view for new and existing addresses. Existing accounts receive a "you already have an
account" notice instead of a link, so email can never be used to bypass a passkey.
"""

import secrets
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.auth.email import OutgoingEmail
from keygate.auth.models import EmailToken, EmailTokenPurpose, User, WebAuthnCredential
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.rbac.service import assign_default_role
from keygate.security.tokens import generate_token, hash_token

WEBAUTHN_USER_HANDLE_BYTES = 32


class InvalidTokenError(Exception):
    """The link is unknown, expired, already used, or no longer applicable."""


def normalize_email(email: str) -> str:
    return email.strip().lower()


def default_display_name(email: str) -> str:
    return email.split("@", 1)[0][:100]


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    return (
        await db.execute(select(User).where(User.email == normalize_email(email)))
    ).scalar_one_or_none()


async def credential_count(db: AsyncSession, user: User) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user.id)
        )
    ).scalar_one()


async def start_signup(db: AsyncSession, settings: Settings, email: str) -> OutgoingEmail:
    """Prepare the email for a sign-up request. The caller sends it in the background so
    response timing doesn't reveal which branch was taken."""
    email = normalize_email(email)
    user = await get_user_by_email(db, email)

    if user is not None and await credential_count(db, user) > 0:
        return OutgoingEmail(
            to=email,
            subject="Sign-in attempt for your Keygate account",
            text=(
                "Someone (hopefully you) tried to create a Keygate account with this email.\n\n"
                "You already have an account. Sign in with your passkey at "
                f"{settings.public_url}/signin\n\n"
                "If this wasn't you, you can ignore this email; nothing has changed."
            ),
        )

    # Only the newest link is valid: invalidate any outstanding ones for this address.
    await db.execute(
        update(EmailToken)
        .where(
            EmailToken.email == email,
            EmailToken.purpose == EmailTokenPurpose.SIGNUP,
            EmailToken.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    token = generate_token()
    db.add(
        EmailToken(
            token_hash=hash_token(token),
            email=email,
            purpose=EmailTokenPurpose.SIGNUP,
            expires_at=utcnow() + timedelta(minutes=settings.magic_link_ttl_minutes),
        )
    )
    await db.commit()

    # The token travels in the URL fragment: browsers never send fragments to servers,
    # so it can't end up in access logs, proxies or Referer headers.
    link = f"{settings.public_url}/verify-email#token={token}"
    return OutgoingEmail(
        to=email,
        subject="Confirm your email for Keygate",
        text=(
            "Confirm your email address to finish creating your Keygate account:\n\n"
            f"{link}\n\n"
            f"This link expires in {settings.magic_link_ttl_minutes} minutes and works once.\n"
            "If you didn't ask for this, ignore this email."
        ),
    )


async def consume_signup_token(db: AsyncSession, token: str) -> User:
    """Atomically mark the token used and return the (possibly new) verified user."""
    now = utcnow()
    row = (
        await db.execute(
            update(EmailToken)
            .where(
                EmailToken.token_hash == hash_token(token),
                EmailToken.purpose == EmailTokenPurpose.SIGNUP,
                EmailToken.used_at.is_(None),
                EmailToken.expires_at > now,
            )
            .values(used_at=now)
            .returning(EmailToken.email)
        )
    ).first()
    if row is None:
        await db.rollback()
        raise InvalidTokenError

    email: str = row[0]
    user = await get_user_by_email(db, email)
    if user is None:
        user = User(
            email=email,
            email_verified=True,
            display_name=default_display_name(email),
            webauthn_user_handle=secrets.token_bytes(WEBAUTHN_USER_HANDLE_BYTES),
        )
        db.add(user)
        await db.flush()
        await assign_default_role(db, user.id)
    elif await credential_count(db, user) > 0:
        # A passkey was registered after this link was sent: email alone must never
        # grant access to an account that has a passkey.
        await db.rollback()
        raise InvalidTokenError
    else:
        user.email_verified = True
    await db.flush()
    return user
