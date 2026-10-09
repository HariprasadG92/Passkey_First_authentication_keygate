"""Accounts, passkeys, email tokens and sessions."""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from keygate.db.base import Base


class UserStatus(enum.StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class SessionLevel(enum.StrEnum):
    # Issued after email verification; may only register the account's first passkey.
    REGISTRATION = "registration"
    # A fully authenticated session (passkey sign-in or first passkey registered).
    FULL = "full"


class EmailTokenPurpose(enum.StrEnum):
    SIGNUP = "signup"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    # Stored normalised (trimmed, lower-cased) so uniqueness is case-insensitive.
    email: Mapped[str] = mapped_column(String(320), unique=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    display_name: Mapped[str] = mapped_column(String(100))
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, name="user_status", values_callable=lambda e: [m.value for m in e]),
        default=UserStatus.ACTIVE,
    )
    # WebAuthn user handle: random, opaque, never the primary key or email, so an
    # authenticator's stored data reveals nothing about the account.
    webauthn_user_handle: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    credentials: Mapped[list["WebAuthnCredential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (CheckConstraint("email = lower(email)", name="email_lowercase"),)


class WebAuthnCredential(Base):
    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(1023), unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    transports: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    aaguid: Mapped[str] = mapped_column(String(36))
    backup_eligible: Mapped[bool] = mapped_column(Boolean)
    backup_state: Mapped[bool] = mapped_column(Boolean)
    friendly_name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="credentials")

    __table_args__ = (Index("ix_webauthn_credentials_user_id", "user_id"),)


class EmailToken(Base):
    """Single-use magic-link token. Only a SHA-256 hash of the token is stored."""

    __tablename__ = "email_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    email: Mapped[str] = mapped_column(String(320))
    purpose: Mapped[EmailTokenPurpose] = mapped_column(
        Enum(
            EmailTokenPurpose,
            name="email_token_purpose",
            values_callable=lambda e: [m.value for m in e],
        )
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_email_tokens_email", "email"),)


class Session(Base):
    """Server-side session. The cookie holds a random token; only its SHA-256 is stored,
    so a database leak does not yield usable session cookies."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary(32), unique=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    level: Mapped[SessionLevel] = mapped_column(
        Enum(SessionLevel, name="session_level", values_callable=lambda e: [m.value for m in e])
    )
    auth_method: Mapped[str] = mapped_column(String(32))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship()

    __table_args__ = (Index("ix_sessions_user_id", "user_id"),)
