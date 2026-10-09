"""OpenID Connect provider: clients, consents, refresh tokens and signing keys."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from keygate.db.base import Base


class OAuthClient(Base):
    """A relying party. Confidential clients authenticate with a secret (stored only as
    SHA-256: it's 256 random bits, see ADR-009); public clients (SPAs, mobile) use PKCE
    alone. Every client must use PKCE regardless."""

    __tablename__ = "oauth_clients"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(100))
    client_secret_hash: Mapped[bytes | None]
    is_confidential: Mapped[bool] = mapped_column(Boolean)
    redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(Text))
    post_logout_redirect_uris: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    allowed_scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_by: Mapped[uuid.UUID | None]
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OAuthConsent(Base):
    """Scopes a user has approved for a client. Asking for more scopes re-prompts."""

    __tablename__ = "oauth_consents"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    client_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("oauth_clients.id", ondelete="CASCADE"), primary_key=True
    )
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OAuthRefreshToken(Base):
    """Rotating refresh token. Each use marks the token used and issues a successor in the
    same *family*. Presenting a used token again means it was copied: the whole family is
    revoked (RFC 6819 §5.2.2.3, OAuth 2.0 Security BCP)."""

    __tablename__ = "oauth_refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[bytes] = mapped_column(unique=True)
    family_id: Mapped[uuid.UUID]
    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("oauth_clients.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    auth_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    family_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_oauth_refresh_tokens_family_id", "family_id"),
        Index("ix_oauth_refresh_tokens_user_client", "user_id", "client_id"),
    )


class SigningKey(Base):
    """Asymmetric key for ID and access tokens. The private JWK is encrypted at rest.

    Lifecycle: *active* (signs new tokens; exactly one) -> *retired* (no longer signs,
    still published in JWKS so tokens it signed keep verifying) -> *removed* (unpublished
    once every token it signed has expired)."""

    __tablename__ = "oidc_signing_keys"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    alg: Mapped[str] = mapped_column(String(16))
    public_jwk: Mapped[str] = mapped_column(Text)
    encrypted_private_jwk: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
