"""Application configuration, loaded from environment variables (prefix ``KEYGATE_``).

Secrets are typed as ``SecretStr`` so they are masked in ``repr()`` and never end up
in logs or tracebacks by accident.
"""

import base64
from datetime import timedelta
from functools import lru_cache
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Passwords that ship in defaults or .env.example. Production must never run with them.
_KNOWN_DEV_PASSWORDS = frozenset(
    {"", "keygate", "keygate-dev-only", "postgres", "password", "change-me", "changeme"}
)
MIN_PRODUCTION_PASSWORD_LENGTH = 16
MIN_SECRET_KEY_LENGTH = 32
AES_KEY_BYTES = 32
DEV_SECRET_KEY = "dev-only-insecure-secret-key-do-not-use-in-production"  # noqa: S105 - rejected in prod
# Derived from a public, obviously-fake string: usable in dev, rejected in production.
DEV_ENCRYPTION_KEY = base64.b64encode(b"dev-only-insecure-encryption-key").decode()


def _url_password(url: str) -> str:
    return urlsplit(url).password or ""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KEYGATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    app_name: str = "Keygate"
    environment: Environment = "development"
    log_level: LogLevel = "INFO"
    log_json: bool = Field(
        default=True,
        description="Emit JSON logs. Set to false for human-readable console logs in dev.",
    )

    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://keygate:keygate@localhost:5432/keygate"
    )
    redis_url: SecretStr = SecretStr("redis://localhost:6379/0")

    # Server-side secret for HMACs (CSRF tokens, decoy credential IDs). Never sent to clients.
    secret_key: SecretStr = SecretStr(DEV_SECRET_KEY)

    # AES-256-GCM keys for data encrypted at rest (TOTP secrets), by key ID. New data is
    # encrypted with ``encryption_key_id``; old IDs stay listed so existing data can still
    # be decrypted during a key rotation.
    encryption_keys: dict[str, SecretStr] = {"dev": SecretStr(DEV_ENCRYPTION_KEY)}
    encryption_key_id: str = "dev"

    # Public origin of the Keygate UI. Used to build links in emails.
    public_url: str = "http://localhost"

    # --- WebAuthn ---------------------------------------------------------------
    # The RP ID is the registrable domain credentials are scoped to; origins are the
    # exact page origins allowed to run ceremonies (scheme + host + port).
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Keygate"
    webauthn_origins: list[str] = ["http://localhost"]
    webauthn_challenge_ttl_seconds: int = Field(default=300, ge=30, le=600)

    # --- Sessions ---------------------------------------------------------------
    session_idle_timeout_minutes: int = Field(default=30, ge=1)
    session_absolute_timeout_hours: int = Field(default=12, ge=1)
    registration_session_minutes: int = Field(default=15, ge=1, le=60)
    # None = secure cookies in production only. Secure cookies get the __Host- prefix.
    cookie_secure: bool | None = None
    # Sensitive actions need a sign-in or re-authentication at most this long ago.
    step_up_ttl_minutes: int = Field(default=5, ge=1, le=30)

    # --- MFA --------------------------------------------------------------------
    totp_issuer: str = "Keygate"

    # --- Email ------------------------------------------------------------------
    magic_link_ttl_minutes: int = Field(default=15, ge=1, le=60)
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_starttls: bool = False
    smtp_from: str = "Keygate <no-reply@keygate.localhost>"

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are a development aid; they widen the attack surface in prod."""
        return not self.is_production

    @property
    def secure_cookies(self) -> bool:
        return self.is_production if self.cookie_secure is None else self.cookie_secure

    @property
    def session_cookie_name(self) -> str:
        # __Host- forces Secure, Path=/ and no Domain: the cookie can't be set or
        # overwritten by a sibling subdomain.
        return "__Host-kg_session" if self.secure_cookies else "kg_session"

    @property
    def csrf_cookie_name(self) -> str:
        return "__Host-kg_csrf" if self.secure_cookies else "kg_csrf"

    @property
    def step_up_ttl(self) -> timedelta:
        return timedelta(minutes=self.step_up_ttl_minutes)

    @property
    def session_idle_timeout(self) -> timedelta:
        return timedelta(minutes=self.session_idle_timeout_minutes)

    @property
    def session_absolute_timeout(self) -> timedelta:
        return timedelta(hours=self.session_absolute_timeout_hours)

    @model_validator(mode="after")
    def _validate_encryption_keys(self) -> Self:
        if self.encryption_key_id not in self.encryption_keys:
            raise ValueError("KEYGATE_ENCRYPTION_KEY_ID must name a configured encryption key.")
        for key_id, key in self.encryption_keys.items():
            try:
                raw = base64.b64decode(key.get_secret_value(), validate=True)
            except ValueError as exc:
                raise ValueError(f"Encryption key {key_id!r} is not valid base64.") from exc
            if len(raw) != AES_KEY_BYTES:
                raise ValueError(f"Encryption key {key_id!r} must decode to 32 bytes (AES-256).")
        return self

    @model_validator(mode="after")
    def _refuse_weak_configuration_in_production(self) -> Self:
        """Fail closed: a production deploy with copied dev settings must not start."""
        if not self.is_production:
            return self
        for name, url in (("database", self.database_url), ("redis", self.redis_url)):
            password = _url_password(url.get_secret_value())
            if password in _KNOWN_DEV_PASSWORDS or len(password) < MIN_PRODUCTION_PASSWORD_LENGTH:
                raise ValueError(
                    f"Weak or development {name} credentials must not be used in production "
                    f"(use a unique password of at least {MIN_PRODUCTION_PASSWORD_LENGTH} chars)."
                )
        secret = self.secret_key.get_secret_value()
        if secret == DEV_SECRET_KEY or len(secret) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(
                f"KEYGATE_SECRET_KEY must be a unique random value of at least "
                f"{MIN_SECRET_KEY_LENGTH} chars in production."
            )
        if not self.secure_cookies:
            raise ValueError("Cookies must be Secure in production.")
        if any(k.get_secret_value() == DEV_ENCRYPTION_KEY for k in self.encryption_keys.values()):
            raise ValueError("The development encryption key must not be used in production.")
        insecure = [
            o for o in [self.public_url, *self.webauthn_origins] if urlsplit(o).scheme != "https"
        ]
        if insecure:
            raise ValueError(f"Production origins must use https: {insecure}")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
