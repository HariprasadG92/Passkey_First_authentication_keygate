"""Application configuration, loaded from environment variables (prefix ``KEYGATE_``).

Secrets are typed as ``SecretStr`` so they are masked in ``repr()`` and never end up
in logs or tracebacks by accident.
"""

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

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def docs_enabled(self) -> bool:
        """Interactive API docs are a development aid; they widen the attack surface in prod."""
        return not self.is_production

    @model_validator(mode="after")
    def _refuse_weak_credentials_in_production(self) -> Self:
        """Fail closed: a production deploy with copied dev credentials must not start."""
        if not self.is_production:
            return self
        for name, url in (("database", self.database_url), ("redis", self.redis_url)):
            password = _url_password(url.get_secret_value())
            if password in _KNOWN_DEV_PASSWORDS or len(password) < MIN_PRODUCTION_PASSWORD_LENGTH:
                raise ValueError(
                    f"Weak or development {name} credentials must not be used in production "
                    f"(use a unique password of at least {MIN_PRODUCTION_PASSWORD_LENGTH} chars)."
                )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
