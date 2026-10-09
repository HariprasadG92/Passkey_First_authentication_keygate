"""Application configuration, loaded from environment variables (prefix ``KEYGATE_``).

Secrets are typed as ``SecretStr`` so they are masked in ``repr()`` and never end up
in logs or tracebacks by accident.
"""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


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
    def _refuse_dev_defaults_in_production(self) -> Self:
        if self.is_production and "keygate:keygate@" in self.database_url.get_secret_value():
            raise ValueError("Default database credentials must not be used in production.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
