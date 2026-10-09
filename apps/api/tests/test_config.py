import pytest
from pydantic import ValidationError

from keygate.config import Settings


def test_secrets_are_masked_in_repr() -> None:
    s = Settings(database_url="postgresql+asyncpg://u:topsecret@h/db")  # type: ignore[arg-type]
    assert "topsecret" not in repr(s)


def test_production_rejects_default_database_credentials() -> None:
    with pytest.raises(ValidationError, match="Default database credentials"):
        Settings(environment="production")


def test_reads_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYGATE_LOG_LEVEL", "DEBUG")
    assert Settings().log_level == "DEBUG"
