import pytest
from pydantic import ValidationError

from keygate.config import Settings

STRONG = "x7Qp2vLm9Zr4Tt8Wn3Kb"
PROD_DB = f"postgresql+asyncpg://keygate:{STRONG}@db:5432/keygate"
PROD_REDIS = f"redis://:{STRONG}@redis:6379/0"


def test_secrets_are_masked_in_repr() -> None:
    s = Settings(database_url="postgresql+asyncpg://u:topsecret@h/db")  # type: ignore[arg-type]
    assert "topsecret" not in repr(s)


@pytest.mark.parametrize(
    ("database_url", "redis_url"),
    [
        ("postgresql+asyncpg://keygate:keygate@db/keygate", PROD_REDIS),
        ("postgresql+asyncpg://keygate:keygate-dev-only@db/keygate", PROD_REDIS),
        ("postgresql+asyncpg://keygate:short@db/keygate", PROD_REDIS),
        ("postgresql+asyncpg://keygate@db/keygate", PROD_REDIS),
        (PROD_DB, "redis://redis:6379/0"),
        (PROD_DB, "redis://:keygate-dev-only@redis:6379/0"),
    ],
)
def test_production_rejects_weak_credentials(database_url: str, redis_url: str) -> None:
    with pytest.raises(ValidationError, match="must not be used in production"):
        Settings(
            environment="production",
            database_url=database_url,  # type: ignore[arg-type]
            redis_url=redis_url,  # type: ignore[arg-type]
        )


def test_production_accepts_strong_credentials() -> None:
    s = Settings(
        environment="production",
        database_url=PROD_DB,  # type: ignore[arg-type]
        redis_url=PROD_REDIS,  # type: ignore[arg-type]
    )
    assert s.is_production


def test_development_allows_dev_credentials() -> None:
    s = Settings(
        environment="development",
        database_url="postgresql+asyncpg://keygate:keygate@localhost/keygate",  # type: ignore[arg-type]
    )
    assert not s.is_production


def test_reads_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYGATE_LOG_LEVEL", "DEBUG")
    assert Settings().log_level == "DEBUG"
