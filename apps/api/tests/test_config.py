import base64

import pytest
from pydantic import ValidationError

from keygate.config import DEV_ENCRYPTION_KEY, Settings

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
        prod_settings(database_url=database_url, redis_url=redis_url)


PROD_SECRET = "q" * 48


def prod_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "database_url": PROD_DB,
        "redis_url": PROD_REDIS,
        "secret_key": PROD_SECRET,
        "public_url": "https://id.example.com",
        "webauthn_rp_id": "example.com",
        "webauthn_origins": ["https://id.example.com"],
        "encryption_keys": {"k1": base64.b64encode(b"k" * 32).decode()},
        "encryption_key_id": "k1",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_production_accepts_strong_configuration() -> None:
    s = prod_settings()
    assert s.is_production
    assert s.secure_cookies
    assert s.session_cookie_name == "__Host-kg_session"
    assert s.csrf_cookie_name == "__Host-kg_csrf"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"secret_key": "dev-only-insecure-secret-key-do-not-use-in-production"}, "SECRET_KEY"),
        ({"secret_key": "too-short"}, "SECRET_KEY"),
        ({"cookie_secure": False}, "Secure"),
        ({"public_url": "http://id.example.com"}, "https"),
        ({"webauthn_origins": ["http://id.example.com"]}, "https"),
        (
            {
                "encryption_keys": {"dev": DEV_ENCRYPTION_KEY},
                "encryption_key_id": "dev",
            },
            "development encryption key",
        ),
        ({"encryption_key_id": "missing"}, "must name a configured"),
        ({"encryption_keys": {"k1": base64.b64encode(b"short").decode()}}, "32 bytes"),
    ],
)
def test_production_rejects_insecure_settings(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        prod_settings(**overrides)


def test_development_uses_unprefixed_non_secure_cookies() -> None:
    s = Settings(environment="development")
    assert not s.secure_cookies
    assert s.session_cookie_name == "kg_session"


def test_development_allows_dev_credentials() -> None:
    s = Settings(
        environment="development",
        database_url="postgresql+asyncpg://keygate:keygate@localhost/keygate",  # type: ignore[arg-type]
    )
    assert not s.is_production


def test_reads_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYGATE_LOG_LEVEL", "DEBUG")
    assert Settings().log_level == "DEBUG"
