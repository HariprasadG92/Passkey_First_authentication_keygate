"""Shared fixtures.

Integration tests run against real Postgres and Redis (from docker compose / CI service
containers) but never touch development data:

* Postgres: a separate ``<db>_test`` database, rebuilt with Alembic migrations once per
  test session (so the migrations themselves are tested) and truncated between tests.
* Redis: logical database 15, flushed between tests.
"""

import asyncio
import os
import re
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import asyncpg
import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from keygate.auth.email import InMemoryMailer
from keygate.config import Settings
from keygate.main import create_app

API_DIR = Path(__file__).resolve().parents[1]
TEST_SECRET = "test-secret-key-0123456789abcdefghijklmnopqrstuvwxyz"  # noqa: S105
ORIGIN = "http://localhost"

_BASE_DB = os.environ.get(
    "KEYGATE_DATABASE_URL", "postgresql+asyncpg://keygate:keygate@127.0.0.1:5432/keygate"
)
_BASE_REDIS = os.environ.get("KEYGATE_REDIS_URL", "redis://127.0.0.1:6379/0")

TEST_DB_URL = make_url(_BASE_DB).set(database=f"{make_url(_BASE_DB).database}_test")
TEST_REDIS_URL = re.sub(r"/\d+$", "", _BASE_REDIS) + "/15"

TABLES = [
    "audit_events",
    "email_tokens",
    "sessions",
    "webauthn_credentials",
    "totp_credentials",
    "recovery_codes",
    "social_accounts",
    "users",
]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "integration: needs the real Postgres and Redis from docker compose"
    )


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "database_url": TEST_DB_URL.render_as_string(hide_password=False),
        "redis_url": TEST_REDIS_URL,
        "secret_key": TEST_SECRET,
        "public_url": ORIGIN,
        "webauthn_rp_id": "localhost",
        "webauthn_origins": [ORIGIN],
        "github_client_id": "gh-client",
        "github_client_secret": "gh-secret",
        "google_client_id": "google-client.apps.googleusercontent.com",
        "google_client_secret": "google-secret",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def unreachable_settings() -> Settings:
    """Settings pointing at a closed port, to exercise dependency-failure paths."""
    return make_settings(
        database_url="postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none",
        redis_url="redis://127.0.0.1:1/0",
    )


# ----------------------------------------------------------------- database / redis


async def _ensure_database() -> None:
    url = TEST_DB_URL
    conn = await asyncpg.connect(
        host=url.host,
        port=url.port,
        user=url.username,
        password=url.password,
        database=make_url(_BASE_DB).database,
    )
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", url.database)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{url.database}"')
    finally:
        await conn.close()


def _migrate(url: str) -> None:
    cfg = Config()  # no ini file: don't let alembic reconfigure logging
    cfg.set_main_option("script_location", str(API_DIR / "src/keygate/db/migrations"))
    cfg.attributes["database_url"] = url
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
async def migrated_database() -> str:
    await _ensure_database()
    url = TEST_DB_URL.render_as_string(hide_password=False)
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.exec_driver_sql("DROP SCHEMA public CASCADE")
        await conn.exec_driver_sql("CREATE SCHEMA public")
    await engine.dispose()
    await asyncio.to_thread(_migrate, url)
    return url


@pytest.fixture
async def db_sessionmaker(
    migrated_database: str,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_async_engine(migrated_database)
    async with engine.begin() as conn:
        await conn.exec_driver_sql(f"TRUNCATE {', '.join(TABLES)} CASCADE")
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def redis() -> AsyncIterator[Redis]:
    client: Redis = Redis.from_url(TEST_REDIS_URL)
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


# ----------------------------------------------------------------------- app/client


@pytest.fixture
def mailer() -> InMemoryMailer:
    return InMemoryMailer()


async def _client_for(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url=ORIGIN,
        ) as client,
    ):
        yield client


def _attach_csrf(client: httpx.AsyncClient, cookie_name: str = "kg_csrf") -> None:
    """Behave like the real frontend: echo the CSRF cookie in a header on every request."""

    async def add_header(request: httpx.Request) -> None:
        token = client.cookies.get(cookie_name)
        if token and "X-CSRF-Token" not in request.headers:
            request.headers["X-CSRF-Token"] = token

    client.event_hooks["request"].append(add_header)


@pytest.fixture
async def app(
    settings: Settings,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    redis: Redis,
) -> FastAPI:
    return create_app(settings, mailer=mailer)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client_for(app):
        _attach_csrf(c)
        await c.get("/auth/session")  # obtain an anonymous CSRF token
        yield c


@pytest.fixture
async def raw_client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """A client that does *not* add CSRF headers, for testing the protection itself."""
    async for c in _client_for(app):
        yield c


@pytest.fixture
async def second_client(
    app: FastAPI, client: httpx.AsyncClient
) -> AsyncIterator[httpx.AsyncClient]:
    """Another browser for the same app (shares the app's lifespan via ``client``)."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url=ORIGIN
    ) as other:
        _attach_csrf(other)
        await other.get("/auth/session")
        yield other


@pytest.fixture
def make_client() -> Callable[[FastAPI], AsyncIterator[httpx.AsyncClient]]:
    """For tests that need a client around a custom-built app."""
    return _client_for
