from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from fastapi import FastAPI

from keygate.config import Settings
from keygate.main import create_app

AppFactory = Callable[..., FastAPI]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "integration: needs the real Postgres and Redis from docker compose"
    )


@pytest.fixture
def settings() -> Settings:
    # Values come from KEYGATE_* env vars when set (e.g. in CI), else the local-dev defaults.
    return Settings(environment="test", log_json=True)


@pytest.fixture
def unreachable_settings() -> Settings:
    """Settings pointing at a closed port, to exercise dependency-failure paths."""
    return Settings(
        environment="test",
        database_url="postgresql+asyncpg://nobody:nothing@127.0.0.1:1/none",  # type: ignore[arg-type]
        redis_url="redis://127.0.0.1:1/0",  # type: ignore[arg-type]
    )


async def _client_for(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client,
    ):
        yield client


@pytest.fixture
async def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async for c in _client_for(app):
        yield c


@pytest.fixture
def make_client() -> Callable[[FastAPI], AsyncIterator[httpx.AsyncClient]]:
    """For tests that need a client around a custom-built app."""
    return _client_for
