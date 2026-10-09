"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from redis.asyncio import Redis

from keygate import __version__
from keygate.api import health
from keygate.config import Settings, get_settings
from keygate.db.session import create_engine, create_sessionmaker
from keygate.errors import register_exception_handlers
from keygate.logging_setup import configure_logging, get_logger
from keygate.security.middleware import SecurityMiddleware

log = get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings)
        redis: Redis = Redis.from_url(settings.redis_url.get_secret_value())
        app.state.settings = settings
        app.state.engine = engine
        app.state.sessionmaker = create_sessionmaker(engine)
        app.state.redis = redis
        log.info("startup", environment=settings.environment, version=__version__)
        try:
            yield
        finally:
            await redis.aclose()
            await engine.dispose()
            log.info("shutdown")

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    register_exception_handlers(app)
    app.add_middleware(
        SecurityMiddleware, hsts=settings.is_production, docs_enabled=settings.docs_enabled
    )
    app.include_router(health.router)
    return app
