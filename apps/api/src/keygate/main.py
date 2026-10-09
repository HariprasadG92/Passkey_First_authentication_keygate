"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from redis.asyncio import Redis

from keygate import __version__
from keygate.api import account, auth, health
from keygate.audit.service import AuditLog
from keygate.auth.email import Mailer, SMTPMailer
from keygate.auth.sessions import SessionManager
from keygate.config import Settings, get_settings
from keygate.db.session import create_engine, create_sessionmaker
from keygate.errors import register_exception_handlers
from keygate.logging_setup import configure_logging, get_logger
from keygate.security.csrf import csrf_protect
from keygate.security.middleware import SecurityMiddleware

log = get_logger(__name__)


def create_app(settings: Settings | None = None, *, mailer: Mailer | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine(settings)
        sessionmaker = create_sessionmaker(engine)
        redis: Redis = Redis.from_url(settings.redis_url.get_secret_value())
        app.state.engine = engine
        app.state.sessionmaker = sessionmaker
        app.state.redis = redis
        app.state.audit = AuditLog(sessionmaker)
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
        # Default-deny CSRF: every state-changing route is protected unless exempted.
        dependencies=[Depends(csrf_protect)],
    )
    app.state.settings = settings
    app.state.mailer = mailer or SMTPMailer(settings)
    app.state.session_manager = SessionManager(settings)

    register_exception_handlers(app)
    app.add_middleware(
        SecurityMiddleware, hsts=settings.is_production, docs_enabled=settings.docs_enabled
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(account.router)
    return app
