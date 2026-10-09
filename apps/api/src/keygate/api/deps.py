"""Shared FastAPI dependencies."""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.service import AuditLog
from keygate.auth.email import Mailer
from keygate.auth.models import SessionLevel
from keygate.auth.sessions import SessionContext, SessionManager
from keygate.config import Settings
from keygate.security.rate_limit import RateLimiter
from keygate.security.request_info import ClientInfo, client_info


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    sessionmaker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with sessionmaker() as session:
        yield session


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_redis(request: Request) -> Redis:
    redis: Redis = request.app.state.redis
    return redis


def get_mailer(request: Request) -> Mailer:
    mailer: Mailer = request.app.state.mailer
    return mailer


def get_audit(request: Request) -> AuditLog:
    audit: AuditLog = request.app.state.audit
    return audit


def get_session_manager(request: Request) -> SessionManager:
    manager: SessionManager = request.app.state.session_manager
    return manager


def get_rate_limiter(redis: Annotated[Redis, Depends(get_redis)]) -> RateLimiter:
    return RateLimiter(redis)


DB = Annotated[AsyncSession, Depends(get_db)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
RedisDep = Annotated[Redis, Depends(get_redis)]
MailerDep = Annotated[Mailer, Depends(get_mailer)]
AuditDep = Annotated[AuditLog, Depends(get_audit)]
Sessions = Annotated[SessionManager, Depends(get_session_manager)]
Limiter = Annotated[RateLimiter, Depends(get_rate_limiter)]
Client = Annotated[ClientInfo, Depends(client_info)]


async def optional_session(
    request: Request, db: DB, sessions: Sessions, settings: SettingsDep
) -> SessionContext | None:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    return await sessions.load(db, token)


OptionalSession = Annotated[SessionContext | None, Depends(optional_session)]

_UNAUTHENTICATED = HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required.")


async def require_full_session(ctx: OptionalSession) -> SessionContext:
    if ctx is None or ctx.session.level is not SessionLevel.FULL:
        raise _UNAUTHENTICATED
    return ctx


async def require_registration_session(ctx: OptionalSession) -> SessionContext:
    if ctx is None or ctx.session.level is not SessionLevel.REGISTRATION:
        raise _UNAUTHENTICATED
    return ctx


FullSession = Annotated[SessionContext, Depends(require_full_session)]
RegistrationSession = Annotated[SessionContext, Depends(require_registration_session)]
