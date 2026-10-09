"""Server-side sessions.

* The cookie carries a 256-bit random token; the database stores only its SHA-256.
* Every sign-in or privilege change **rotates** the session: the old row is revoked and
  a new token issued, defeating session fixation.
* Sessions expire after an idle timeout (no activity) and an absolute timeout (since
  creation), whichever comes first.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from fastapi import Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from keygate.auth.models import Session, SessionLevel, User, UserStatus
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.security.csrf import issue_csrf_token
from keygate.security.request_info import ClientInfo
from keygate.security.tokens import generate_token, hash_token

# Refresh last_seen_at at most this often, to avoid a write on every request.
LAST_SEEN_RESOLUTION = timedelta(seconds=60)


@dataclass(frozen=True)
class NewSession:
    token: str
    csrf_token: str


@dataclass(frozen=True)
class SessionContext:
    session: Session
    user: User
    token: str


class SessionManager:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def create(
        self,
        db: AsyncSession,
        response: Response,
        *,
        user: User,
        level: SessionLevel,
        auth_method: str,
        client: ClientInfo,
        replaces_token: str | None = None,
    ) -> NewSession:
        """Start a new session (rotating out ``replaces_token``) and set the cookies."""
        if replaces_token:
            await self.revoke_token(db, replaces_token)

        now = utcnow()
        lifetime = (
            timedelta(minutes=self._settings.registration_session_minutes)
            if level is SessionLevel.REGISTRATION
            else self._settings.session_absolute_timeout
        )
        token = generate_token()
        db.add(
            Session(
                token_hash=hash_token(token),
                user_id=user.id,
                level=level,
                auth_method=auth_method,
                ip_address=client.ip,
                user_agent=client.user_agent,
                last_seen_at=now,
                expires_at=now + lifetime,
            )
        )
        self._set_cookie(response, token, lifetime)
        # The CSRF token is bound to the session, so it must be re-issued with it.
        csrf = issue_csrf_token(self._settings, response, token)
        return NewSession(token=token, csrf_token=csrf)

    async def load(self, db: AsyncSession, token: str) -> SessionContext | None:
        row = (
            await db.execute(
                select(Session)
                .options(joinedload(Session.user))
                .where(Session.token_hash == hash_token(token), Session.revoked_at.is_(None))
            )
        ).scalar_one_or_none()
        if row is None:
            return None

        now = utcnow()
        if self._is_expired(row, now) or row.user.status is not UserStatus.ACTIVE:
            row.revoked_at = now
            await db.commit()
            return None

        if now - row.last_seen_at >= LAST_SEEN_RESOLUTION:
            row.last_seen_at = now
            await db.commit()
        return SessionContext(session=row, user=row.user, token=token)

    def _is_expired(self, row: Session, now: datetime) -> bool:
        return (
            now >= row.expires_at or now - row.last_seen_at >= self._settings.session_idle_timeout
        )

    async def revoke_token(self, db: AsyncSession, token: str) -> None:
        await db.execute(
            update(Session)
            .where(Session.token_hash == hash_token(token), Session.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )

    def clear_cookies(self, response: Response) -> None:
        response.delete_cookie(
            self._settings.session_cookie_name,
            path="/",
            secure=self._settings.secure_cookies,
            httponly=True,
            samesite="lax",
        )
        # Fresh anonymous CSRF token so the next request (e.g. sign-in) still works.
        issue_csrf_token(self._settings, response, None)

    def _set_cookie(self, response: Response, token: str, lifetime: timedelta) -> None:
        response.set_cookie(
            self._settings.session_cookie_name,
            token,
            max_age=int(lifetime.total_seconds()),
            path="/",
            secure=self._settings.secure_cookies,
            httponly=True,  # not readable by JavaScript, so XSS can't exfiltrate it
            samesite="lax",
        )
