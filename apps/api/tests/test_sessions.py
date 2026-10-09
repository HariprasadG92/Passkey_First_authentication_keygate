from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from keygate.auth.models import Session
from keygate.db.types import utcnow
from tests.helpers import sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration


@pytest.fixture
async def signed_in(client: httpx.AsyncClient, mailer: InMemoryMailer) -> httpx.AsyncClient:
    await sign_up(client, mailer, SoftAuthenticator())
    return client


async def test_session_cookie_attributes(client: httpx.AsyncClient, mailer: InMemoryMailer) -> None:
    await sign_up(client, mailer, SoftAuthenticator())
    resp = await client.get("/auth/session")
    assert resp.json()["authenticated"] is True
    # Inspect the Set-Cookie emitted at sign-in time via a fresh sign-up response.
    other = await client.post("/auth/logout")
    cookies = other.headers.get_list("set-cookie")
    session_clear = next(c for c in cookies if c.startswith("kg_session="))
    assert "HttpOnly" in session_clear
    assert "SameSite=lax" in session_clear
    assert "Path=/" in session_clear


async def test_session_cookie_set_on_login_is_httponly_lax(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    from tests.helpers import start_and_verify_email

    resp = await start_and_verify_email(client, mailer, "c@example.com")
    cookie = next(c for c in resp.headers.get_list("set-cookie") if c.startswith("kg_session="))
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie
    assert "Max-Age=900" in cookie  # registration sessions live 15 minutes
    csrf = next(c for c in resp.headers.get_list("set-cookie") if c.startswith("kg_csrf="))
    assert "HttpOnly" not in csrf
    assert "SameSite=strict" in csrf


async def test_session_token_stored_hashed(
    signed_in: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    token = signed_in.cookies.get("kg_session")
    assert token
    async with db_sessionmaker() as db:
        rows = list((await db.execute(select(Session))).scalars())
    assert all(row.token_hash != token.encode() for row in rows)
    assert all(len(row.token_hash) == 32 for row in rows)


async def test_idle_timeout(
    signed_in: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    assert (await signed_in.get("/account")).status_code == 200
    async with db_sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.revoked_at.is_(None))
            .values(last_seen_at=utcnow() - timedelta(minutes=31))
        )
        await db.commit()
    assert (await signed_in.get("/account")).status_code == 401


async def test_absolute_timeout(
    signed_in: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async with db_sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.revoked_at.is_(None))
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
        await db.commit()
    assert (await signed_in.get("/account")).status_code == 401


async def test_activity_extends_idle_window(
    signed_in: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async with db_sessionmaker() as db:
        await db.execute(
            update(Session)
            .where(Session.revoked_at.is_(None))
            .values(last_seen_at=utcnow() - timedelta(minutes=29))
        )
        await db.commit()
    assert (await signed_in.get("/account")).status_code == 200
    async with db_sessionmaker() as db:
        live = (await db.execute(select(Session).where(Session.revoked_at.is_(None)))).scalar_one()
    assert utcnow() - live.last_seen_at < timedelta(minutes=1)


async def test_logout_revokes_session(signed_in: httpx.AsyncClient) -> None:
    token = signed_in.cookies.get("kg_session")
    assert (await signed_in.post("/auth/logout")).status_code == 204
    signed_in.cookies.set("kg_session", token or "")
    assert (await signed_in.get("/account")).status_code == 401


async def test_unauthenticated_account_access(client: httpx.AsyncClient) -> None:
    resp = await client.get("/account")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_garbage_session_cookie(client: httpx.AsyncClient) -> None:
    client.cookies.set("kg_session", "not-a-real-session")
    assert (await client.get("/account")).status_code == 401
