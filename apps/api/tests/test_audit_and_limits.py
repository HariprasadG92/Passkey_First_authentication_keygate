import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.models import AuditResult
from keygate.audit.service import AuditLog

pytestmark = pytest.mark.integration


async def test_audit_log_is_append_only(db_sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    await AuditLog(db_sessionmaker).record("test.event", result=AuditResult.SUCCESS)
    async with db_sessionmaker() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("UPDATE audit_events SET event_type = 'tampered'"))
    async with db_sessionmaker() as db:
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(text("DELETE FROM audit_events"))
    async with db_sessionmaker() as db:
        count = (await db.execute(text("SELECT count(*) FROM audit_events"))).scalar_one()
    assert count == 1


async def test_signup_rate_limited_per_email(client: httpx.AsyncClient) -> None:
    for _ in range(3):
        assert (
            await client.post("/auth/signup", json={"email": "x@example.com"})
        ).status_code == 202
    resp = await client.post("/auth/signup", json={"email": "x@example.com"})
    assert resp.status_code == 429
    assert int(resp.headers["retry-after"]) > 0
    assert resp.json()["error"]["code"] == "too_many_requests"
    # Other addresses are unaffected.
    assert (await client.post("/auth/signup", json={"email": "y@example.com"})).status_code == 202


async def test_login_options_rate_limited_per_ip(client: httpx.AsyncClient) -> None:
    for _ in range(30):
        assert (await client.post("/auth/passkeys/login/options", json={})).status_code == 200
    assert (await client.post("/auth/passkeys/login/options", json={})).status_code == 429


async def test_rate_limit_keys_do_not_contain_raw_identifiers(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    await client.post("/auth/signup", json={"email": "private@example.com"})
    keys = [k.decode() async for k in redis.scan_iter("rl:*")]
    assert keys
    assert not any("private" in k or "127.0.0.1" in k for k in keys)
