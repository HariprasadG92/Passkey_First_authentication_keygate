import re

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from keygate.mfa.models import RecoveryCode
from tests.helpers import expire_step_up, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration
EMAIL = "rec@example.com"
CODE_RE = re.compile(r"^[2-9A-HJKMNP-Z]{5}-[2-9A-HJKMNP-Z]{5}$")


@pytest.fixture
async def codes(client: httpx.AsyncClient, mailer: InMemoryMailer) -> list[str]:
    await sign_up(client, mailer, SoftAuthenticator(), EMAIL)
    resp = await client.post("/account/recovery-codes")
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    result: list[str] = resp.json()["codes"]
    return result


async def _recover(client: httpx.AsyncClient, code: str, email: str = EMAIL) -> httpx.Response:
    await client.post("/auth/logout")
    return await client.post("/auth/recovery/login", json={"email": email, "code": code})


async def test_ten_unique_codes_in_expected_format(codes: list[str]) -> None:
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert all(CODE_RE.fullmatch(c) for c in codes)


async def test_stored_as_argon2id_hashes(
    codes: list[str], db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async with db_sessionmaker() as db:
        rows = list((await db.execute(select(RecoveryCode))).scalars())
    assert len(rows) == 10
    for row in rows:
        assert row.code_hash.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
        assert all(c.replace("-", "") not in row.code_hash for c in codes)


async def test_recovery_sign_in_is_single_use(
    client: httpx.AsyncClient, codes: list[str], mailer: InMemoryMailer
) -> None:
    resp = await _recover(client, codes[0].lower().replace("-", " "))  # forgiving input
    assert resp.status_code == 200, resp.text
    overview = (await client.get("/account")).json()
    assert overview["recovery_codes_remaining"] == 9
    assert "recovery code was used" in mailer.outbox[-1].text
    assert "Codes left: 9" in mailer.outbox[-1].text
    # Same code again: rejected.
    assert (await _recover(client, codes[0])).status_code == 400


async def test_recovered_session_can_add_passkey_immediately(
    client: httpx.AsyncClient, codes: list[str]
) -> None:
    await _recover(client, codes[1])
    resp = await client.post("/account/passkeys/register/options")
    assert resp.status_code == 200  # fresh authentication satisfies step-up


async def test_regenerating_invalidates_old_codes(
    client: httpx.AsyncClient, codes: list[str]
) -> None:
    new = (await client.post("/account/recovery-codes")).json()["codes"]
    assert set(new).isdisjoint(codes)
    assert (await _recover(client, codes[2])).status_code == 400
    assert (await _recover(client, new[0])).status_code == 200


async def test_wrong_code_and_unknown_email_look_the_same(
    client: httpx.AsyncClient, codes: list[str]
) -> None:
    wrong = await _recover(client, "AAAAA-AAAAA")
    unknown = await _recover(client, codes[0], email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 400
    assert wrong.json() == unknown.json()


async def test_regeneration_requires_step_up(
    client: httpx.AsyncClient, codes: list[str], db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    await expire_step_up(db_sessionmaker)
    resp = await client.post("/account/recovery-codes")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "step_up_required"
