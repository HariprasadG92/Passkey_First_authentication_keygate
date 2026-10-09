import time

import httpx
import pyotp
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from tests.helpers import (
    enable_totp,
    expire_step_up,
    sign_in,
    sign_up,
    start_and_verify_email,
    step_up_with_passkey,
)
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration


@pytest.fixture
async def auth(client: httpx.AsyncClient, mailer: InMemoryMailer) -> SoftAuthenticator:
    a = SoftAuthenticator()
    await sign_up(client, mailer, a, "me@example.com")
    return a


async def test_step_up_with_passkey_rotates_session(
    client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await expire_step_up(db_sessionmaker)
    before = client.cookies.get("kg_session")
    resp = await step_up_with_passkey(client, auth)
    assert resp.status_code == 200
    assert client.cookies.get("kg_session") != before
    overview = (await client.get("/account")).json()
    assert overview["step_up_valid_until"] is not None
    assert (await client.post("/account/recovery-codes")).status_code == 200


async def test_step_up_with_totp(
    client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    secret = await enable_totp(client)
    await expire_step_up(db_sessionmaker)
    code = pyotp.TOTP(secret).at(int(time.time()) + 30)
    assert (await client.post("/auth/step-up/totp", json={"code": code})).status_code == 200
    assert (await client.post("/account/recovery-codes")).status_code == 200


async def test_step_up_with_someone_elses_passkey_rejected(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    other = SoftAuthenticator()
    await sign_up(second_client, mailer, other, "other@example.com")
    await expire_step_up(db_sessionmaker)
    options = (await client.post("/auth/step-up/passkey/options")).json()
    other_cred = next(iter(other.credentials))
    forged = other.get({**options, "allowCredentials": []}, credential_id=other_cred)
    resp = await client.post("/auth/step-up/passkey/verify", json={"credential": forged})
    assert resp.status_code == 400
    assert (await client.post("/account/recovery-codes")).status_code == 403


async def test_registration_session_cannot_step_up(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "new@example.com")
    assert (await client.post("/auth/step-up/passkey/options")).status_code == 401
    assert (await client.post("/account/recovery-codes")).status_code == 401


async def test_list_and_revoke_other_sessions(
    client: httpx.AsyncClient, second_client: httpx.AsyncClient, auth: SoftAuthenticator
) -> None:
    assert (await sign_in(second_client, auth)).status_code == 200
    listed = (await client.get("/account/sessions")).json()
    assert len(listed) == 2
    assert sorted(s["current"] for s in listed) == [False, True]
    assert all(s["auth_method"] == "passkey" for s in listed)

    other = next(s for s in listed if not s["current"])
    assert (await client.delete(f"/account/sessions/{other['id']}")).status_code == 204
    assert (await second_client.get("/account")).status_code == 401
    assert (await client.get("/account")).status_code == 200


async def test_revoke_all_other_sessions(
    client: httpx.AsyncClient, second_client: httpx.AsyncClient, auth: SoftAuthenticator
) -> None:
    await sign_in(second_client, auth)
    resp = await client.post("/account/sessions/revoke-others")
    assert resp.json() == {"revoked": 1}
    assert (await second_client.get("/account")).status_code == 401
    assert len((await client.get("/account/sessions")).json()) == 1


async def test_cannot_revoke_another_users_session(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    await sign_up(second_client, mailer, SoftAuthenticator(), "victim@example.com")
    [victim_session] = (await second_client.get("/account/sessions")).json()
    resp = await client.delete(f"/account/sessions/{victim_session['id']}")
    assert resp.status_code == 404
    assert (await second_client.get("/account")).status_code == 200


async def test_email_change_flow(
    client: httpx.AsyncClient, auth: SoftAuthenticator, mailer: InMemoryMailer
) -> None:
    resp = await client.post("/account/email", json={"new_email": "New@Example.com"})
    assert resp.status_code == 202
    link_mail = next(m for m in mailer.outbox if m.to == "new@example.com")
    notice = next(m for m in mailer.outbox if m.to == "me@example.com" and "change" in m.text)
    assert "Requested new address: new@example.com" in notice.text
    token = link_mail.text.split("#token=")[1].split()[0]

    confirmed = await client.post("/account/email/confirm", json={"token": token})
    assert confirmed.status_code == 200
    assert confirmed.json()["email"] == "new@example.com"
    assert (await sign_in(client, auth, "new@example.com")).status_code == 200


async def test_email_change_link_useless_to_another_user(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    await client.post("/account/email", json={"new_email": "target@example.com"})
    token = (
        next(m for m in mailer.outbox if m.to == "target@example.com")
        .text.split("#token=")[1]
        .split()[0]
    )
    await sign_up(second_client, mailer, SoftAuthenticator(), "eve@example.com")
    assert (
        await second_client.post("/account/email/confirm", json={"token": token})
    ).status_code == 400


async def test_email_change_to_taken_address_reveals_nothing(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    await sign_up(second_client, mailer, SoftAuthenticator(), "taken@example.com")
    sent_before = len([m for m in mailer.outbox if m.to == "taken@example.com"])
    taken = await client.post("/account/email", json={"new_email": "taken@example.com"})
    free = await client.post("/account/email", json={"new_email": "free@example.com"})
    assert taken.status_code == free.status_code == 202
    assert taken.json() == free.json()
    assert len([m for m in mailer.outbox if m.to == "taken@example.com"]) == sent_before


async def test_email_change_requires_step_up(
    client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await expire_step_up(db_sessionmaker)
    resp = await client.post("/account/email", json={"new_email": "x@example.com"})
    assert resp.status_code == 403
