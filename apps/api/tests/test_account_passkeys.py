import asyncio

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from tests.helpers import expire_step_up, sign_in, sign_up, step_up_with_passkey
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration


@pytest.fixture
async def auth(client: httpx.AsyncClient, mailer: InMemoryMailer) -> SoftAuthenticator:
    authenticator = SoftAuthenticator()
    await sign_up(client, mailer, authenticator, "owner@example.com")
    return authenticator


async def _add_passkey(
    client: httpx.AsyncClient, device: SoftAuthenticator, name: str
) -> httpx.Response:
    options = (await client.post("/account/passkeys/register/options")).json()
    return await client.post(
        "/account/passkeys/register/verify",
        json={"credential": device.create(options), "friendly_name": name},
    )


async def test_add_second_passkey_and_notify(
    client: httpx.AsyncClient, auth: SoftAuthenticator, mailer: InMemoryMailer
) -> None:
    phone = SoftAuthenticator()
    resp = await _add_passkey(client, phone, "Phone")
    assert resp.status_code == 200, resp.text
    names = [p["friendly_name"] for p in (await client.get("/account")).json()["passkeys"]]
    assert names == ["Test key", "Phone"]
    assert mailer.outbox[-1].subject == "Keygate security alert"
    assert "new passkey" in mailer.outbox[-1].text
    # The new passkey works for sign-in.
    assert (await sign_in(client, phone)).status_code == 200


async def test_add_passkey_excludes_existing_credentials(
    client: httpx.AsyncClient, auth: SoftAuthenticator
) -> None:
    options = (await client.post("/account/passkeys/register/options")).json()
    assert len(options["excludeCredentials"]) == 1
    with pytest.raises(ValueError, match="already registered"):
        auth.create(options)


async def test_adding_passkey_requires_step_up(
    client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await expire_step_up(db_sessionmaker)
    resp = await client.post("/account/passkeys/register/options")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "step_up_required"
    assert (await step_up_with_passkey(client, auth)).status_code == 200
    assert (await _add_passkey(client, SoftAuthenticator(), "Laptop")).status_code == 200


async def test_rename_passkey(client: httpx.AsyncClient, auth: SoftAuthenticator) -> None:
    [pk] = (await client.get("/account")).json()["passkeys"]
    resp = await client.patch(f"/account/passkeys/{pk['id']}", json={"friendly_name": "Work Mac"})
    assert resp.status_code == 200
    assert resp.json()["friendly_name"] == "Work Mac"


async def test_cannot_delete_last_sign_in_method(
    client: httpx.AsyncClient, auth: SoftAuthenticator
) -> None:
    [pk] = (await client.get("/account")).json()["passkeys"]
    resp = await client.delete(f"/account/passkeys/{pk['id']}")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "last_sign_in_method"
    assert len((await client.get("/account")).json()["passkeys"]) == 1


async def test_delete_passkey_when_another_exists(
    client: httpx.AsyncClient, auth: SoftAuthenticator, mailer: InMemoryMailer
) -> None:
    await _add_passkey(client, SoftAuthenticator(), "Backup")
    first = (await client.get("/account")).json()["passkeys"][0]
    assert (await client.delete(f"/account/passkeys/{first['id']}")).status_code == 204
    assert "passkey was removed" in mailer.outbox[-1].text
    # The deleted passkey can no longer sign in.
    assert (await sign_in(client, auth)).status_code == 400


async def test_concurrent_deletes_cannot_remove_every_method(
    client: httpx.AsyncClient, auth: SoftAuthenticator
) -> None:
    """Two parallel deletes of the last two passkeys: the user-row lock serialises them,
    so exactly one succeeds."""
    await _add_passkey(client, SoftAuthenticator(), "Second")
    ids = [p["id"] for p in (await client.get("/account")).json()["passkeys"]]
    results = await asyncio.gather(*(client.delete(f"/account/passkeys/{i}") for i in ids))
    assert sorted(r.status_code for r in results) == [204, 409]
    assert len((await client.get("/account")).json()["passkeys"]) == 1


async def test_cannot_touch_another_users_passkey(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    auth: SoftAuthenticator,
    mailer: InMemoryMailer,
) -> None:
    """IDOR: object IDs are always looked up together with the owner."""
    [victim_pk] = (await client.get("/account")).json()["passkeys"]
    await sign_up(second_client, mailer, SoftAuthenticator(), "attacker@example.com")
    await _add_passkey(second_client, SoftAuthenticator(), "Extra")  # so deletes aren't blocked
    rename = await second_client.patch(
        f"/account/passkeys/{victim_pk['id']}", json={"friendly_name": "pwned"}
    )
    delete = await second_client.delete(f"/account/passkeys/{victim_pk['id']}")
    assert rename.status_code == delete.status_code == 404
    assert (await client.get("/account")).json()["passkeys"][0]["friendly_name"] == "Test key"
