"""Flow helpers shared by the auth tests."""

import re
from typing import Any

import httpx

from keygate.auth.email import InMemoryMailer
from tests.soft_authenticator import SoftAuthenticator

TOKEN_RE = re.compile(r"#token=([A-Za-z0-9_-]+)")


def last_link_token(mailer: InMemoryMailer, to: str) -> str:
    for message in reversed(mailer.outbox):
        if message.to == to.strip().lower() and (m := TOKEN_RE.search(message.text)):
            return m.group(1)
    raise AssertionError(f"no magic link sent to {to}")


async def start_and_verify_email(
    client: httpx.AsyncClient, mailer: InMemoryMailer, email: str
) -> httpx.Response:
    resp = await client.post("/auth/signup", json={"email": email})
    assert resp.status_code == 202, resp.text
    token = last_link_token(mailer, email)
    return await client.post("/auth/email/verify", json={"token": token})


async def register_first_passkey(
    client: httpx.AsyncClient, authenticator: SoftAuthenticator, name: str = "Test key"
) -> httpx.Response:
    options = (await client.post("/auth/passkeys/register/options")).json()
    credential = authenticator.create(options)
    return await client.post(
        "/auth/passkeys/register/verify",
        json={"credential": credential, "friendly_name": name},
    )


async def sign_up(
    client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    authenticator: SoftAuthenticator,
    email: str = "alice@example.com",
) -> dict[str, Any]:
    verify = await start_and_verify_email(client, mailer, email)
    assert verify.status_code == 200, verify.text
    resp = await register_first_passkey(client, authenticator)
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def login_options(client: httpx.AsyncClient, email: str | None = None) -> dict[str, Any]:
    resp = await client.post("/auth/passkeys/login/options", json={"email": email} if email else {})
    assert resp.status_code == 200, resp.text
    body: dict[str, Any] = resp.json()
    return body


async def sign_in(
    client: httpx.AsyncClient,
    authenticator: SoftAuthenticator,
    email: str | None = None,
    **get_kwargs: Any,
) -> httpx.Response:
    opts = await login_options(client, email)
    assertion = authenticator.get(opts["options"], **get_kwargs)
    return await client.post(
        "/auth/passkeys/login/verify",
        json={"ceremony_id": opts["ceremony_id"], "credential": assertion},
    )
