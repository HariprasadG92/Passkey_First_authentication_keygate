import httpx
import pytest

from keygate.auth.email import InMemoryMailer
from tests.helpers import sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration


async def test_post_without_csrf_token_rejected(raw_client: httpx.AsyncClient) -> None:
    await raw_client.get("/auth/session")  # has the cookie, but won't send the header
    resp = await raw_client.post("/auth/signup", json={"email": "a@example.com"})
    assert resp.status_code == 403
    assert resp.json()["error"]["message"] == "CSRF token missing or invalid."


async def test_header_must_match_cookie(raw_client: httpx.AsyncClient) -> None:
    await raw_client.get("/auth/session")
    resp = await raw_client.post(
        "/auth/signup", json={"email": "a@example.com"}, headers={"X-CSRF-Token": "forged.value"}
    )
    assert resp.status_code == 403


async def test_attacker_cannot_mint_token_without_secret(raw_client: httpx.AsyncClient) -> None:
    """Even if an attacker plants both a cookie and a matching header (e.g. via a
    cookie-injection bug), the MAC must verify."""
    raw_client.cookies.set("kg_csrf", "attacker.nonce")
    resp = await raw_client.post(
        "/auth/signup", json={"email": "a@example.com"}, headers={"X-CSRF-Token": "attacker.nonce"}
    )
    assert resp.status_code == 403


async def test_valid_token_accepted(raw_client: httpx.AsyncClient) -> None:
    token = (await raw_client.get("/auth/session")).json()["csrf_token"]
    assert raw_client.cookies.get("kg_csrf") == token
    resp = await raw_client.post(
        "/auth/signup", json={"email": "a@example.com"}, headers={"X-CSRF-Token": token}
    )
    assert resp.status_code == 202


async def test_token_bound_to_session(client: httpx.AsyncClient, mailer: InMemoryMailer) -> None:
    """A token issued before sign-in (anonymous) stops working once the session changes."""
    anon_token = client.cookies.get("kg_csrf")
    await sign_up(client, mailer, SoftAuthenticator())
    assert client.cookies.get("kg_csrf") != anon_token  # re-issued at sign-in
    session = client.cookies.get("kg_session") or ""
    client.cookies.clear()
    client.cookies.set("kg_session", session)
    client.cookies.set("kg_csrf", anon_token or "")
    resp = await client.post("/auth/logout", headers={"X-CSRF-Token": anon_token or ""})
    assert resp.status_code == 403


async def test_safe_methods_need_no_token(raw_client: httpx.AsyncClient) -> None:
    assert (await raw_client.get("/auth/session")).status_code == 200


async def test_session_endpoint_keeps_a_valid_token(raw_client: httpx.AsyncClient) -> None:
    """Concurrent page requests must not invalidate each other's CSRF header."""
    first = (await raw_client.get("/auth/session")).json()["csrf_token"]
    second = await raw_client.get("/auth/session")
    assert second.json()["csrf_token"] == first
    assert "kg_csrf" not in second.headers.get("set-cookie", "")


async def test_session_endpoint_replaces_token_bound_to_another_session(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    anon = client.cookies.get("kg_csrf")
    await sign_up(client, mailer, SoftAuthenticator())
    session = client.cookies.get("kg_session") or ""
    client.cookies.clear()
    client.cookies.set("kg_session", session)
    client.cookies.set("kg_csrf", anon or "")  # stale: bound to the anonymous state
    fresh = (await client.get("/auth/session")).json()["csrf_token"]
    assert fresh != anon
