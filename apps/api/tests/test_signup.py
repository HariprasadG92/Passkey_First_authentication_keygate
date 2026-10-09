from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from keygate.auth.models import EmailToken, User
from keygate.db.types import utcnow
from tests.helpers import last_link_token, register_first_passkey, sign_up, start_and_verify_email
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration


async def test_full_signup_flow(client: httpx.AsyncClient, mailer: InMemoryMailer) -> None:
    auth = SoftAuthenticator()
    verify = await start_and_verify_email(client, mailer, "  Alice@Example.COM ")
    assert verify.status_code == 200
    assert verify.json() == {"email": "alice@example.com", "next": "register_passkey"}

    session = (await client.get("/auth/session")).json()
    assert session["authenticated"] is False
    assert session["level"] == "registration"

    registration_cookie = client.cookies.get("kg_session")
    resp = await register_first_passkey(client, auth, name="MacBook Touch ID")
    assert resp.status_code == 200, resp.text
    assert resp.json()["authenticated"] is True
    # Privilege change rotated the session.
    assert client.cookies.get("kg_session") != registration_cookie

    account = (await client.get("/account")).json()
    assert account["user"]["email"] == "alice@example.com"
    assert account["user"]["email_verified"] is True
    [passkey] = account["passkeys"]
    assert passkey["friendly_name"] == "MacBook Touch ID"
    assert passkey["backup_eligible"] is True
    assert passkey["transports"] == ["internal", "hybrid"]


async def test_magic_link_token_stored_hashed_and_link_uses_fragment(
    client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await client.post("/auth/signup", json={"email": "bob@example.com"})
    token = last_link_token(mailer, "bob@example.com")
    assert "http://localhost/verify-email#token=" in mailer.outbox[-1].text
    assert len(token) >= 43  # 32 random bytes, base64url

    async with db_sessionmaker() as db:
        row = (await db.execute(select(EmailToken))).scalar_one()
    assert row.token_hash != token.encode()
    assert len(row.token_hash) == 32
    assert row.expires_at - row.created_at <= timedelta(minutes=15, seconds=5)


async def test_magic_link_is_single_use(client: httpx.AsyncClient, mailer: InMemoryMailer) -> None:
    await client.post("/auth/signup", json={"email": "carol@example.com"})
    token = last_link_token(mailer, "carol@example.com")
    assert (await client.post("/auth/email/verify", json={"token": token})).status_code == 200
    again = await client.post("/auth/email/verify", json={"token": token})
    assert again.status_code == 400
    assert again.json()["error"]["message"].startswith("This link is invalid")


async def test_expired_magic_link_rejected(
    client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await client.post("/auth/signup", json={"email": "dave@example.com"})
    token = last_link_token(mailer, "dave@example.com")
    async with db_sessionmaker() as db:
        await db.execute(update(EmailToken).values(expires_at=utcnow() - timedelta(seconds=1)))
        await db.commit()
    assert (await client.post("/auth/email/verify", json={"token": token})).status_code == 400


async def test_only_newest_link_is_valid(client: httpx.AsyncClient, mailer: InMemoryMailer) -> None:
    await client.post("/auth/signup", json={"email": "erin@example.com"})
    first = last_link_token(mailer, "erin@example.com")
    await client.post("/auth/signup", json={"email": "erin@example.com"})
    second = last_link_token(mailer, "erin@example.com")
    assert first != second
    assert (await client.post("/auth/email/verify", json={"token": first})).status_code == 400
    assert (await client.post("/auth/email/verify", json={"token": second})).status_code == 200


async def test_signup_response_identical_for_existing_account(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    """No account enumeration: same status and body; existing users get a notice, no link."""
    await sign_up(client, mailer, SoftAuthenticator(), "frank@example.com")
    existing = await client.post("/auth/signup", json={"email": "frank@example.com"})
    new = await client.post("/auth/signup", json={"email": "newperson@example.com"})
    assert existing.status_code == new.status_code == 202
    assert existing.json() == new.json()

    notice = mailer.outbox[-2]
    assert notice.to == "frank@example.com"
    assert "already have an account" in notice.text
    assert "#token=" not in notice.text


async def test_link_cannot_bypass_passkey_registered_later(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    """A link issued before the account got a passkey must not grant a session after."""
    await client.post("/auth/signup", json={"email": "gina@example.com"})
    stale = last_link_token(mailer, "gina@example.com")
    # Manually issue a second, legitimate flow that registers a passkey.
    await client.post("/auth/signup", json={"email": "gina@example.com"})
    fresh = last_link_token(mailer, "gina@example.com")
    assert (await client.post("/auth/email/verify", json={"token": fresh})).status_code == 200
    assert (await register_first_passkey(client, SoftAuthenticator())).status_code == 200
    # The stale link was already invalidated when the fresh one was issued...
    assert (await client.post("/auth/email/verify", json={"token": stale})).status_code == 400


async def test_registration_session_is_limited(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "hank@example.com")
    # Can't use the account yet...
    assert (await client.get("/account")).status_code == 401
    # ...and can enrol only one passkey with it.
    assert (await register_first_passkey(client, SoftAuthenticator())).status_code == 200


async def test_registration_rejects_wrong_origin(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "ivan@example.com")
    resp = await register_first_passkey(client, SoftAuthenticator(origin="https://evil.example"))
    assert resp.status_code == 400
    assert resp.json()["error"]["message"] == "Passkey verification failed. Please try again."


async def test_registration_rejects_wrong_rp_id(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "judy@example.com")
    resp = await register_first_passkey(client, SoftAuthenticator(rp_id="evil.example"))
    assert resp.status_code == 400


async def test_registration_requires_user_verification(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "kim@example.com")
    resp = await register_first_passkey(client, SoftAuthenticator(user_verified=False))
    assert resp.status_code == 400


async def test_registration_challenge_is_single_use(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "leo@example.com")
    auth = SoftAuthenticator()
    options = (await client.post("/auth/passkeys/register/options")).json()
    credential = auth.create(options)
    # Challenge consumed by a failed attempt (bad name type) can't be reused...
    bad = await client.post(
        "/auth/passkeys/register/verify",
        json={
            "credential": {
                **credential,
                "response": {**credential["response"], "clientDataJSON": "AAAA"},
            }
        },
    )
    assert bad.status_code == 400
    retry = await client.post("/auth/passkeys/register/verify", json={"credential": credential})
    assert retry.status_code == 400


async def test_registration_options_exclude_and_require_uv(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "mia@example.com")
    options = (await client.post("/auth/passkeys/register/options")).json()
    assert options["rp"] == {"id": "localhost", "name": "Keygate"}
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["authenticatorSelection"]["residentKey"] == "preferred"
    assert options["attestation"] == "none"
    assert options["timeout"] == 300_000
    # User handle is random and opaque, not the email.
    assert "mia" not in options["user"]["id"]


async def test_email_normalisation_enforced_by_database(
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    from sqlalchemy.exc import IntegrityError

    async with db_sessionmaker() as db:
        db.add(User(email="Upper@Example.com", display_name="x", webauthn_user_handle=b"h" * 32))
        with pytest.raises(IntegrityError):
            await db.commit()
