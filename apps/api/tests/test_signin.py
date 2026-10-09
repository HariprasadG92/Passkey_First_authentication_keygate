import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.models import AuditEvent, AuditResult, Severity
from keygate.auth.email import InMemoryMailer
from keygate.auth.models import User, UserStatus, WebAuthnCredential
from tests.helpers import login_options, sign_in, sign_up
from tests.soft_authenticator import SoftAuthenticator, b64url, b64url_decode

pytestmark = pytest.mark.integration


@pytest.fixture
async def alice(client: httpx.AsyncClient, mailer: InMemoryMailer) -> SoftAuthenticator:
    """An account with one passkey; returns its authenticator, signed out."""
    auth = SoftAuthenticator()
    await sign_up(client, mailer, auth, "alice@example.com")
    await client.post("/auth/logout")
    return auth


async def _audit(
    db_sessionmaker: async_sessionmaker[AsyncSession], event_type: str
) -> list[AuditEvent]:
    async with db_sessionmaker() as db:
        return list(
            (
                await db.execute(select(AuditEvent).where(AuditEvent.event_type == event_type))
            ).scalars()
        )


async def test_usernameless_sign_in(client: httpx.AsyncClient, alice: SoftAuthenticator) -> None:
    opts = await login_options(client)
    assert opts["options"]["allowCredentials"] == []
    assert opts["options"]["userVerification"] == "required"
    assertion = alice.get(opts["options"])
    resp = await client.post(
        "/auth/passkeys/login/verify",
        json={"ceremony_id": opts["ceremony_id"], "credential": assertion},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["email"] == "alice@example.com"
    assert (await client.get("/account")).status_code == 200


async def test_email_first_sign_in(client: httpx.AsyncClient, alice: SoftAuthenticator) -> None:
    opts = await login_options(client, "ALICE@example.com")
    [allowed] = opts["options"]["allowCredentials"]
    assert b64url_decode(allowed["id"]) in alice.credentials
    resp = await sign_in(client, alice, "alice@example.com")
    assert resp.status_code == 200


async def test_unknown_email_gets_stable_decoy_options(
    client: httpx.AsyncClient, alice: SoftAuthenticator
) -> None:
    """Options for a non-existent account look like a real one's (no enumeration)."""
    first = (await login_options(client, "nobody@example.com"))["options"]["allowCredentials"]
    second = (await login_options(client, "nobody@example.com"))["options"]["allowCredentials"]
    other = (await login_options(client, "someone@example.com"))["options"]["allowCredentials"]
    real = (await login_options(client, "alice@example.com"))["options"]["allowCredentials"]
    assert len(first) == len(real) == 1
    assert first == second
    assert first != other
    assert len(b64url_decode(first[0]["id"])) == len(b64url_decode(real[0]["id"]))


async def test_sign_in_rotates_session(client: httpx.AsyncClient, alice: SoftAuthenticator) -> None:
    await sign_in(client, alice)
    old = client.cookies.get("kg_session")
    await sign_in(client, alice)
    new = client.cookies.get("kg_session")
    assert old
    assert new
    assert old != new
    # The old token is dead.
    stale = httpx.Cookies({"kg_session": old})
    client.cookies = stale
    assert (await client.get("/account")).status_code == 401


async def test_assertion_replay_rejected(
    client: httpx.AsyncClient, alice: SoftAuthenticator
) -> None:
    opts = await login_options(client)
    assertion = alice.get(opts["options"])
    body = {"ceremony_id": opts["ceremony_id"], "credential": assertion}
    assert (await client.post("/auth/passkeys/login/verify", json=body)).status_code == 200
    # Same ceremony again: challenge already consumed.
    assert (await client.post("/auth/passkeys/login/verify", json=body)).status_code == 400
    # Same assertion with a fresh ceremony: challenge mismatch.
    fresh = await login_options(client)
    replay = {"ceremony_id": fresh["ceremony_id"], "credential": assertion}
    assert (await client.post("/auth/passkeys/login/verify", json=replay)).status_code == 400


async def test_expired_challenge_rejected(
    client: httpx.AsyncClient, alice: SoftAuthenticator, redis: Redis
) -> None:
    opts = await login_options(client)
    keys = [k async for k in redis.scan_iter("webauthn:auth:*")]
    assert len(keys) == 1
    ttl = await redis.ttl(keys[0])
    assert 0 < ttl <= 300
    await redis.delete(keys[0])  # what Redis does when the TTL runs out
    resp = await client.post(
        "/auth/passkeys/login/verify",
        json={"ceremony_id": opts["ceremony_id"], "credential": alice.get(opts["options"])},
    )
    assert resp.status_code == 400


async def test_origin_mismatch_rejected(
    client: httpx.AsyncClient, alice: SoftAuthenticator
) -> None:
    alice.origin = "https://phishing.example"
    assert (await sign_in(client, alice)).status_code == 400


async def test_rp_id_mismatch_rejected(client: httpx.AsyncClient, alice: SoftAuthenticator) -> None:
    alice.rp_id = "phishing.example"
    assert (await sign_in(client, alice)).status_code == 400


async def test_user_verification_required(
    client: httpx.AsyncClient, alice: SoftAuthenticator
) -> None:
    alice.user_verified = False
    assert (await sign_in(client, alice)).status_code == 400


async def test_unknown_credential_rejected(
    client: httpx.AsyncClient, alice: SoftAuthenticator, mailer: InMemoryMailer
) -> None:
    stranger = SoftAuthenticator()
    opts = await login_options(client)
    stranger.create({"rp": {"id": "localhost"}, "user": {"id": b64url(b"x")}, "challenge": "AA"})
    resp = await client.post(
        "/auth/passkeys/login/verify",
        json={"ceremony_id": opts["ceremony_id"], "credential": stranger.get(opts["options"])},
    )
    assert resp.status_code == 400


async def test_user_handle_mismatch_rejected(
    client: httpx.AsyncClient, alice: SoftAuthenticator
) -> None:
    assert (await sign_in(client, alice, user_handle=b"someone-else")).status_code == 400


async def test_sign_count_regression_flags_cloned_authenticator(
    client: httpx.AsyncClient,
    alice: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    assert (await sign_in(client, alice)).status_code == 200  # counter now 1
    assert (await sign_in(client, alice)).status_code == 200  # counter now 2
    # A clone of the authenticator still at counter 1 signs a valid assertion.
    resp = await sign_in(client, alice, sign_count=1)
    assert resp.status_code == 400

    [event] = await _audit(db_sessionmaker, "credential.sign_count_regression")
    assert event.severity is Severity.HIGH
    assert event.result is AuditResult.FAILURE
    assert event.target_user_id is not None
    async with db_sessionmaker() as db:
        stored = (await db.execute(select(WebAuthnCredential))).scalar_one()
    assert stored.sign_count == 2  # not overwritten by the clone


async def test_zero_counter_authenticators_allowed(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    """Synced passkeys (e.g. iCloud Keychain) always report 0: that's not a clone."""
    auth = SoftAuthenticator(counter_step=0)
    await sign_up(client, mailer, auth, "zero@example.com")
    assert (await sign_in(client, auth)).status_code == 200
    assert (await sign_in(client, auth)).status_code == 200


async def test_suspended_user_cannot_sign_in(
    client: httpx.AsyncClient,
    alice: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with db_sessionmaker() as db:
        await db.execute(update(User).values(status=UserStatus.SUSPENDED))
        await db.commit()
    assert (await sign_in(client, alice)).status_code == 400


async def test_sign_in_audited(
    client: httpx.AsyncClient,
    alice: SoftAuthenticator,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await sign_in(client, alice)
    alice.origin = "https://evil.example"
    await sign_in(client, alice)
    events = await _audit(db_sessionmaker, "signin")
    results = sorted(e.result.value for e in events)
    assert results == ["failure", "success"]
    for event in events:
        assert event.ip_address == "127.0.0.1"
        assert event.request_id
        # Never store credential material in the audit log.
        assert "signature" not in str(event.details)
        assert "clientDataJSON" not in str(event.details)
