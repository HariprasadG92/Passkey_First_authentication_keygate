import time
import uuid

import httpx
import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.auth.email import InMemoryMailer
from keygate.mfa.models import TotpCredential
from keygate.mfa.totp import matching_step
from keygate.security.crypto import DecryptionError, Encryptor
from tests.conftest import make_settings
from tests.helpers import enable_totp, expire_step_up, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration
EMAIL = "totp@example.com"


@pytest.fixture
async def secret(client: httpx.AsyncClient, mailer: InMemoryMailer) -> str:
    await sign_up(client, mailer, SoftAuthenticator(), EMAIL)
    return await enable_totp(client)


async def _login(client: httpx.AsyncClient, code: str, email: str = EMAIL) -> httpx.Response:
    await client.post("/auth/logout")
    return await client.post("/auth/totp/login", json={"email": email, "code": code})


async def test_enrolment_returns_qr_and_uri(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), EMAIL)
    setup = (await client.post("/account/totp/setup")).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/Keygate:totp%40example.com?secret=")
    assert setup["qr_svg_data_uri"].startswith("data:image/svg+xml")
    assert len(setup["secret"]) == 32
    # Not enabled until a code is confirmed.
    assert (await client.get("/account")).json()["totp_enabled"] is False


async def test_secret_encrypted_at_rest_and_bound_to_user(
    secret: str, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    async with db_sessionmaker() as db:
        row = (await db.execute(select(TotpCredential))).scalar_one()
    assert secret not in row.encrypted_secret
    assert row.encrypted_secret.startswith("dev:")
    enc = Encryptor.from_settings(make_settings())
    assert enc.decrypt(row.encrypted_secret, b"totp:" + row.user_id.bytes).decode() == secret
    # Copied onto another user's row, the ciphertext no longer decrypts.
    with pytest.raises(DecryptionError):
        enc.decrypt(row.encrypted_secret, b"totp:" + uuid.uuid4().bytes)


async def test_confirm_rejects_wrong_code(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), EMAIL)
    await client.post("/account/totp/setup")
    assert (await client.post("/account/totp/confirm", json={"code": "000000"})).status_code == 400


async def test_totp_sign_in(client: httpx.AsyncClient, secret: str) -> None:
    resp = await _login(client, pyotp.TOTP(secret).at(int(time.time()) + 30))
    assert resp.status_code == 200, resp.text
    assert (await client.get("/account")).status_code == 200


async def test_reused_code_rejected(client: httpx.AsyncClient, secret: str) -> None:
    code = pyotp.TOTP(secret).at(int(time.time()) + 30)  # next step: newer than enrolment's
    assert (await _login(client, code)).status_code == 200
    assert (await _login(client, code)).status_code == 400


async def test_older_code_rejected_after_newer_one_used(
    client: httpx.AsyncClient, secret: str
) -> None:
    totp = pyotp.TOTP(secret)
    assert (await _login(client, totp.at(int(time.time()) + 30))).status_code == 200
    assert (await _login(client, totp.now())).status_code == 400


def test_window_accepts_adjacent_steps_only() -> None:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    now = 1_700_000_000
    step = int(now // 30)
    assert matching_step(secret, totp.at(now), now) == step
    assert matching_step(secret, totp.at(now - 30), now) == step - 1
    assert matching_step(secret, totp.at(now + 30), now) == step + 1
    assert matching_step(secret, totp.at(now - 60), now) is None
    assert matching_step(secret, "12345", now) is None
    assert matching_step(secret, "abcdef", now) is None


async def test_unknown_email_and_wrong_code_look_the_same(
    client: httpx.AsyncClient, secret: str
) -> None:
    wrong = await _login(client, "000000")
    unknown = await _login(client, pyotp.TOTP(secret).now(), email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 400
    assert wrong.json() == unknown.json()


async def test_totp_brute_force_rate_limited(client: httpx.AsyncClient, secret: str) -> None:
    await client.post("/auth/logout")
    statuses = [
        (
            await client.post("/auth/totp/login", json={"email": EMAIL, "code": f"{i:06d}"})
        ).status_code
        for i in range(6)
    ]
    # One verification per account was spent confirming enrolment; the budget (5 per
    # 15 minutes) is shared by every TOTP check on the account.
    assert statuses[:4] == [400] * 4
    assert statuses[4:] == [429, 429]


async def test_setup_requires_step_up(
    client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), EMAIL)
    await expire_step_up(db_sessionmaker)
    assert (await client.post("/account/totp/setup")).status_code == 403


async def test_cannot_disable_totp_when_it_is_the_only_method(
    client: httpx.AsyncClient, secret: str
) -> None:
    [pk] = (await client.get("/account")).json()["passkeys"]
    assert (await client.delete(f"/account/passkeys/{pk['id']}")).status_code == 204
    resp = await client.delete("/account/totp")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "last_sign_in_method"


async def test_disable_totp(client: httpx.AsyncClient, secret: str, mailer: InMemoryMailer) -> None:
    assert (await client.delete("/account/totp")).status_code == 204
    assert (await client.get("/account")).json()["totp_enabled"] is False
    assert "authenticator app was removed" in mailer.outbox[-1].text
    assert (await _login(client, pyotp.TOTP(secret).at(int(time.time()) + 30))).status_code == 400


async def test_second_setup_while_enabled_conflicts(client: httpx.AsyncClient, secret: str) -> None:
    resp = await client.post("/account/totp/setup")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "totp_already_enabled"
