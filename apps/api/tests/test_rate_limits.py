"""Every sensitive endpoint is rate-limited, by IP and/or by account.

Each case sends requests until the limit is exhausted and asserts the next one gets a
429 with Retry-After. Limits come from the central policy in ``security/rate_limit.py``.
"""

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from keygate.auth.email import InMemoryMailer
from keygate.security.rate_limit import LIMITS
from tests.helpers import sign_up, start_and_verify_email
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration

B64_43 = "A" * 43
FAKE_ASSERTION = {
    "id": "AAAA",
    "rawId": "AAAA",
    "type": "public-key",
    "response": {"clientDataJSON": "AAAA", "authenticatorData": "AAAA", "signature": "AAAA"},
}

Body = Callable[[int], dict[str, Any]]

ANONYMOUS_CASES: list[tuple[str, str, Body, str]] = [
    # (name, path, body for request i, limit key)
    ("signup by IP", "/auth/signup", lambda i: {"email": f"u{i}@example.com"}, "signup:ip"),
    ("signup by email", "/auth/signup", lambda i: {"email": "same@example.com"}, "signup:email"),
    ("email verify by IP", "/auth/email/verify", lambda i: {"token": B64_43}, "email_verify:ip"),
    (
        "login options by IP",
        "/auth/passkeys/login/options",
        lambda i: {},
        "passkey_login_options:ip",
    ),
    (
        "login verify by IP",
        "/auth/passkeys/login/verify",
        lambda i: {"ceremony_id": B64_43, "credential": FAKE_ASSERTION},
        "passkey_login_verify:ip",
    ),
    (
        "TOTP login by IP",
        "/auth/totp/login",
        lambda i: {"email": f"t{i}@example.com", "code": "000000"},
        "totp_login:ip",
    ),
    (
        "TOTP login by account",
        "/auth/totp/login",
        lambda i: {"email": "t@example.com", "code": "000000"},
        "totp:user",
    ),
    (
        "recovery login by IP",
        "/auth/recovery/login",
        lambda i: {"email": f"r{i}@example.com", "code": "AAAAA-AAAAA"},
        "recovery_login:ip",
    ),
    (
        "recovery login by account",
        "/auth/recovery/login",
        lambda i: {"email": "r@example.com", "code": "AAAAA-AAAAA"},
        "recovery:user",
    ),
    ("social start by IP", "/auth/social/github/start", lambda i: {}, "social_start:ip"),
]


async def _exhaust(send: Callable[[int], Awaitable[httpx.Response]], limit: int) -> httpx.Response:
    for i in range(limit):
        resp = await send(i)
        assert resp.status_code != 429, f"limited early at request {i + 1}/{limit}"
    return await send(limit)


def _assert_limited(resp: httpx.Response) -> None:
    assert resp.status_code == 429, resp.text
    assert int(resp.headers["retry-after"]) >= 1
    assert resp.json()["error"]["code"] == "too_many_requests"


@pytest.mark.parametrize(
    ("name", "path", "body", "key"), ANONYMOUS_CASES, ids=[c[0] for c in ANONYMOUS_CASES]
)
async def test_anonymous_endpoint_limits(
    client: httpx.AsyncClient, name: str, path: str, body: Body, key: str
) -> None:
    resp = await _exhaust(lambda i: client.post(path, json=body(i)), LIMITS[key].limit)
    _assert_limited(resp)


async def test_passkey_registration_options_limited_per_session(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await start_and_verify_email(client, mailer, "reg@example.com")
    resp = await _exhaust(
        lambda i: client.post("/auth/passkeys/register/options"),
        LIMITS["passkey_register:session"].limit,
    )
    _assert_limited(resp)


async def test_step_up_limited_per_session(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), "step@example.com")
    resp = await _exhaust(
        lambda i: client.post("/auth/step-up/passkey/options"), LIMITS["step_up:session"].limit
    )
    _assert_limited(resp)


async def test_email_change_limited_per_account(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), "change@example.com")
    resp = await _exhaust(
        lambda i: client.post("/account/email", json={"new_email": f"n{i}@example.com"}),
        LIMITS["email_change:user"].limit,
    )
    _assert_limited(resp)


async def test_admin_actions_limited_per_admin(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    monkeypatch: pytest.MonkeyPatch,
    settings: Any,
) -> None:
    from keygate import cli

    await sign_up(client, mailer, SoftAuthenticator(), "boss@example.com")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert await cli.grant_role("boss@example.com", "admin") == 0
    victim = await sign_up(second_client, mailer, SoftAuthenticator(), "v@example.com")
    url = f"/admin/users/{victim['user']['id']}/unsuspend"
    resp = await _exhaust(lambda i: client.post(url), LIMITS["admin:actor"].limit)
    _assert_limited(resp)


async def test_token_endpoint_limits(client: httpx.AsyncClient, db_sessionmaker: Any) -> None:
    from keygate.oidc.clients import build_client

    async with db_sessionmaker() as db:
        db.add(
            build_client(
                name="limits",
                confidential=True,
                redirect_uris=["http://127.0.0.1/cb"],
                post_logout_redirect_uris=[],
                allowed_scopes=["openid"],
                created_by=None,
                client_id="limits",
                secret="s" * 43,
            ).client
        )
        await db.commit()
    # Per IP: unauthenticated junk still counts.
    resp = await _exhaust(
        lambda i: client.post("/oauth2/token", data={"grant_type": "x"}),
        LIMITS["token:ip"].limit,
    )
    assert resp.status_code == 429
    assert resp.json()["error"] == "slow_down"


async def test_token_endpoint_limited_per_client(
    client: httpx.AsyncClient, db_sessionmaker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from keygate.oidc.clients import build_client
    from keygate.security import rate_limit

    async with db_sessionmaker() as db:
        db.add(
            build_client(
                name="limits",
                confidential=True,
                redirect_uris=["http://127.0.0.1/cb"],
                post_logout_redirect_uris=[],
                allowed_scopes=["openid"],
                created_by=None,
                client_id="limits",
                secret="s" * 43,
            ).client
        )
        await db.commit()
    # Lift the per-IP limit for this test so the per-client one is what trips.
    monkeypatch.setitem(rate_limit.LIMITS, "token:ip", rate_limit.Limit(10_000, 60))
    resp = await _exhaust(
        lambda i: client.post("/oauth2/token", data={"grant_type": "x"}, auth=("limits", "s" * 43)),
        LIMITS["token:client"].limit,
    )
    assert resp.status_code == 429


def test_every_limit_is_exercised() -> None:
    """Guard against adding a limit without a test that hits it."""
    tested = {c[3] for c in ANONYMOUS_CASES} | {
        "passkey_register:session",
        "step_up:session",
        "email_change:user",
        "admin:actor",
        "token:ip",
        "token:client",
    }
    assert set(LIMITS) == tested
