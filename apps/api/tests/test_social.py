"""Social login with mocked GitHub and Google.

Provider HTTP calls are intercepted with respx (only the app's outbound client; the
ASGI test transport is unaffected). Google ID tokens are real RS256 JWTs signed with a
test key whose JWKS is served by the mock, so signature and claim validation run for real.
"""

import base64
import hashlib
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.models import AuditEvent
from keygate.auth.email import InMemoryMailer
from keygate.auth.models import User
from keygate.social.models import SocialAccount
from keygate.social.providers import GITHUB, GITHUB_API, GOOGLE, GOOGLE_JWKS_URL
from tests.helpers import expire_step_up, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration

GOOGLE_CLIENT = "google-client.apps.googleusercontent.com"
SIGNING_KEY = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
OTHER_KEY = RSAKey.generate_key(2048, parameters={"kid": "test-key"})


class FakeProviders:
    """Mutable provider state: tests tweak what the 'provider' returns."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.github_user: dict[str, Any] = {"id": 4242, "login": "octocat", "name": "Octo Cat"}
        self.github_emails: list[dict[str, Any]] = [
            {"email": "Octo@Example.com", "primary": True, "verified": True}
        ]
        self.github_token: dict[str, Any] = {"access_token": "gho_test", "token_type": "bearer"}
        self.google_claims: dict[str, Any] = {}
        self.google_key = SIGNING_KEY
        self.token_requests: list[httpx.Request] = []
        self.nonce = ""

        router.post(GITHUB.token_url).mock(side_effect=self._github_token)
        router.get(f"{GITHUB_API}/user").mock(
            side_effect=lambda r: httpx.Response(200, json=self.github_user)
        )
        router.get(f"{GITHUB_API}/user/emails").mock(
            side_effect=lambda r: httpx.Response(200, json=self.github_emails)
        )
        router.post(GOOGLE.token_url).mock(side_effect=self._google_token)
        router.get(GOOGLE_JWKS_URL).mock(
            return_value=httpx.Response(200, json=KeySet([SIGNING_KEY]).as_dict(private=False))
        )

    def _github_token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests.append(request)
        return httpx.Response(200, json=self.github_token)

    def _google_token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests.append(request)
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com",
            "aud": GOOGLE_CLIENT,
            "sub": "google-sub-1",
            "email": "goo@example.com",
            "email_verified": True,
            "name": "Goo Gle",
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            **self.google_claims,
        }
        id_token = jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, self.google_key)
        return httpx.Response(200, json={"access_token": "ya29", "id_token": id_token})


@pytest.fixture
def providers() -> Iterator[FakeProviders]:
    with respx.mock(assert_all_called=False) as router:
        yield FakeProviders(router)


async def start(client: httpx.AsyncClient, provider: str, intent: str = "signin") -> dict[str, str]:
    resp = await client.post(f"/auth/social/{provider}/start", json={"intent": intent})
    assert resp.status_code == 200, resp.text
    query = parse_qs(urlparse(resp.json()["authorize_url"]).query)
    return {k: v[0] for k, v in query.items()}


async def callback(
    client: httpx.AsyncClient, provider: str, state: str, **params: str
) -> httpx.Response:
    return await client.get(
        f"/auth/social/{provider}/callback",
        params={"code": "auth-code", "state": state, **params},
        follow_redirects=False,
    )


async def social_sign_in(
    client: httpx.AsyncClient, providers: FakeProviders, provider: str = "github"
) -> httpx.Response:
    params = await start(client, provider)
    providers.nonce = params.get("nonce", "")
    return await callback(client, provider, params["state"])


async def _count(db_sessionmaker: async_sessionmaker[AsyncSession], model: Any) -> int:
    async with db_sessionmaker() as db:
        return (await db.execute(select(func.count()).select_from(model))).scalar_one()


# ----------------------------------------------------------------- authorize request


async def test_authorize_url_uses_state_pkce_s256_and_exact_redirect(
    client: httpx.AsyncClient, providers: FakeProviders
) -> None:
    params = await start(client, "github")
    assert params["client_id"] == "gh-client"
    assert params["response_type"] == "code"
    assert params["redirect_uri"] == "http://localhost/api/auth/social/github/callback"
    assert params["code_challenge_method"] == "S256"
    assert len(params["state"]) >= 43
    cookie = client.cookies.get("kg_oauth")
    assert cookie
    assert cookie not in str(params)  # the browser binding never leaves this origin


async def test_google_authorize_url_has_nonce(
    client: httpx.AsyncClient, providers: FakeProviders
) -> None:
    params = await start(client, "google")
    assert params["scope"] == "openid email profile"
    assert len(params["nonce"]) >= 43


async def test_token_request_carries_matching_pkce_verifier(
    client: httpx.AsyncClient, providers: FakeProviders
) -> None:
    params = await start(client, "github")
    await callback(client, "github", params["state"])
    form = parse_qs(providers.token_requests[-1].content.decode())
    verifier = form["code_verifier"][0]
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert expected.decode() == params["code_challenge"]
    assert form["redirect_uri"] == ["http://localhost/api/auth/social/github/callback"]


# ------------------------------------------------------------------ sign-in / up


async def test_github_sign_up_creates_verified_account(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    resp = await social_sign_in(client, providers)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/account?welcome=social"
    account = (await client.get("/account")).json()
    assert account["user"]["email"] == "octo@example.com"
    assert account["user"]["email_verified"] is True
    assert account["social_accounts"][0]["provider"] == "github"
    assert account["passkeys"] == []
    # The binding cookie is cleared once the flow completes.
    assert "kg_oauth" not in client.cookies


async def test_returning_github_user_signs_in_to_same_account(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await social_sign_in(client, providers)
    await client.post("/auth/logout")
    # The user renamed their GitHub login and changed email: the numeric ID still matches.
    providers.github_user["login"] = "renamed"
    providers.github_emails[0]["email"] = "new-address@example.com"
    resp = await social_sign_in(client, providers)
    assert resp.headers["location"] == "/account"
    assert await _count(db_sessionmaker, User) == 1


async def test_google_sign_up(client: httpx.AsyncClient, providers: FakeProviders) -> None:
    resp = await social_sign_in(client, providers, "google")
    assert resp.headers["location"] == "/account?welcome=social"
    assert (await client.get("/account")).json()["user"]["email"] == "goo@example.com"


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        ({"nonce": "attacker-nonce"}, "nonce"),
        ({"aud": "someone-elses-client"}, "audience"),
        ({"iss": "https://evil.example"}, "issuer"),
        ({"exp": int(time.time()) - 3600}, "expired"),
    ],
)
async def test_google_id_token_claims_validated(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
    claims: dict[str, Any],
    reason: str,
) -> None:
    providers.google_claims = claims
    resp = await social_sign_in(client, providers, "google")
    assert resp.headers["location"] == "/signin?error=social_failed", reason
    assert await _count(db_sessionmaker, User) == 0


async def test_google_id_token_signed_by_wrong_key_rejected(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    providers.google_key = OTHER_KEY  # same kid, different key: forged token
    resp = await social_sign_in(client, providers, "google")
    assert resp.headers["location"] == "/signin?error=social_failed"
    assert await _count(db_sessionmaker, User) == 0


async def test_google_unverified_email_cannot_sign_up(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    providers.google_claims = {"email_verified": False}
    resp = await social_sign_in(client, providers, "google")
    assert resp.headers["location"] == "/signin?error=social_unverified_email"
    assert await _count(db_sessionmaker, User) == 0


async def test_github_without_verified_primary_email_cannot_sign_up(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    providers.github_emails = [
        {"email": "octo@example.com", "primary": True, "verified": False},
        {"email": "other@example.com", "primary": False, "verified": True},
    ]
    resp = await social_sign_in(client, providers)
    assert resp.headers["location"] == "/signin?error=social_unverified_email"
    assert await _count(db_sessionmaker, User) == 0


async def test_existing_email_is_never_merged_silently(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    providers: FakeProviders,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await sign_up(second_client, mailer, SoftAuthenticator(), "octo@example.com")
    resp = await social_sign_in(client, providers)
    assert resp.headers["location"] == "/signin?error=social_email_in_use"
    assert await _count(db_sessionmaker, SocialAccount) == 0
    assert (await client.get("/account")).status_code == 401


# ------------------------------------------------------------ flow integrity / CSRF


async def test_unknown_state_rejected(client: httpx.AsyncClient, providers: FakeProviders) -> None:
    await start(client, "github")
    resp = await callback(client, "github", "forged-state-value")
    assert resp.headers["location"] == "/signin?error=social_failed"


async def test_state_is_single_use(client: httpx.AsyncClient, providers: FakeProviders) -> None:
    params = await start(client, "github")
    assert (
        (await callback(client, "github", params["state"]))
        .headers["location"]
        .startswith("/account")
    )
    client.cookies.set("kg_oauth", "whatever")
    assert (await callback(client, "github", params["state"])).headers["location"] == (
        "/signin?error=social_failed"
    )


async def test_login_csrf_callback_in_another_browser_rejected(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    """The attacker starts a flow and sends the victim the callback URL: the victim's
    browser doesn't hold the binding cookie, so nothing happens."""
    params = await start(client, "github")  # attacker
    resp = await callback(second_client, "github", params["state"])  # victim
    assert resp.headers["location"] == "/signin?error=social_failed"
    assert (await second_client.get("/account")).status_code == 401
    async with db_sessionmaker() as db:
        reasons = [
            e.details.get("reason") for e in (await db.execute(select(AuditEvent))).scalars()
        ]
    assert "browser_binding_mismatch" in reasons


async def test_state_for_other_provider_rejected(
    client: httpx.AsyncClient, providers: FakeProviders
) -> None:
    params = await start(client, "google")
    resp = await callback(client, "github", params["state"])
    assert resp.headers["location"] == "/signin?error=social_failed"


async def test_provider_error_handled(client: httpx.AsyncClient, providers: FakeProviders) -> None:
    params = await start(client, "github")
    resp = await client.get(
        "/auth/social/github/callback",
        params={"state": params["state"], "error": "access_denied"},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/signin?error=social_failed"


async def test_token_exchange_error_handled(
    client: httpx.AsyncClient, providers: FakeProviders
) -> None:
    providers.github_token = {"error": "bad_verification_code"}
    resp = await social_sign_in(client, providers)
    assert resp.headers["location"] == "/signin?error=social_failed"


async def test_unconfigured_provider_is_404(client: httpx.AsyncClient) -> None:
    assert (await client.post("/auth/social/myspace/start", json={})).status_code == 404
    providers = (await client.get("/auth/social/providers")).json()
    assert {p["id"] for p in providers} == {"github", "google"}


# ------------------------------------------------------------------------ linking


@pytest.fixture
async def passkey_user(client: httpx.AsyncClient, mailer: InMemoryMailer) -> SoftAuthenticator:
    auth = SoftAuthenticator()
    await sign_up(client, mailer, auth, "me@example.com")
    return auth


async def _link(
    client: httpx.AsyncClient, providers: FakeProviders, provider: str = "github"
) -> str:
    params = await start(client, provider, intent="link")
    providers.nonce = params.get("nonce", "")
    resp = await callback(client, provider, params["state"])
    location = resp.headers["location"]
    assert location.startswith("/account/link-social#pending="), location
    return location.split("#pending=")[1]


async def test_link_requires_explicit_confirmation(
    client: httpx.AsyncClient,
    passkey_user: SoftAuthenticator,
    providers: FakeProviders,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    pending = await _link(client, providers)
    # Nothing is linked until the user confirms.
    assert await _count(db_sessionmaker, SocialAccount) == 0
    preview = await client.post("/account/social/pending", json={"pending_id": pending})
    assert preview.json() == {
        "provider": "github",
        "email": "octo@example.com",
        "display_name": "Octo Cat",
    }
    confirm = await client.post("/account/social/confirm", json={"pending_id": pending})
    assert confirm.status_code == 200
    assert "social account was linked" in mailer.outbox[-1].text
    # The pending link is single-use.
    again = await client.post("/account/social/confirm", json={"pending_id": pending})
    assert again.status_code == 404

    # GitHub now signs in to this (differently-emailed) account.
    await client.post("/auth/logout")
    resp = await social_sign_in(client, providers)
    assert resp.headers["location"] == "/account"
    assert (await client.get("/account")).json()["user"]["email"] == "me@example.com"


async def test_link_requires_step_up(
    client: httpx.AsyncClient,
    passkey_user: SoftAuthenticator,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await expire_step_up(db_sessionmaker)
    resp = await client.post("/auth/social/github/start", json={"intent": "link"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "step_up_required"


async def test_link_requires_sign_in(client: httpx.AsyncClient, providers: FakeProviders) -> None:
    resp = await client.post("/auth/social/github/start", json={"intent": "link"})
    assert resp.status_code == 401


async def test_cannot_link_identity_owned_by_another_user(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    passkey_user: SoftAuthenticator,
    providers: FakeProviders,
) -> None:
    await social_sign_in(second_client, providers)  # someone else owns this GitHub identity
    params = await start(client, "github", intent="link")
    resp = await callback(client, "github", params["state"])
    assert resp.headers["location"] == "/account?social_error=linked_elsewhere"


async def test_cannot_link_unverified_identity(
    client: httpx.AsyncClient, passkey_user: SoftAuthenticator, providers: FakeProviders
) -> None:
    providers.github_emails[0]["verified"] = False
    params = await start(client, "github", intent="link")
    resp = await callback(client, "github", params["state"])
    assert resp.headers["location"] == "/account?social_error=unverified_email"


async def test_pending_link_cannot_be_redeemed_by_another_user(
    client: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    passkey_user: SoftAuthenticator,
    providers: FakeProviders,
    mailer: InMemoryMailer,
) -> None:
    pending = await _link(client, providers)
    await sign_up(second_client, mailer, SoftAuthenticator(), "eve@example.com")
    resp = await second_client.post("/account/social/confirm", json={"pending_id": pending})
    assert resp.status_code == 404


async def test_unlink_respects_last_method(
    client: httpx.AsyncClient, providers: FakeProviders, mailer: InMemoryMailer
) -> None:
    await social_sign_in(client, providers)  # GitHub-only account
    [linked] = (await client.get("/account")).json()["social_accounts"]
    resp = await client.delete(f"/account/social/{linked['id']}")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "last_sign_in_method"

    # A fresh social sign-in satisfies step-up, so a passkey can be added right away...
    options = (await client.post("/account/passkeys/register/options")).json()
    added = await client.post(
        "/account/passkeys/register/verify",
        json={"credential": SoftAuthenticator().create(options)},
    )
    assert added.status_code == 200
    # ...after which GitHub can be unlinked.
    assert (await client.delete(f"/account/social/{linked['id']}")).status_code == 204
    assert "social account was unlinked" in mailer.outbox[-1].text


# ------------------------------------------------------------------------ step-up


async def test_step_up_with_linked_social_account(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await social_sign_in(client, providers)
    await expire_step_up(db_sessionmaker)
    assert (await client.post("/account/recovery-codes")).status_code == 403

    params = await start(client, "github", intent="stepup")
    resp = await callback(client, "github", params["state"])
    assert resp.headers["location"] == "/account?stepped_up=1"
    assert (await client.post("/account/recovery-codes")).status_code == 200


async def test_step_up_with_a_different_social_identity_fails(
    client: httpx.AsyncClient,
    providers: FakeProviders,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await social_sign_in(client, providers)
    await expire_step_up(db_sessionmaker)
    providers.github_user["id"] = 9999  # a different GitHub account
    params = await start(client, "github", intent="stepup")
    resp = await callback(client, "github", params["state"])
    assert resp.headers["location"] == "/account?social_error=stepup_failed"
    assert (await client.post("/account/recovery-codes")).status_code == 403
