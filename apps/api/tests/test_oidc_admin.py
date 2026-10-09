"""OIDC client registration (admin API) and operator CLI commands."""

from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate import cli
from keygate.auth.email import InMemoryMailer
from keygate.config import Settings
from keygate.oidc.models import OAuthClient, SigningKey
from keygate.security.tokens import hash_token
from tests.helpers import expire_step_up, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration

NEW_CLIENT: dict[str, Any] = {
    "name": "My App",
    "confidential": True,
    "redirect_uris": ["https://app.example.com/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/"],
    "allowed_scopes": ["openid", "email"],
}


@pytest.fixture
async def admin(
    client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
) -> httpx.AsyncClient:
    await sign_up(client, mailer, SoftAuthenticator(), "root@example.com")
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert await cli.grant_role("root@example.com", "admin") == 0
    return client


async def test_register_client_shows_secret_once_and_stores_hash(
    admin: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    resp = await admin.post("/admin/clients", json=NEW_CLIENT)
    assert resp.status_code == 201
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["client_id"].startswith("kg_")
    secret = body["client_secret"]
    assert len(secret) >= 43

    listed = (await admin.get("/admin/clients")).json()
    assert "client_secret" not in listed[0]
    async with db_sessionmaker() as db:
        row = (await db.execute(select(OAuthClient))).scalar_one()
    assert row.client_secret_hash == hash_token(secret)


async def test_rotate_secret_invalidates_old(
    admin: httpx.AsyncClient, db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    created = (await admin.post("/admin/clients", json=NEW_CLIENT)).json()
    rotated = (await admin.post(f"/admin/clients/{created['id']}/secret")).json()
    assert rotated["client_secret"] != created["client_secret"]
    async with db_sessionmaker() as db:
        row = (await db.execute(select(OAuthClient))).scalar_one()
    assert row.client_secret_hash == hash_token(rotated["client_secret"])


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ({"redirect_uris": ["http://evil.example/cb"]}, "loopback"),
        ({"redirect_uris": ["https://app.example.com/cb#frag"]}, "fragment"),
        ({"redirect_uris": ["javascript:alert(1)"]}, "https"),
        ({"allowed_scopes": ["email"]}, "openid"),
        ({"allowed_scopes": ["openid", "admin"]}, "Unknown scopes"),
    ],
)
async def test_registration_validation(
    admin: httpx.AsyncClient, change: dict[str, object], fragment: str
) -> None:
    resp = await admin.post("/admin/clients", json={**NEW_CLIENT, **change})
    assert resp.status_code == 422
    assert fragment in str(resp.json())


async def test_update_and_disable_client(admin: httpx.AsyncClient) -> None:
    created = (await admin.post("/admin/clients", json=NEW_CLIENT)).json()
    updated = await admin.put(
        f"/admin/clients/{created['id']}",
        json={**NEW_CLIENT, "name": "Renamed", "allowed_scopes": ["openid"]},
    )
    assert updated.json()["name"] == "Renamed"
    flip = await admin.put(
        f"/admin/clients/{created['id']}", json={**NEW_CLIENT, "confidential": False}
    )
    assert flip.json()["error"]["code"] == "client_type_immutable"
    disabled = (await admin.post(f"/admin/clients/{created['id']}/disable")).json()
    assert disabled["disabled"] is True
    # A disabled client can't start a flow.
    resp = await admin.get(
        "/oauth2/authorize",
        params={"client_id": created["client_id"], "redirect_uri": NEW_CLIENT["redirect_uris"][0]},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/oauth/error?error=invalid_client"


async def test_public_client_has_no_secret(admin: httpx.AsyncClient) -> None:
    created = (
        await admin.post("/admin/clients", json={**NEW_CLIENT, "confidential": False})
    ).json()
    assert created["client_secret"] is None
    resp = await admin.post(f"/admin/clients/{created['id']}/secret")
    assert resp.json()["error"]["code"] == "public_client"


async def test_client_admin_requires_permission_and_step_up(
    admin: httpx.AsyncClient,
    second_client: httpx.AsyncClient,
    mailer: InMemoryMailer,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await sign_up(second_client, mailer, SoftAuthenticator(), "pleb@example.com")
    assert (await second_client.get("/admin/clients")).status_code == 403
    assert (await second_client.post("/admin/clients", json=NEW_CLIENT)).status_code == 403
    await expire_step_up(db_sessionmaker)
    resp = await admin.post("/admin/clients", json=NEW_CLIENT)
    assert resp.json()["error"]["code"] == "step_up_required"
    assert (await admin.get("/admin/clients")).status_code == 200


# ------------------------------------------------------------------------ CLI


async def test_cli_ensure_client_is_idempotent(
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    kwargs: dict[str, object] = {
        "client_id": "notes-demo",
        "name": "Notes",
        "redirect_uris": ["http://127.0.0.1:3001/api/auth/callback"],
        "post_logout_redirect_uris": ["http://127.0.0.1:3001/"],
        "scopes": ["openid", "profile"],
    }
    assert await cli.ensure_client(secret="a" * 40, **kwargs) == 0  # type: ignore[arg-type]
    assert await cli.ensure_client(secret="b" * 40, **kwargs) == 0  # type: ignore[arg-type]
    assert await cli.ensure_client(secret="short", **kwargs) == 1  # type: ignore[arg-type]
    async with db_sessionmaker() as db:
        rows = list((await db.execute(select(OAuthClient))).scalars())
    assert len(rows) == 1
    assert rows[0].client_secret_hash == hash_token("b" * 40)


async def test_cli_rotate_signing_key(
    client: httpx.AsyncClient,
    settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await client.get("/oauth2/jwks")  # creates the first key
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert await cli.rotate_signing_key() == 0
    async with db_sessionmaker() as db:
        keys = list((await db.execute(select(SigningKey))).scalars())
    assert len(keys) == 2
    assert sum(k.retired_at is None for k in keys) == 1


def test_cli_parses_ensure_client(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def fake(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "ensure_client", fake)
    monkeypatch.setenv("NOTES_SECRET", "z" * 40)
    code = cli.main(
        [
            "ensure-client",
            "--client-id",
            "notes-demo",
            "--name",
            "Notes",
            "--secret-env",
            "NOTES_SECRET",
            "--redirect-uri",
            "http://127.0.0.1:3001/cb",
            "--scopes",
            "openid profile",
        ]
    )
    assert code == 0
    assert captured["secret"] == "z" * 40
    assert captured["scopes"] == ["openid", "profile"]
