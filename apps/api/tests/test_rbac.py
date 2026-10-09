import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate import cli
from keygate.audit.models import AuditEvent
from keygate.auth.email import InMemoryMailer
from keygate.config import Settings
from tests.helpers import expire_step_up, sign_in, sign_up
from tests.soft_authenticator import SoftAuthenticator

pytestmark = pytest.mark.integration

ClientFactory = Callable[[], Awaitable[httpx.AsyncClient]]


@dataclass
class Actor:
    client: httpx.AsyncClient
    auth: SoftAuthenticator
    email: str
    id: str


async def grant(monkeypatch: pytest.MonkeyPatch, settings: Settings, email: str, role: str) -> None:
    """Grant via the operator CLI (the real bootstrap path), against the test database."""
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert await cli.grant_role(email, role) == 0


@pytest.fixture
def make_actor(
    client_factory: ClientFactory,
    mailer: InMemoryMailer,
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
) -> Callable[..., Awaitable[Actor]]:
    async def make(email: str, role: str | None = None) -> Actor:
        c = await client_factory()
        auth = SoftAuthenticator()
        body = await sign_up(c, mailer, auth, email)
        if role:
            await grant(monkeypatch, settings, email, role)
        return Actor(c, auth, email, body["user"]["id"])

    return make


@pytest.fixture
async def cast(make_actor: Callable[..., Awaitable[Actor]]) -> dict[str, Actor]:
    return {
        "admin": await make_actor("admin@example.com", "admin"),
        "auditor": await make_actor("auditor@example.com", "auditor"),
        "user": await make_actor("user@example.com"),
        "victim": await make_actor("victim@example.com"),
    }


# ----------------------------------------------------------- authorization matrix

READ = {"anonymous": 401, "user": 403, "auditor": 200, "admin": 200}
WRITE = {"anonymous": 401, "user": 403, "auditor": 403, "admin": 200}

MATRIX = [
    ("GET", "/admin/users", None, READ),
    ("GET", "/admin/users/{victim}", None, READ),
    ("GET", "/admin/roles", None, READ),
    ("GET", "/admin/audit", None, READ),
    ("POST", "/admin/users/{victim}/suspend", {"reason": "matrix test"}, WRITE),
    ("POST", "/admin/users/{victim}/unsuspend", None, WRITE),
    ("PUT", "/admin/users/{victim}/roles", {"roles": ["auditor"]}, WRITE),
    ("POST", "/admin/users/{victim}/sessions/revoke", None, WRITE),
]


@pytest.mark.parametrize("who", ["anonymous", "user", "auditor", "admin"])
@pytest.mark.parametrize(("method", "path", "body", "expected"), MATRIX)
async def test_authorization_matrix(
    cast: dict[str, Actor],
    client_factory: ClientFactory,
    who: str,
    method: str,
    path: str,
    body: dict[str, object] | None,
    expected: dict[str, int],
) -> None:
    caller = await client_factory() if who == "anonymous" else cast[who].client
    url = path.format(victim=cast["victim"].id)
    resp = await caller.request(method, url, json=body)
    assert resp.status_code == expected[who], f"{who} {method} {path}: {resp.text}"


async def test_denials_are_audited(
    cast: dict[str, Actor], db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    await cast["user"].client.get("/admin/users")
    async with db_sessionmaker() as db:
        [event] = (
            await db.execute(select(AuditEvent).where(AuditEvent.event_type == "authz.denied"))
        ).scalars()
    assert str(event.actor_user_id) == cast["user"].id
    assert event.details == {"missing": ["users:read"]}


async def test_session_exposes_permissions_for_ui_only(cast: dict[str, Actor]) -> None:
    admin = (await cast["admin"].client.get("/auth/session")).json()["permissions"]
    auditor = (await cast["auditor"].client.get("/auth/session")).json()["permissions"]
    user = (await cast["user"].client.get("/auth/session")).json()["permissions"]
    assert set(admin) >= {"users:read", "users:write", "roles:assign", "audit:read"}
    assert auditor == ["audit:read", "users:read"]
    assert user == []


# ------------------------------------------------------------------- admin safety


async def test_admin_mutations_require_step_up_but_permission_is_checked_first(
    cast: dict[str, Actor], db_sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    await expire_step_up(db_sessionmaker)
    url = f"/admin/users/{cast['victim'].id}/suspend"
    as_admin = await cast["admin"].client.post(url, json={"reason": "test"})
    as_auditor = await cast["auditor"].client.post(url, json={"reason": "test"})
    assert as_admin.json()["error"]["code"] == "step_up_required"
    assert as_auditor.json()["error"]["code"] == "forbidden"


async def test_admin_cannot_suspend_self_or_change_own_roles(cast: dict[str, Actor]) -> None:
    admin = cast["admin"]
    suspend = await admin.client.post(f"/admin/users/{admin.id}/suspend", json={"reason": "oops"})
    roles = await admin.client.put(f"/admin/users/{admin.id}/roles", json={"roles": []})
    assert suspend.json()["error"]["code"] == "cannot_suspend_self"
    assert roles.json()["error"]["code"] == "cannot_change_own_roles"


async def test_two_admins_cannot_demote_each_other_to_zero(
    cast: dict[str, Actor], make_actor: Callable[..., Awaitable[Actor]]
) -> None:
    a = cast["admin"]
    b = await make_actor("admin2@example.com", "admin")
    results = await asyncio.gather(
        a.client.put(f"/admin/users/{b.id}/roles", json={"roles": []}),
        b.client.put(f"/admin/users/{a.id}/roles", json={"roles": []}),
    )
    statuses = sorted(r.status_code for r in results)
    assert statuses[0] == 200
    assert statuses[1] in (403, 409)  # lost the permission, or hit the last-admin rule
    admins = (await a.client.get("/admin/users", params={"role": "admin"})).json()
    if admins.get("total") is None:  # a was the one demoted
        admins = (await b.client.get("/admin/users", params={"role": "admin"})).json()
    assert admins["total"] == 1


async def test_unknown_role_rejected(cast: dict[str, Actor]) -> None:
    resp = await cast["admin"].client.put(
        f"/admin/users/{cast['victim'].id}/roles", json={"roles": ["superuser"]}
    )
    assert resp.json()["error"]["code"] == "unknown_role"


# ----------------------------------------------------------- suspension and roles


async def test_suspension_revokes_sessions_and_blocks_sign_in(cast: dict[str, Actor]) -> None:
    victim = cast["victim"]
    resp = await cast["admin"].client.post(
        f"/admin/users/{victim.id}/suspend", json={"reason": "abuse report #42"}
    )
    assert resp.json()["status"] == "suspended"
    assert (await victim.client.get("/account")).status_code == 401
    assert (await sign_in(victim.client, victim.auth)).status_code == 400

    await cast["admin"].client.post(f"/admin/users/{victim.id}/unsuspend")
    assert (await sign_in(victim.client, victim.auth)).status_code == 200


async def test_granting_a_role_forces_fresh_sign_in(cast: dict[str, Actor]) -> None:
    victim = cast["victim"]
    resp = await cast["admin"].client.put(
        f"/admin/users/{victim.id}/roles", json={"roles": ["auditor"]}
    )
    assert resp.json()["roles"] == ["auditor", "user"]
    # The pre-grant session is gone; the new role is used from a fresh session.
    assert (await victim.client.get("/admin/audit")).status_code == 401
    await sign_in(victim.client, victim.auth)
    assert (await victim.client.get("/admin/audit")).status_code == 200


async def test_revoking_a_role_takes_effect_immediately(cast: dict[str, Actor]) -> None:
    auditor = cast["auditor"]
    assert (await auditor.client.get("/admin/audit")).status_code == 200
    await cast["admin"].client.put(f"/admin/users/{auditor.id}/roles", json={"roles": []})
    # No re-login needed: permissions are resolved on every request.
    assert (await auditor.client.get("/admin/audit")).status_code == 403


async def test_admin_revokes_users_sessions(cast: dict[str, Actor]) -> None:
    victim = cast["victim"]
    resp = await cast["admin"].client.post(f"/admin/users/{victim.id}/sessions/revoke")
    assert resp.json() == {"revoked": 1}
    assert (await victim.client.get("/account")).status_code == 401


# ------------------------------------------------------------------------- search


async def test_user_search_and_filters(cast: dict[str, Actor]) -> None:
    admin = cast["admin"].client
    by_q = (await admin.get("/admin/users", params={"q": "VICTIM"})).json()
    assert [u["email"] for u in by_q["items"]] == ["victim@example.com"]
    by_role = (await admin.get("/admin/users", params={"role": "auditor"})).json()
    assert [u["email"] for u in by_role["items"]] == ["auditor@example.com"]
    paged = (await admin.get("/admin/users", params={"limit": 2})).json()
    assert paged["total"] == 4
    assert len(paged["items"]) == 2


async def test_search_wildcards_are_literal(cast: dict[str, Actor]) -> None:
    """'%' and '_' are escaped: they can't be used to match everything."""
    admin = cast["admin"].client
    for q in ("%", "_", "%%"):
        assert (await admin.get("/admin/users", params={"q": q})).json()["total"] == 0


async def test_admin_user_detail_has_no_secrets(cast: dict[str, Actor]) -> None:
    detail = (await cast["admin"].client.get(f"/admin/users/{cast['victim'].id}")).json()
    assert detail["passkeys"] == 1
    assert len(detail["sessions"]) == 1
    text = str(detail).lower()
    for forbidden in ("public_key", "token", "secret", "handle", "hash"):
        assert forbidden not in text


# -------------------------------------------------------------------------- audit


async def test_audit_filters_and_cursor_pagination(cast: dict[str, Actor]) -> None:
    auditor = cast["auditor"].client
    victim_id = cast["victim"].id
    signins = (await auditor.get("/admin/audit", params={"event_type": "credential.add"})).json()
    assert len(signins["items"]) == 4  # one passkey per cast member
    about_victim = (await auditor.get("/admin/audit", params={"user_id": victim_id})).json()
    assert all(
        victim_id in (e["actor_user_id"], e["target_user_id"]) for e in about_victim["items"]
    )

    seen: list[str] = []
    cursor = None
    while True:
        params = {"limit": 3, **({"cursor": cursor} if cursor else {})}
        page = (await auditor.get("/admin/audit", params=params)).json()
        seen += [e["id"] for e in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    everything = (await auditor.get("/admin/audit", params={"limit": 100})).json()["items"]
    assert seen == [e["id"] for e in everything]  # complete, ordered, no duplicates
    assert len(seen) == len(set(seen))


async def test_audit_log_is_read_only_over_http(cast: dict[str, Actor]) -> None:
    admin = cast["admin"].client
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert (await admin.request(method, "/admin/audit")).status_code == 405


async def test_bad_cursor_rejected(cast: dict[str, Actor]) -> None:
    resp = await cast["auditor"].client.get("/admin/audit", params={"cursor": "not-a-cursor"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------- bootstrap


async def test_new_accounts_get_default_role(
    client: httpx.AsyncClient, mailer: InMemoryMailer
) -> None:
    await sign_up(client, mailer, SoftAuthenticator(), "fresh@example.com")
    assert (await client.get("/auth/session")).json()["permissions"] == []


async def test_cli_grant_is_audited_and_validates_email(
    cast: dict[str, Actor],
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
    db_sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    async with db_sessionmaker() as db:
        grants = list(
            (
                await db.execute(select(AuditEvent).where(AuditEvent.event_type == "role.grant"))
            ).scalars()
        )
    admin_grant = next(e for e in grants if e.details["roles"] == ["admin"])
    assert admin_grant.details["via"] == "cli"
    assert admin_grant.actor_user_id is None

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert await cli.grant_role("nobody@example.com", "admin") == 1
