import httpx
import pytest

from keygate.config import Settings
from keygate.main import create_app
from tests.conftest import _client_for
from tests.test_config import prod_settings

EXPECTED_HEADERS = {
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


@pytest.mark.parametrize("path", ["/health", "/does-not-exist"])
async def test_security_headers_on_every_response(client: httpx.AsyncClient, path: str) -> None:
    resp = await client.get(path)
    for name, value in EXPECTED_HEADERS.items():
        assert resp.headers.get(name) == value, name


async def test_no_hsts_outside_production(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health")
    assert "strict-transport-security" not in resp.headers


async def test_production_sets_hsts_and_disables_docs() -> None:
    prod = prod_settings()
    async for client in _client_for(create_app(prod)):
        resp = await client.get("/health")
        assert resp.headers["strict-transport-security"].startswith("max-age=63072000")
        for path in ("/docs", "/redoc", "/openapi.json"):
            assert (await client.get(path)).status_code == 404


async def test_generates_request_id(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health")
    assert len(resp.headers["x-request-id"]) == 32


async def test_echoes_well_formed_inbound_request_id(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health", headers={"X-Request-ID": "trace-abc-12345"})
    assert resp.headers["x-request-id"] == "trace-abc-12345"


@pytest.mark.parametrize(
    "bad_id",
    ["short", "x" * 65, "has spaces in it", "inject\\nlog-line", "<script>alert(1)</script>"],
)
async def test_replaces_malformed_inbound_request_id(
    client: httpx.AsyncClient, bad_id: str
) -> None:
    resp = await client.get("/health", headers={"X-Request-ID": bad_id})
    assert resp.headers["x-request-id"] != bad_id
    assert len(resp.headers["x-request-id"]) == 32


async def test_docs_csp_exemption_only_in_development_and_honours_root_path(
    settings: Settings,
) -> None:
    app = create_app(settings)
    async for client in _client_for(app):
        docs = await client.get("/docs")
        assert docs.status_code == 200
        assert "content-security-policy" not in docs.headers
        # Everything else keeps the strict CSP.
        assert "content-security-policy" in (await client.get("/health")).headers

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, root_path="/api"),
            base_url="http://testserver",
        ) as client,
    ):
        docs = await client.get("/api/docs")
        assert docs.status_code == 200
        assert "content-security-policy" not in docs.headers
