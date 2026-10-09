import httpx
import pytest

from keygate.config import Settings
from keygate.main import create_app
from tests.conftest import _client_for


async def test_liveness_needs_no_dependencies(unreachable_settings: Settings) -> None:
    async for client in _client_for(create_app(unreachable_settings)):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


async def test_readiness_reports_unavailable_without_leaking_details(
    unreachable_settings: Settings,
) -> None:
    async for client in _client_for(create_app(unreachable_settings)):
        resp = await client.get("/health/ready")
    assert resp.status_code == 503
    assert resp.json() == {
        "status": "degraded",
        "checks": {"database": "unavailable", "redis": "unavailable"},
    }
    # No hostnames, ports or driver errors in the body.
    assert "127.0.0.1" not in resp.text
    assert "refused" not in resp.text.lower()


@pytest.mark.integration
async def test_readiness_ok_with_real_dependencies(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}
