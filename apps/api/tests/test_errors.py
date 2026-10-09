import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from keygate.config import Settings
from keygate.main import create_app
from tests.conftest import _client_for


class _Payload(BaseModel):
    email: str
    count: int


def _app_with_test_routes(settings: Settings) -> FastAPI:
    app = create_app(settings)

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("db password is hunter2")

    @app.post("/echo")
    async def echo(payload: _Payload) -> _Payload:
        return payload

    return app


async def test_not_found_uses_error_envelope(client: httpx.AsyncClient) -> None:
    resp = await client.get("/nope")
    assert resp.status_code == 404
    assert resp.json() == {"error": {"code": "not_found", "message": "Not Found"}}


async def test_unhandled_exception_returns_generic_500(settings: Settings) -> None:
    async for client in _client_for(_app_with_test_routes(settings)):
        resp = await client.get("/boom")
    assert resp.status_code == 500
    assert resp.json() == {
        "error": {"code": "internal_error", "message": "An unexpected error occurred."}
    }
    assert "hunter2" not in resp.text
    assert "RuntimeError" not in resp.text
    # Security headers and request ID still applied on the error path.
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "x-request-id" in resp.headers


async def test_validation_error_does_not_echo_input(settings: Settings) -> None:
    async for client in _client_for(_app_with_test_routes(settings)):
        resp = await client.post("/echo", json={"email": "a@b.c", "count": "SECRET-VALUE"})
    assert resp.status_code == 422
    body = resp.json()["error"]
    assert body["code"] == "validation_error"
    assert body["details"][0]["loc"] == ["body", "count"]
    assert "SECRET-VALUE" not in resp.text
