"""Pure-ASGI middleware applied to every HTTP request.

One middleware handles the cross-cutting concerns that must wrap *every* response,
including unexpected errors:

* assigns a request ID (accepts a well-formed inbound ``X-Request-ID``, else generates one)
  and binds it to the structlog context so every log line for the request carries it;
* logs one access line per request (method, path, status, duration). The query string
  is deliberately *not* logged because OAuth codes and magic-link tokens travel there;
* sets security headers on every response;
* turns unhandled exceptions into a generic 500 so internals never leak to clients.

Written as raw ASGI rather than ``BaseHTTPMiddleware`` to avoid buffering and
contextvar-propagation pitfalls.
"""

import re
import secrets
import time

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from keygate.errors import error_response
from keygate.logging_setup import get_logger

log = get_logger("keygate.access")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"})

# The API only ever returns JSON, so the CSP can be maximally strict.
_BASE_HEADERS: dict[str, str] = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store",
}
_HSTS = "max-age=63072000; includeSubDomains"


def _resolve_request_id(scope: Scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"x-request-id":
            candidate: str = value.decode("latin-1")
            if _REQUEST_ID_RE.fullmatch(candidate):
                return candidate
            break
    return secrets.token_hex(16)


class SecurityMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool, docs_enabled: bool) -> None:
        self.app = app
        self.hsts = hsts
        self.docs_enabled = docs_enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = _resolve_request_id(scope)
        path: str = scope["path"]
        # Behind the gateway the app is mounted at root_path (/api); match routes without it.
        root_path: str = scope.get("root_path", "")
        route_path = path.removeprefix(root_path) if root_path else path
        start = time.perf_counter()
        status_code = 500
        response_started = False

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                self._apply_headers(headers, route_path)
                headers["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            log.exception("unhandled_exception", method=scope["method"], path=path)
            if response_started:
                raise
            response = error_response(500, "internal_error", "An unexpected error occurred.")
            await response(scope, receive, send_wrapper)
        finally:
            log.info(
                "request",
                method=scope["method"],
                path=path,
                status=status_code,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
                client_ip=scope["client"][0] if scope.get("client") else None,
            )
            structlog.contextvars.clear_contextvars()

    def _apply_headers(self, headers: MutableHeaders, path: str) -> None:
        for name, value in _BASE_HEADERS.items():
            # Swagger UI needs scripts/styles; docs are disabled in production anyway.
            if name == "Content-Security-Policy" and self.docs_enabled and path in _DOCS_PATHS:
                continue
            headers.setdefault(name, value)
        if self.hsts:
            headers["Strict-Transport-Security"] = _HSTS
