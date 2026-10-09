"""Client metadata for sessions and audit events."""

from dataclasses import dataclass

import structlog
from fastapi import Request

MAX_USER_AGENT = 512


@dataclass(frozen=True)
class ClientInfo:
    ip: str | None
    user_agent: str | None
    request_id: str | None


def client_info(request: Request) -> ClientInfo:
    """IP comes from the ASGI scope, which uvicorn fills from X-Forwarded-For only when
    the peer is a trusted proxy (see ADR-003), so it can't be spoofed by clients. The
    request ID is the one the security middleware validated and bound to the log context."""
    ua = request.headers.get("user-agent")
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    return ClientInfo(
        ip=request.client.host if request.client else None,
        user_agent=ua[:MAX_USER_AGENT] if ua else None,
        request_id=request_id if isinstance(request_id, str) else None,
    )
