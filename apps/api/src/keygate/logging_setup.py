"""Structured logging with structlog.

Standard-library loggers (uvicorn, sqlalchemy, alembic) are routed through the same
processor chain, so every log line has the same shape. A redaction processor scrubs
values whose key looks sensitive, as a safety net: code should never log secrets in
the first place.
"""

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from keygate.config import Settings

REDACTED = "[REDACTED]"
# A key is sensitive if any of its "_", "-" or "." separated segments is in this set,
# e.g. "access_token", "Set-Cookie", "code_verifier", "recovery_code".
_SENSITIVE_SEGMENTS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "tokens",
        "authorization",
        "cookie",
        "cookies",
        "session",
        "otp",
        "totp",
        "challenge",
        "credential",
        "credentials",
        "private",
        "apikey",
        "signature",
        "verifier",
        "recovery",
        "assertion",
        "attestation",
    }
)


def is_sensitive_key(key: object) -> bool:
    return any(seg in _SENSITIVE_SEGMENTS for seg in re.split(r"[_\-.]", str(key).lower()))


def _redact(value: Any) -> Any:
    if isinstance(value, MutableMapping):
        return {k: REDACTED if is_sensitive_key(k) else _redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(_redact(v) for v in value)
    return value


def redact_sensitive(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    """Mask values of sensitive-looking keys, including in nested dicts."""
    for key in list(event_dict):
        if key == "event":
            continue
        if is_sensitive_key(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _redact(event_dict[key])
    return event_dict


def configure_logging(settings: Settings) -> None:
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_sensitive,
    ]
    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_json
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            renderer,
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    # Uvicorn installs its own handlers; let records propagate to ours instead.
    # Access logs are replaced by our request-logging middleware (it redacts query strings).
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").handlers.clear()
    logging.getLogger("uvicorn.access").propagate = False


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.stdlib.get_logger(name)
