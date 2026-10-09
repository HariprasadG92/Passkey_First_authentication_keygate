"""Consistent error envelope: ``{"error": {"code": ..., "message": ..., "details"?: ...}}``.

Clients get a stable machine-readable ``code`` and a safe human message. Internal details
(stack traces, SQL, library messages) are never returned. Validation errors report *where*
the input was wrong but never echo the submitted values back, since they may be secrets.
"""

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class KeygateError(Exception):
    """An expected error with a stable machine-readable ``code`` for clients."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status_code, headers=headers)


def _code_for_status(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase.lower().replace(" ", "_").replace("-", "_")
    except ValueError:
        return "error"


async def _http_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101 - narrowing for mypy
    message = exc.detail if isinstance(exc.detail, str) else HTTPStatus(exc.status_code).phrase
    return error_response(
        exc.status_code, _code_for_status(exc.status_code), message, headers=exc.headers
    )


async def _validation_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101 - narrowing for mypy
    details = [
        {
            "loc": [str(p) for p in err.get("loc", ())],
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]
    return error_response(422, "validation_error", "Request validation failed.", details)


async def _keygate_error_handler(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, KeygateError)  # noqa: S101 - narrowing for mypy
    return error_response(exc.status_code, exc.code, exc.message)


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(KeygateError, _keygate_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)
