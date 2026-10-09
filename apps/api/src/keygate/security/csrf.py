"""CSRF protection: signed double-submit cookie, bound to the session.

* The server sets a readable (non-HttpOnly) cookie holding ``<nonce>.<mac>``, where
  ``mac = HMAC(secret_key, session_binding, nonce)`` and the binding is the hash of the
  current session cookie (or ``anon``).
* For every state-changing request the client must echo the cookie value in the
  ``X-CSRF-Token`` header. A cross-site attacker can make the browser *send* cookies
  but can't *read* them, so it can't produce the header.
* Binding the MAC to the session means a token planted by an attacker (e.g. via a
  cookie-injection bug) is useless once the victim's session changes, and a new token
  is issued on every login and logout.

This is enforced globally (default-deny); routes that legitimately take cross-site
POSTs (OAuth back-channel endpoints, later phases) must be exempted explicitly.
"""

import base64
import hmac
import secrets

from fastapi import HTTPException, Request, Response, status

from keygate.config import Settings
from keygate.security.tokens import hash_token, hmac_sha256

CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
# Paths (relative to the app root) that must accept requests without a CSRF token.
CSRF_EXEMPT_PATHS: set[str] = set()


def _binding(session_token: str | None) -> str:
    return hash_token(session_token).hex() if session_token else "anon"


def _mac(settings: Settings, binding: str, nonce: str) -> str:
    raw = hmac_sha256(settings.secret_key.get_secret_value(), "csrf", binding, nonce)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def issue_csrf_token(settings: Settings, response: Response, session_token: str | None) -> str:
    nonce = secrets.token_urlsafe(16)
    token = f"{nonce}.{_mac(settings, _binding(session_token), nonce)}"
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        httponly=False,  # the SPA must read it to echo it in the header
        secure=settings.secure_cookies,
        samesite="strict",
        path="/",
    )
    return token


def current_or_new_csrf_token(
    settings: Settings, request_cookie: str | None, response: Response, session_token: str | None
) -> str:
    """Reuse the browser's token if it's still valid for this session; otherwise issue one.

    Re-minting on every call would race: a page that read the cookie, then had another
    request replace it before its own request went out, would send a header that no
    longer matches the cookie. Tokens still change whenever the session does."""
    if request_cookie and is_valid_csrf_token(settings, request_cookie, session_token):
        return request_cookie
    return issue_csrf_token(settings, response, session_token)


def is_valid_csrf_token(settings: Settings, token: str, session_token: str | None) -> bool:
    nonce, _, mac = token.partition(".")
    if not nonce or not mac:
        return False
    return hmac.compare_digest(mac, _mac(settings, _binding(session_token), nonce))


async def csrf_protect(request: Request) -> None:
    """Global dependency: reject state-changing requests without a valid token."""
    if request.method in SAFE_METHODS:
        return
    route_path = request.url.path.removeprefix(request.scope.get("root_path", ""))
    if route_path in CSRF_EXEMPT_PATHS:
        return

    settings: Settings = request.app.state.settings
    cookie = request.cookies.get(settings.csrf_cookie_name)
    header = request.headers.get(CSRF_HEADER)
    session_token = request.cookies.get(settings.session_cookie_name)
    if (
        not cookie
        or not header
        or not hmac.compare_digest(cookie, header)
        or not is_valid_csrf_token(settings, header, session_token)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid.")
