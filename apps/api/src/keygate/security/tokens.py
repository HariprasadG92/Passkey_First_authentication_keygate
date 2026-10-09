"""Random tokens and their storage form.

Bearer secrets (session IDs, magic-link tokens) are generated with ``secrets`` and
stored only as SHA-256 hashes. A fast hash is appropriate here (unlike passwords)
because the inputs are 256-bit random values: there is nothing to brute-force.
"""

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32


def generate_token() -> str:
    """URL-safe random token with 256 bits of entropy."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def hmac_sha256(key: str, *parts: str) -> bytes:
    msg = b"\x00".join(p.encode("utf-8") for p in parts)
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).digest()
