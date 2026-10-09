"""Redis-backed fixed-window rate limiting.

Each (bucket, key) pair gets a counter that expires with its window. INCR and the first
PEXPIRE run atomically in a Lua script, so concurrent requests can't leave a counter
without a TTL (which would lock a user out forever).

Keys are hashed before use so Redis never holds raw emails or IPs.
"""

import hashlib
from dataclasses import dataclass

from fastapi import HTTPException, status
from redis.asyncio import Redis

from keygate.logging_setup import get_logger

log = get_logger(__name__)

_LUA_HIT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return {current, redis.call('PTTL', KEYS[1])}
"""


@dataclass(frozen=True)
class Limit:
    limit: int
    window_seconds: int


class RateLimitExceededError(HTTPException):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )


class RateLimiter:
    def __init__(self, redis: Redis, *, prefix: str = "rl") -> None:
        self._redis = redis
        self._prefix = prefix

    def _key(self, bucket: str, key: str) -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return f"{self._prefix}:{bucket}:{digest}"

    async def hit(self, bucket: str, key: str, limit: Limit) -> None:
        """Count one request; raise 429 if the limit for this window is exceeded."""
        count, ttl_ms = await self._redis.eval(
            _LUA_HIT, 1, self._key(bucket, key), limit.window_seconds * 1000
        )
        if int(count) > limit.limit:
            retry_after = max(1, (int(ttl_ms) + 999) // 1000)
            log.warning("rate_limited", bucket=bucket, retry_after=retry_after)
            raise RateLimitExceededError(retry_after)


# Central policy so limits are reviewable in one place.
LIMITS: dict[str, Limit] = {
    "signup:ip": Limit(10, 3600),
    "signup:email": Limit(3, 900),
    "email_verify:ip": Limit(20, 900),
    "passkey_login_options:ip": Limit(30, 300),
    "passkey_login_verify:ip": Limit(20, 300),
    "passkey_register:session": Limit(10, 300),
    # TOTP: 10^6 codes, ~3 valid at a time. 5 tries / 15 min / account makes online
    # guessing hopeless (~10^-5 success chance per window).
    "totp:user": Limit(5, 900),
    "totp_login:ip": Limit(20, 900),
    "recovery_login:ip": Limit(10, 900),
    "recovery:user": Limit(5, 3600),
    "step_up:session": Limit(10, 300),
    "email_change:user": Limit(3, 3600),
    "social_start:ip": Limit(30, 300),
}
