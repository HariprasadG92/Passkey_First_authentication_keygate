"""OAuth 2.0 / OIDC authorization-code flow with PKCE, state, nonce and browser binding.

Starting a flow creates, server-side in Redis (single-use, 10-minute TTL):

* ``state``: random value echoed by the provider; proves the callback answers *our* request.
* ``code_verifier``: PKCE (S256). The authorization code is useless without it, so a code
  intercepted in transit (logs, Referer, malicious app) can't be redeemed.
* ``nonce`` (OIDC): echoed inside the signed ID token, tying that token to this login.
* a **browser binding**: a random value set as an HttpOnly cookie in the browser that
  started the flow; only its hash is stored. The callback must come from that same
  browser. This stops *login CSRF*: an attacker can't send a victim a callback URL
  from the attacker's own flow to sign the victim into the attacker's account.
"""

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass
from typing import Literal

import httpx
from authlib.oauth2.rfc6749.parameters import prepare_grant_uri
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from redis.asyncio import Redis

from keygate.config import Settings
from keygate.social.providers import (
    Provider,
    ProviderError,
    SocialIdentity,
    client_credentials,
    exchange_code,
    github_identity,
    google_identity,
)

Intent = Literal["signin", "link", "stepup"]
PENDING_LINK_SECONDS = 600


class SocialFlowError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class StartedFlow:
    authorize_url: str
    binding: str  # value for the browser-binding cookie


@dataclass(frozen=True)
class CompletedFlow:
    intent: Intent
    identity: SocialIdentity
    user_id: uuid.UUID | None  # set for link/stepup: who started the flow


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def redirect_uri(settings: Settings, provider: Provider) -> str:
    return f"{settings.public_url}/api/auth/social/{provider.id}/callback"


class SocialLogin:
    def __init__(self, settings: Settings, redis: Redis, http: httpx.AsyncClient) -> None:
        self._settings = settings
        self._redis = redis
        self._http = http

    def _credentials(self, provider: Provider) -> tuple[str, str]:
        creds = client_credentials(self._settings, provider)
        if creds is None:
            raise SocialFlowError("provider_not_configured")
        return creds

    async def start(
        self, provider: Provider, intent: Intent, user_id: uuid.UUID | None
    ) -> StartedFlow:
        client_id, _ = self._credentials(provider)
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43-128
        binding = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32) if provider.is_oidc else None

        await self._redis.set(
            f"oauth:state:{_sha256(state)}",
            json.dumps(
                {
                    "provider": provider.id,
                    "intent": intent,
                    "user_id": str(user_id) if user_id else None,
                    "verifier": verifier,
                    "nonce": nonce,
                    "binding": _sha256(binding),
                }
            ),
            ex=self._settings.social_flow_ttl_seconds,
        )
        extra: dict[str, str] = {
            "code_challenge": create_s256_code_challenge(verifier),  # type: ignore[no-untyped-call]
            "code_challenge_method": "S256",
        }
        if nonce:
            extra["nonce"] = nonce
        if provider.id == "google":
            extra["prompt"] = "select_account"
        url = prepare_grant_uri(
            provider.authorize_url,
            client_id=client_id,
            response_type="code",
            redirect_uri=redirect_uri(self._settings, provider),
            scope=provider.scope,
            state=state,
            **extra,
        )
        return StartedFlow(authorize_url=url, binding=binding)

    async def complete(
        self,
        provider: Provider,
        *,
        code: str | None,
        state: str | None,
        error: str | None,
        binding: str | None,
    ) -> CompletedFlow:
        if not state:
            raise SocialFlowError("missing_state")
        # Single use: the state is deleted whether or not the rest succeeds.
        raw = await self._redis.getdel(f"oauth:state:{_sha256(state)}")
        if raw is None:
            raise SocialFlowError("unknown_or_expired_state")
        flow = json.loads(raw)
        if flow["provider"] != provider.id:
            raise SocialFlowError("provider_mismatch")
        if not binding or not hmac.compare_digest(flow["binding"], _sha256(binding)):
            raise SocialFlowError("browser_binding_mismatch")
        if error:
            raise SocialFlowError(f"provider_error:{error[:64]}")
        if not code:
            raise SocialFlowError("missing_code")

        client_id, client_secret = self._credentials(provider)
        try:
            token = await exchange_code(
                self._http,
                provider,
                client_id=client_id,
                client_secret=client_secret,
                code=code,
                redirect_uri=redirect_uri(self._settings, provider),
                code_verifier=flow["verifier"],
            )
            if provider.is_oidc:
                identity = await google_identity(
                    self._http, self._redis, token, client_id=client_id, nonce=flow["nonce"]
                )
            else:
                identity = await github_identity(self._http, token["access_token"])
        except ProviderError as exc:
            raise SocialFlowError(exc.reason) from exc
        except httpx.HTTPError as exc:
            raise SocialFlowError(f"provider_unreachable:{type(exc).__name__}") from exc

        user_id = uuid.UUID(flow["user_id"]) if flow["user_id"] else None
        return CompletedFlow(intent=flow["intent"], identity=identity, user_id=user_id)

    # ------------------------------------------------------------- pending links

    async def stash_pending_link(self, user_id: uuid.UUID, identity: SocialIdentity) -> str:
        """Linking needs an explicit confirmation by the signed-in user. Park the verified
        identity under a random ID that only that user can redeem."""
        pending_id = secrets.token_urlsafe(32)
        await self._redis.set(
            f"oauth:pending:{_sha256(pending_id)}",
            json.dumps(
                {
                    "user_id": str(user_id),
                    "provider": identity.provider,
                    "subject": identity.subject,
                    "email": identity.email,
                    "email_verified": identity.email_verified,
                    "display_name": identity.display_name,
                }
            ),
            ex=PENDING_LINK_SECONDS,
        )
        return pending_id

    async def peek_pending_link(self, pending_id: str, user_id: uuid.UUID) -> SocialIdentity:
        raw = await self._redis.get(f"oauth:pending:{_sha256(pending_id)}")
        return self._pending(raw, user_id)

    async def take_pending_link(self, pending_id: str, user_id: uuid.UUID) -> SocialIdentity:
        raw = await self._redis.getdel(f"oauth:pending:{_sha256(pending_id)}")
        return self._pending(raw, user_id)

    @staticmethod
    def _pending(raw: bytes | str | None, user_id: uuid.UUID) -> SocialIdentity:
        if raw is None:
            raise SocialFlowError("pending_link_missing_or_expired")
        data = json.loads(raw)
        if data["user_id"] != str(user_id):
            raise SocialFlowError("pending_link_wrong_user")
        return SocialIdentity(
            provider=data["provider"],
            subject=data["subject"],
            email=data["email"],
            email_verified=data["email_verified"],
            display_name=data["display_name"],
        )
