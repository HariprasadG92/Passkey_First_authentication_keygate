"""WebAuthn (passkey) registration and authentication ceremonies.

Challenges
    Every ceremony gets a fresh 32-byte random challenge stored server-side in Redis
    with a 5-minute TTL. Verification fetches it with GETDEL, so each challenge can be
    used at most once and a captured response can't be replayed.

Binding
    Registration challenges are keyed by the session that requested them; sign-in
    challenges by a random ``ceremony_id`` handed to the browser (there is no session
    yet). Responses must come from an allowed origin and target our RP ID.

Sign counter
    py_webauthn's own counter check runs *before* signature verification and only
    raises a generic error. We pass a current count of 0 to skip it, then compare the
    counters ourselves *after* the signature has been verified. Only a correctly signed
    assertion with a counter that went backwards can raise the cloned-authenticator
    alarm, and it is reported separately (high-severity audit event).
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    options_to_json_dict,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from keygate.auth.models import Session, User, UserStatus, WebAuthnCredential
from keygate.auth.schemas import AuthenticationCredentialJSON, RegistrationCredentialJSON
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.security.tokens import hmac_sha256

CHALLENGE_BYTES = 32
DECOY_CREDENTIAL_BYTES = 32
_KNOWN_TRANSPORTS = {t.value for t in AuthenticatorTransport}


class PasskeyError(Exception):
    """A ceremony failed. ``reason`` is for the audit log only; clients get a generic
    message so failures can't be used as an oracle."""

    def __init__(
        self,
        reason: str,
        *,
        user_id: uuid.UUID | None = None,
        credential: WebAuthnCredential | None = None,
        suspicious: bool = False,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        # Plain values, not ORM objects: callers roll back (expiring instances) before
        # they read these for the audit log.
        self.user_id = user_id
        self.credential_id = credential.id if credential is not None else None
        self.suspicious = suspicious


@dataclass(frozen=True)
class AuthenticatedPasskey:
    user: User
    credential: WebAuthnCredential


def _transports(values: list[str]) -> list[AuthenticatorTransport]:
    return [AuthenticatorTransport(v) for v in values if v in _KNOWN_TRANSPORTS]


class PasskeyService:
    def __init__(self, settings: Settings, redis: Redis) -> None:
        self._settings = settings
        self._redis = redis

    # ------------------------------------------------------------------ challenges

    async def _store_challenge(self, key: str, challenge: bytes) -> None:
        await self._redis.set(
            key, bytes_to_base64url(challenge), ex=self._settings.webauthn_challenge_ttl_seconds
        )

    async def _take_challenge(self, key: str) -> bytes:
        """Fetch and delete atomically: a challenge can be used once."""
        value = await self._redis.getdel(key)
        if value is None:
            raise PasskeyError("challenge_missing_or_expired")
        return base64url_to_bytes(value.decode() if isinstance(value, bytes) else str(value))

    @staticmethod
    def _registration_key(session: Session) -> str:
        return f"webauthn:reg:{session.id}"

    @staticmethod
    def _authentication_key(ceremony_id: str) -> str:
        return f"webauthn:auth:{hashlib.sha256(ceremony_id.encode()).hexdigest()}"

    @property
    def _timeout_ms(self) -> int:
        return self._settings.webauthn_challenge_ttl_seconds * 1000

    # ---------------------------------------------------------------- registration

    async def registration_options(
        self, db: AsyncSession, user: User, session: Session
    ) -> dict[str, Any]:
        existing = (
            await db.execute(
                select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
            )
        ).scalars()
        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        options = generate_registration_options(
            rp_id=self._settings.webauthn_rp_id,
            rp_name=self._settings.webauthn_rp_name,
            user_id=user.webauthn_user_handle,
            user_name=user.email,
            user_display_name=user.display_name,
            challenge=challenge,
            timeout=self._timeout_ms,
            authenticator_selection=AuthenticatorSelectionCriteria(
                # Discoverable credentials enable usernameless sign-in.
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            # Stop the same authenticator being registered twice on this account.
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=c.credential_id, transports=_transports(c.transports)
                )
                for c in existing
            ],
        )
        await self._store_challenge(self._registration_key(session), challenge)
        return options_to_json_dict(options)

    async def verify_registration(
        self,
        db: AsyncSession,
        user: User,
        session: Session,
        credential: RegistrationCredentialJSON,
        friendly_name: str | None,
    ) -> WebAuthnCredential:
        challenge = await self._take_challenge(self._registration_key(session))
        try:
            verified = verify_registration_response(
                credential=credential.model_dump(),
                expected_challenge=challenge,
                expected_rp_id=self._settings.webauthn_rp_id,
                expected_origin=self._settings.webauthn_origins,
                require_user_verification=True,
            )
        except WebAuthnException as exc:
            raise PasskeyError("registration_verification_failed", user_id=user.id) from exc

        duplicate = (
            await db.execute(
                select(WebAuthnCredential.id).where(
                    WebAuthnCredential.credential_id == verified.credential_id
                )
            )
        ).first()
        if duplicate is not None:
            raise PasskeyError("credential_already_registered", user_id=user.id)

        row = WebAuthnCredential(
            user_id=user.id,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            transports=[t for t in credential.response.transports if t in _KNOWN_TRANSPORTS],
            aaguid=verified.aaguid,
            backup_eligible=verified.credential_device_type is CredentialDeviceType.MULTI_DEVICE,
            backup_state=verified.credential_backed_up,
            friendly_name=(friendly_name or "Passkey").strip()[:64] or "Passkey",
        )
        db.add(row)
        await db.flush()
        return row

    # -------------------------------------------------------------- authentication

    def _decoy_descriptors(self, email: str) -> list[PublicKeyCredentialDescriptor]:
        """Stable fake credential for unknown emails, so the options for a non-existent
        account look like those of a real one (no account enumeration)."""
        fake_id = hmac_sha256(self._settings.secret_key.get_secret_value(), "decoy-cred", email)
        return [
            PublicKeyCredentialDescriptor(
                id=fake_id[:DECOY_CREDENTIAL_BYTES],
                transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID],
            )
        ]

    async def authentication_options(
        self, db: AsyncSession, email: str | None
    ) -> tuple[str, dict[str, Any]]:
        allow: list[PublicKeyCredentialDescriptor] = []
        if email is not None:
            user = (
                (
                    await db.execute(
                        select(User)
                        .options(joinedload(User.credentials))
                        .where(User.email == email)
                    )
                )
                .unique()
                .scalar_one_or_none()
            )
            if user is not None and user.credentials:
                allow = [
                    PublicKeyCredentialDescriptor(
                        id=c.credential_id, transports=_transports(c.transports)
                    )
                    for c in user.credentials
                ]
            else:
                allow = self._decoy_descriptors(email)

        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        options = generate_authentication_options(
            rp_id=self._settings.webauthn_rp_id,
            challenge=challenge,
            timeout=self._timeout_ms,
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        ceremony_id = secrets.token_urlsafe(32)
        await self._store_challenge(self._authentication_key(ceremony_id), challenge)
        return ceremony_id, options_to_json_dict(options)

    async def step_up_options(
        self, db: AsyncSession, user: User, session: Session
    ) -> dict[str, Any]:
        """Assertion options limited to the signed-in user's own passkeys, with the
        challenge bound to their session."""
        creds = (
            await db.execute(
                select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id)
            )
        ).scalars()
        challenge = secrets.token_bytes(CHALLENGE_BYTES)
        options = generate_authentication_options(
            rp_id=self._settings.webauthn_rp_id,
            challenge=challenge,
            timeout=self._timeout_ms,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=c.credential_id, transports=_transports(c.transports)
                )
                for c in creds
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        await self._store_challenge(self._step_up_key(session), challenge)
        return options_to_json_dict(options)

    @staticmethod
    def _step_up_key(session: Session) -> str:
        return f"webauthn:stepup:{session.id}"

    async def verify_authentication(
        self, db: AsyncSession, ceremony_id: str, credential: AuthenticationCredentialJSON
    ) -> AuthenticatedPasskey:
        challenge = await self._take_challenge(self._authentication_key(ceremony_id))
        return await self._verify_assertion(db, challenge, credential)

    async def verify_step_up(
        self,
        db: AsyncSession,
        user: User,
        session: Session,
        credential: AuthenticationCredentialJSON,
    ) -> AuthenticatedPasskey:
        challenge = await self._take_challenge(self._step_up_key(session))
        return await self._verify_assertion(db, challenge, credential, expected_user_id=user.id)

    async def _verify_assertion(
        self,
        db: AsyncSession,
        challenge: bytes,
        credential: AuthenticationCredentialJSON,
        *,
        expected_user_id: uuid.UUID | None = None,
    ) -> AuthenticatedPasskey:
        try:
            raw_id = base64url_to_bytes(credential.rawId)
        except ValueError as exc:
            raise PasskeyError("malformed_credential_id") from exc
        stored = (
            await db.execute(
                select(WebAuthnCredential)
                .options(joinedload(WebAuthnCredential.user))
                .where(WebAuthnCredential.credential_id == raw_id)
                .with_for_update(of=WebAuthnCredential)
            )
        ).scalar_one_or_none()
        if stored is None:
            raise PasskeyError("unknown_credential")
        user = stored.user
        if expected_user_id is not None and user.id != expected_user_id:
            # Step-up must be done with one of *your* passkeys.
            raise PasskeyError("credential_owner_mismatch", user_id=expected_user_id)

        # For discoverable credentials the authenticator returns the user handle it was
        # registered with; it must belong to the credential's owner.
        handle = credential.response.userHandle
        if handle and base64url_to_bytes(handle) != user.webauthn_user_handle:
            raise PasskeyError("user_handle_mismatch", user_id=user.id, credential=stored)

        try:
            verified = verify_authentication_response(
                credential=credential.model_dump(),
                expected_challenge=challenge,
                expected_rp_id=self._settings.webauthn_rp_id,
                expected_origin=self._settings.webauthn_origins,
                credential_public_key=stored.public_key,
                credential_current_sign_count=0,  # checked below, after the signature
                require_user_verification=True,
            )
        except WebAuthnException as exc:
            raise PasskeyError(
                "authentication_verification_failed", user_id=user.id, credential=stored
            ) from exc

        new_count = verified.new_sign_count
        if (new_count > 0 or stored.sign_count > 0) and new_count <= stored.sign_count:
            raise PasskeyError(
                "sign_count_regression",
                user_id=user.id,
                credential=stored,
                suspicious=True,
            )

        if user.status is not UserStatus.ACTIVE:
            raise PasskeyError("account_not_active", user_id=user.id, credential=stored)

        stored.sign_count = new_count
        stored.backup_state = verified.credential_backed_up
        stored.last_used_at = utcnow()
        return AuthenticatedPasskey(user=user, credential=stored)
