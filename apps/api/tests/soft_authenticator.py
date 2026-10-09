"""A software WebAuthn authenticator for tests.

Produces genuine registration (``none`` attestation) and assertion responses signed with
a real P-256 key, so tests exercise the server's actual cryptographic verification
instead of mocking it. Knobs let tests forge specific failures: wrong origin, wrong RP
ID, missing user verification, replayed or rewound sign counters.
"""

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40

AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class SoftCredential:
    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    rp_id: str
    user_handle: bytes
    sign_count: int = 0

    def cose_public_key(self) -> bytes:
        numbers = self.private_key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )


@dataclass
class SoftAuthenticator:
    origin: str = "http://localhost"
    rp_id: str | None = None  # None = use the RP ID from the options
    user_verified: bool = True
    backup_eligible: bool = True
    counter_step: int = 1  # 0 = authenticator without a counter (like synced passkeys)
    credentials: dict[bytes, SoftCredential] = field(default_factory=dict)

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": self.origin, "crossOrigin": False},
            separators=(",", ":"),
        ).encode()

    def _flags(self, *, attested: bool = False) -> int:
        flags = FLAG_UP
        if self.user_verified:
            flags |= FLAG_UV
        if self.backup_eligible:
            flags |= FLAG_BE | FLAG_BS
        if attested:
            flags |= FLAG_AT
        return flags

    def create(self, options: dict[str, Any]) -> dict[str, Any]:
        """Equivalent of navigator.credentials.create() + JSON serialisation."""
        rp_id = self.rp_id or options["rp"]["id"]
        excluded = {b64url_decode(c["id"]) for c in options.get("excludeCredentials", [])}
        if excluded & set(self.credentials):
            raise ValueError("InvalidStateError: authenticator already registered")

        cred = SoftCredential(
            credential_id=os.urandom(32),
            private_key=ec.generate_private_key(ec.SECP256R1()),
            rp_id=rp_id,
            user_handle=b64url_decode(options["user"]["id"]),
        )
        self.credentials[cred.credential_id] = cred

        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", cred.sign_count)
            + AAGUID
            + struct.pack(">H", len(cred.credential_id))
            + cred.credential_id
            + cred.cose_public_key()
        )
        attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"])
        return {
            "id": b64url(cred.credential_id),
            "rawId": b64url(cred.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation_object),
                "transports": ["internal", "hybrid"],
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }

    def get(
        self,
        options: dict[str, Any],
        *,
        credential_id: bytes | None = None,
        sign_count: int | None = None,
        user_handle: bytes | None = None,
    ) -> dict[str, Any]:
        """Equivalent of navigator.credentials.get() + JSON serialisation."""
        allowed = [b64url_decode(c["id"]) for c in options.get("allowCredentials", [])]
        if credential_id is None:
            usable = [cid for cid in self.credentials if not allowed or cid in allowed]
            if not usable:
                raise ValueError("NotAllowedError: no matching credential")
            credential_id = usable[0]
        cred = self.credentials[credential_id]

        if sign_count is None:
            cred.sign_count += self.counter_step
            sign_count = cred.sign_count

        rp_id = self.rp_id or options.get("rpId") or cred.rp_id
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags()])
            + struct.pack(">I", sign_count)
        )
        client_data = self._client_data("webauthn.get", options["challenge"])
        signature = cred.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64url(cred.credential_id),
            "rawId": b64url(cred.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(user_handle if user_handle is not None else cred.user_handle),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }
