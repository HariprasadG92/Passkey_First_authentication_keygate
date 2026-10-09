"""Authenticated encryption for secrets at rest (AES-256-GCM).

Ciphertext format: ``<key_id>:<base64(nonce || ciphertext+tag)>``.

* The key ID makes rotation possible: add a new key, switch ``encryption_key_id``, and old
  rows stay readable until re-encrypted.
* Associated data (e.g. the owning user's ID) is authenticated but not stored. A ciphertext
  copied onto another user's row fails to decrypt, so an attacker with DB write access
  can't move their own TOTP secret onto a victim's account.
* Nonces are 96-bit random values: safe for far more encryptions than this table will see.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keygate.config import Settings

NONCE_BYTES = 12


class DecryptionError(Exception):
    pass


class Encryptor:
    def __init__(self, keys: dict[str, bytes], current_key_id: str) -> None:
        self._keys = {kid: AESGCM(key) for kid, key in keys.items()}
        self._current = current_key_id

    @classmethod
    def from_settings(cls, settings: Settings) -> "Encryptor":
        keys = {
            kid: base64.b64decode(key.get_secret_value())
            for kid, key in settings.encryption_keys.items()
        }
        return cls(keys, settings.encryption_key_id)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> str:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = self._keys[self._current].encrypt(nonce, plaintext, associated_data)
        return f"{self._current}:{base64.b64encode(nonce + ciphertext).decode()}"

    def decrypt(self, token: str, associated_data: bytes) -> bytes:
        key_id, _, payload = token.partition(":")
        aead = self._keys.get(key_id)
        if aead is None or not payload:
            raise DecryptionError("unknown key or malformed ciphertext")
        raw = base64.b64decode(payload)
        try:
            return aead.decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], associated_data)
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc

    def needs_rotation(self, token: str) -> bool:
        return not token.startswith(f"{self._current}:")
