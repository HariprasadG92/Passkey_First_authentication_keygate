"""Request/response models for the auth API.

WebAuthn responses are validated structurally here (types, sizes) before being handed
to py_webauthn for cryptographic verification, so oversized or malformed input is
rejected early with a 422.
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

B64 = r"^[A-Za-z0-9_-]*={0,2}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignupStartRequest(_Strict):
    email: EmailStr = Field(max_length=320)


class AcceptedResponse(BaseModel):
    message: str


class EmailVerifyRequest(_Strict):
    token: str = Field(min_length=32, max_length=128, pattern=B64)


class EmailVerifyResponse(BaseModel):
    email: str
    next: Literal["register_passkey"]


class AttestationResponseJSON(BaseModel):
    model_config = ConfigDict(extra="ignore")

    clientDataJSON: str = Field(max_length=8192, pattern=B64)  # noqa: N815 - WebAuthn field name
    attestationObject: str = Field(max_length=65536, pattern=B64)  # noqa: N815
    transports: list[str] = Field(default_factory=list, max_length=10)


class RegistrationCredentialJSON(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(max_length=1400, pattern=B64)
    rawId: str = Field(max_length=1400, pattern=B64)  # noqa: N815
    type: Literal["public-key"]
    response: AttestationResponseJSON
    authenticatorAttachment: str | None = Field(default=None, max_length=32)  # noqa: N815
    clientExtensionResults: dict[str, Any] = Field(default_factory=dict)  # noqa: N815


class RegisterVerifyRequest(_Strict):
    credential: RegistrationCredentialJSON
    friendly_name: str | None = Field(default=None, min_length=1, max_length=64)


class AssertionResponseJSON(BaseModel):
    model_config = ConfigDict(extra="ignore")

    clientDataJSON: str = Field(max_length=8192, pattern=B64)  # noqa: N815
    authenticatorData: str = Field(max_length=8192, pattern=B64)  # noqa: N815
    signature: str = Field(max_length=2048, pattern=B64)
    userHandle: str | None = Field(default=None, max_length=128, pattern=B64)  # noqa: N815


class AuthenticationCredentialJSON(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(max_length=1400, pattern=B64)
    rawId: str = Field(max_length=1400, pattern=B64)  # noqa: N815
    type: Literal["public-key"]
    response: AssertionResponseJSON
    authenticatorAttachment: str | None = Field(default=None, max_length=32)  # noqa: N815
    clientExtensionResults: dict[str, Any] = Field(default_factory=dict)  # noqa: N815


class LoginOptionsRequest(_Strict):
    # Optional: omit for usernameless (discoverable credential) sign-in.
    email: EmailStr | None = Field(default=None, max_length=320)


class LoginOptionsResponse(BaseModel):
    ceremony_id: str
    options: dict[str, Any]


class LoginVerifyRequest(_Strict):
    ceremony_id: str = Field(min_length=32, max_length=128, pattern=B64)
    credential: AuthenticationCredentialJSON


class PasskeyOut(BaseModel):
    id: uuid.UUID
    friendly_name: str
    created_at: datetime
    last_used_at: datetime | None
    backup_eligible: bool
    backup_state: bool
    transports: list[str]


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    email_verified: bool
    display_name: str


class SessionOut(BaseModel):
    authenticated: bool
    level: Literal["registration", "full"] | None = None
    user: UserOut | None = None
    csrf_token: str


class AccountOut(BaseModel):
    user: UserOut
    passkeys: list[PasskeyOut]
