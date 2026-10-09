"""OIDC client registration (admin). Client secrets are shown exactly once."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from keygate.api.deps import DB, AuditDep, Client, Limiter
from keygate.audit.models import AuditResult, Severity
from keygate.auth.sessions import SessionContext
from keygate.db.types import utcnow
from keygate.errors import KeygateError
from keygate.oidc.clients import build_client, new_client_secret, validate_redirect_uri
from keygate.oidc.models import OAuthClient
from keygate.oidc.scopes import SCOPES
from keygate.rbac.dependencies import require_permission
from keygate.security.rate_limit import LIMITS
from keygate.security.tokens import hash_token

router = APIRouter(prefix="/admin/clients", tags=["admin"])

CanRead = Annotated[SessionContext, Depends(require_permission("clients:read"))]
CanWrite = Annotated[SessionContext, Depends(require_permission("clients:write", step_up=True))]


class ClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    confidential: bool = True
    redirect_uris: list[str] = Field(min_length=1, max_length=10)
    post_logout_redirect_uris: list[str] = Field(default_factory=list, max_length=10)
    allowed_scopes: list[str] = Field(min_length=1, max_length=len(SCOPES))

    @field_validator("redirect_uris", "post_logout_redirect_uris")
    @classmethod
    def _uris(cls, values: list[str]) -> list[str]:
        for uri in values:
            if len(uri) > 2000:
                raise ValueError("URI too long.")
            if error := validate_redirect_uri(uri):
                raise ValueError(error)
        return values

    @field_validator("allowed_scopes")
    @classmethod
    def _scopes(cls, values: list[str]) -> list[str]:
        unknown = set(values) - set(SCOPES)
        if unknown:
            raise ValueError(f"Unknown scopes: {', '.join(sorted(unknown))}.")
        if "openid" not in values:
            raise ValueError("allowed_scopes must include openid.")
        return sorted(set(values))


class ClientOut(BaseModel):
    id: uuid.UUID
    client_id: str
    name: str
    confidential: bool
    redirect_uris: list[str]
    post_logout_redirect_uris: list[str]
    allowed_scopes: list[str]
    created_at: datetime
    disabled: bool


class ClientWithSecret(ClientOut):
    client_secret: str | None = Field(description="Shown only once. Store it securely.")


def _out(c: OAuthClient) -> ClientOut:
    return ClientOut(
        id=c.id,
        client_id=c.client_id,
        name=c.name,
        confidential=c.is_confidential,
        redirect_uris=c.redirect_uris,
        post_logout_redirect_uris=c.post_logout_redirect_uris,
        allowed_scopes=c.allowed_scopes,
        created_at=c.created_at,
        disabled=c.disabled_at is not None,
    )


async def _get(db: DB, pk: uuid.UUID) -> OAuthClient:
    row = await db.get(OAuthClient, pk)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found.")
    return row


@router.get("", response_model=list[ClientOut])
async def list_clients(_: CanRead, db: DB) -> list[ClientOut]:
    rows = (await db.execute(select(OAuthClient).order_by(OAuthClient.created_at))).scalars()
    return [_out(c) for c in rows]


@router.post("", response_model=ClientWithSecret, status_code=status.HTTP_201_CREATED)
async def create_client(
    body: ClientIn,
    ctx: CanWrite,
    response: Response,
    db: DB,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> ClientWithSecret:
    actor = ctx.user.id
    await limiter.hit("admin:actor", str(actor), LIMITS["admin:actor"])
    created = build_client(
        name=body.name,
        confidential=body.confidential,
        redirect_uris=body.redirect_uris,
        post_logout_redirect_uris=body.post_logout_redirect_uris,
        allowed_scopes=body.allowed_scopes,
        created_by=actor,
    )
    db.add(created.client)
    await db.commit()
    await audit.record(
        "oauth.client.create",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor,
        details={"client_id": created.client.client_id, "name": body.name},
    )
    response.headers["Cache-Control"] = "no-store"
    return ClientWithSecret(**_out(created.client).model_dump(), client_secret=created.secret)


@router.get("/{pk}", response_model=ClientOut)
async def get_client_detail(pk: uuid.UUID, _: CanRead, db: DB) -> ClientOut:
    return _out(await _get(db, pk))


@router.put("/{pk}", response_model=ClientOut)
async def update_client(
    pk: uuid.UUID,
    body: ClientIn,
    ctx: CanWrite,
    db: DB,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> ClientOut:
    actor = ctx.user.id
    await limiter.hit("admin:actor", str(actor), LIMITS["admin:actor"])
    row = await _get(db, pk)
    if body.confidential != row.is_confidential:
        raise KeygateError(
            status.HTTP_409_CONFLICT,
            "client_type_immutable",
            "A client can't switch between public and confidential; register a new one.",
        )
    row.name = body.name
    row.redirect_uris = body.redirect_uris
    row.post_logout_redirect_uris = body.post_logout_redirect_uris
    row.allowed_scopes = body.allowed_scopes
    out = _out(row)
    await db.commit()
    await audit.record(
        "oauth.client.update",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor,
        details={"client_id": out.client_id},
    )
    return out


@router.post("/{pk}/secret", response_model=ClientWithSecret)
async def rotate_secret(
    pk: uuid.UUID,
    ctx: CanWrite,
    response: Response,
    db: DB,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> ClientWithSecret:
    actor = ctx.user.id
    await limiter.hit("admin:actor", str(actor), LIMITS["admin:actor"])
    row = await _get(db, pk)
    if not row.is_confidential:
        raise KeygateError(
            status.HTTP_409_CONFLICT, "public_client", "Public clients have no secret."
        )
    secret = new_client_secret()
    row.client_secret_hash = hash_token(secret)
    out = _out(row)
    await db.commit()
    await audit.record(
        "oauth.client.rotate_secret",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor,
        details={"client_id": out.client_id},
    )
    response.headers["Cache-Control"] = "no-store"
    return ClientWithSecret(**out.model_dump(), client_secret=secret)


@router.post("/{pk}/disable", response_model=ClientOut)
async def disable_client(
    pk: uuid.UUID, ctx: CanWrite, db: DB, limiter: Limiter, audit: AuditDep, client: Client
) -> ClientOut:
    actor = ctx.user.id
    await limiter.hit("admin:actor", str(actor), LIMITS["admin:actor"])
    row = await _get(db, pk)
    row.disabled_at = row.disabled_at or utcnow()
    out = _out(row)
    await db.commit()
    await audit.record(
        "oauth.client.disable",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor,
        details={"client_id": out.client_id},
    )
    return out
