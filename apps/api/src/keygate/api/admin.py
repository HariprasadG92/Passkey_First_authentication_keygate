"""Administration and audit endpoints.

Authorization is by permission (``require_permission``), not by role name. Every
mutating action also requires step-up re-authentication, is rate-limited per admin, and
is audited with both actor and target.
"""

import base64
import json
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from keygate.api.deps import DB, AuditDep, Client, Limiter, Sessions
from keygate.audit.models import AuditEvent, AuditResult, Severity
from keygate.auth.methods import lock_user
from keygate.auth.models import User, UserStatus, WebAuthnCredential
from keygate.auth.sessions import SessionContext
from keygate.errors import KeygateError
from keygate.mfa.models import TotpCredential
from keygate.rbac.dependencies import require_permission
from keygate.rbac.models import Role, UserRole
from keygate.rbac.service import RoleChangeError, roles_for, set_roles
from keygate.security.rate_limit import LIMITS
from keygate.social.models import SocialAccount

router = APIRouter(prefix="/admin", tags=["admin"])

CanReadUsers = Annotated[SessionContext, Depends(require_permission("users:read"))]
CanWriteUsers = Annotated[SessionContext, Depends(require_permission("users:write", step_up=True))]
CanRevokeSessions = Annotated[
    SessionContext, Depends(require_permission("users:sessions:revoke", step_up=True))
]
CanAssignRoles = Annotated[
    SessionContext, Depends(require_permission("roles:assign", step_up=True))
]
CanReadAudit = Annotated[SessionContext, Depends(require_permission("audit:read"))]

MAX_PAGE = 100


# ------------------------------------------------------------------------- schemas


class AdminUserSummary(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    status: str
    roles: list[str]
    created_at: datetime


class UserPage(BaseModel):
    items: list[AdminUserSummary]
    total: int


class AdminSession(BaseModel):
    id: uuid.UUID
    auth_method: str
    ip_address: str | None
    user_agent: str | None
    last_seen_at: datetime


class AdminUserDetail(AdminUserSummary):
    email_verified: bool
    passkeys: int
    totp_enabled: bool
    social_providers: list[str]
    sessions: list[AdminSession]


class SuspendRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class RolesRequest(BaseModel):
    roles: list[str] = Field(max_length=10)


class RoleOut(BaseModel):
    name: str
    description: str
    permissions: list[str]


class AuditEventOut(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    event_type: str
    severity: str
    result: str
    actor_user_id: uuid.UUID | None
    target_user_id: uuid.UUID | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, object]


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_cursor: str | None


class RevokedOut(BaseModel):
    revoked: int


# ------------------------------------------------------------------------- helpers


def _escape_like(value: str) -> str:
    """Treat user input literally in LIKE patterns (no wildcard injection)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


async def _summary(db: AsyncSession, user: User) -> AdminUserSummary:
    return AdminUserSummary(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        status=user.status.value,
        roles=await roles_for(db, user.id),
        created_at=user.created_at,
    )


async def _locked_target(db: AsyncSession, user_id: uuid.UUID) -> User:
    if await db.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return await lock_user(db, user_id)


# --------------------------------------------------------------------------- users


@router.get("/users", response_model=UserPage)
async def search_users(
    _: CanReadUsers,
    db: DB,
    q: str | None = Query(default=None, max_length=320),
    user_status: Literal["active", "suspended"] | None = Query(default=None, alias="status"),
    role: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=25, ge=1, le=MAX_PAGE),
    offset: int = Query(default=0, ge=0, le=100_000),
) -> UserPage:
    conditions = []
    if q and q.strip():
        pattern = f"%{_escape_like(q.strip().lower())}%"
        conditions.append(
            or_(
                User.email.like(pattern, escape="\\"),
                func.lower(User.display_name).like(pattern, escape="\\"),
            )
        )
    if user_status:
        conditions.append(User.status == UserStatus(user_status))
    if role:
        conditions.append(
            User.id.in_(
                select(UserRole.user_id)
                .join(Role, Role.id == UserRole.role_id)
                .where(Role.name == role)
            )
        )
    where = and_(True, *conditions)
    total = (await db.execute(select(func.count()).select_from(User).where(where))).scalar_one()
    users = (
        await db.execute(
            select(User)
            .where(where)
            .order_by(User.created_at.desc(), User.id)
            .limit(limit)
            .offset(offset)
        )
    ).scalars()
    return UserPage(items=[await _summary(db, u) for u in users], total=total)


@router.get("/users/{user_id}", response_model=AdminUserDetail)
async def get_user(
    user_id: uuid.UUID, _: CanReadUsers, db: DB, sessions: Sessions
) -> AdminUserDetail:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    passkeys = (
        await db.execute(
            select(func.count())
            .select_from(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user.id)
        )
    ).scalar_one()
    totp = await db.get(TotpCredential, user.id)
    providers = (
        await db.execute(select(SocialAccount.provider).where(SocialAccount.user_id == user.id))
    ).scalars()
    summary = await _summary(db, user)
    return AdminUserDetail(
        **summary.model_dump(),
        email_verified=user.email_verified,
        passkeys=passkeys,
        totp_enabled=totp is not None and totp.confirmed_at is not None,
        social_providers=sorted(providers),
        sessions=[
            AdminSession(
                id=s.id,
                auth_method=s.auth_method,
                ip_address=s.ip_address,
                user_agent=s.user_agent,
                last_seen_at=s.last_seen_at,
            )
            for s in await sessions.list_active(db, user.id)
        ],
    )


@router.post("/users/{user_id}/suspend", response_model=AdminUserSummary)
async def suspend_user(
    user_id: uuid.UUID,
    body: SuspendRequest,
    ctx: CanWriteUsers,
    db: DB,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> AdminUserSummary:
    actor_id = ctx.user.id
    await limiter.hit("admin:actor", str(actor_id), LIMITS["admin:actor"])
    if user_id == actor_id:
        raise KeygateError(
            status.HTTP_409_CONFLICT, "cannot_suspend_self", "You can't suspend yourself."
        )
    user = await _locked_target(db, user_id)
    user.status = UserStatus.SUSPENDED
    # Takes effect immediately: every session of the user is revoked.
    revoked = await sessions.revoke_for_user(db, user_id)
    summary = await _summary(db, user)
    await db.commit()
    await audit.record(
        "user.suspend",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor_id,
        target_user_id=user_id,
        details={"reason": body.reason, "sessions_revoked": revoked},
    )
    return summary


@router.post("/users/{user_id}/unsuspend", response_model=AdminUserSummary)
async def unsuspend_user(
    user_id: uuid.UUID,
    ctx: CanWriteUsers,
    db: DB,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> AdminUserSummary:
    actor_id = ctx.user.id
    await limiter.hit("admin:actor", str(actor_id), LIMITS["admin:actor"])
    user = await _locked_target(db, user_id)
    user.status = UserStatus.ACTIVE
    summary = await _summary(db, user)
    await db.commit()
    await audit.record(
        "user.unsuspend",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor_id,
        target_user_id=user_id,
    )
    return summary


@router.put("/users/{user_id}/roles", response_model=AdminUserSummary)
async def set_user_roles(
    user_id: uuid.UUID,
    body: RolesRequest,
    ctx: CanAssignRoles,
    db: DB,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> AdminUserSummary:
    actor_id = ctx.user.id
    await limiter.hit("admin:actor", str(actor_id), LIMITS["admin:actor"])
    # Serialise role changes (protects the last-admin rule against concurrent demotions).
    await db.execute(select(Role.id).where(Role.name == "admin").with_for_update())
    user = await _locked_target(db, user_id)
    try:
        granted, revoked = await set_roles(
            db, actor_id=actor_id, target_id=user_id, roles=set(body.roles)
        )
    except RoleChangeError as exc:
        await db.rollback()
        raise KeygateError(status.HTTP_409_CONFLICT, exc.code, exc.message) from None
    sessions_revoked = 0
    if granted:
        # Privilege increase: the user's elevated access starts from a fresh sign-in
        # (new session ID), never from a session that existed before the grant.
        sessions_revoked = await sessions.revoke_for_user(db, user_id)
    summary = await _summary(db, user)
    await db.commit()
    for event, names in (("role.grant", granted), ("role.revoke", revoked)):
        if names:
            await audit.record(
                event,
                result=AuditResult.SUCCESS,
                severity=Severity.HIGH if "admin" in names else Severity.WARNING,
                client=client,
                actor_user_id=actor_id,
                target_user_id=user_id,
                details={"roles": sorted(names), "sessions_revoked": sessions_revoked},
            )
    return summary


@router.post("/users/{user_id}/sessions/revoke", response_model=RevokedOut)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    ctx: CanRevokeSessions,
    db: DB,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> RevokedOut:
    actor_id = ctx.user.id
    await limiter.hit("admin:actor", str(actor_id), LIMITS["admin:actor"])
    if await db.get(User, user_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    revoked = await sessions.revoke_for_user(
        db, user_id, except_session_id=ctx.session.id if user_id == actor_id else None
    )
    await db.commit()
    await audit.record(
        "session.revoke_all",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=actor_id,
        target_user_id=user_id,
        details={"revoked": revoked},
    )
    return RevokedOut(revoked=revoked)


@router.get("/roles", response_model=list[RoleOut])
async def list_roles(_: CanReadUsers, db: DB) -> list[RoleOut]:
    roles = (
        await db.execute(select(Role).options(selectinload(Role.permissions)).order_by(Role.name))
    ).scalars()
    return [
        RoleOut(
            name=r.name,
            description=r.description,
            permissions=sorted(p.name for p in r.permissions),
        )
        for r in roles
    ]


# --------------------------------------------------------------------------- audit


def _encode_cursor(event: AuditEvent) -> str:
    raw = json.dumps([event.occurred_at.isoformat(), str(event.id)]).encode()
    return base64.urlsafe_b64encode(raw).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        occurred, event_id = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return datetime.fromisoformat(occurred), uuid.UUID(event_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid cursor.") from exc


@router.get("/audit", response_model=AuditPage)
async def audit_log(
    _: CanReadAudit,
    db: DB,
    event_type: str | None = Query(default=None, max_length=64),
    severity: Literal["info", "warning", "high"] | None = None,
    result: Literal["success", "failure"] | None = None,
    user_id: Annotated[uuid.UUID | None, Query(description="Actor or target")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=50, ge=1, le=MAX_PAGE),
) -> AuditPage:
    """Read-only, newest first, keyset-paginated (stable under concurrent inserts)."""
    stmt = select(AuditEvent)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(AuditEvent.severity == severity)
    if result:
        stmt = stmt.where(AuditEvent.result == result)
    if user_id:
        stmt = stmt.where(
            or_(AuditEvent.actor_user_id == user_id, AuditEvent.target_user_id == user_id)
        )
    if since:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.occurred_at < until)
    if cursor:
        occurred, event_id = _decode_cursor(cursor)
        stmt = stmt.where(tuple_(AuditEvent.occurred_at, AuditEvent.id) < (occurred, event_id))
    rows = list(
        (
            await db.execute(
                stmt.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(limit + 1)
            )
        ).scalars()
    )
    page, more = rows[:limit], len(rows) > limit
    return AuditPage(
        items=[
            AuditEventOut(
                id=e.id,
                occurred_at=e.occurred_at,
                event_type=e.event_type,
                severity=e.severity.value,
                result=e.result.value,
                actor_user_id=e.actor_user_id,
                target_user_id=e.target_user_id,
                ip_address=e.ip_address,
                user_agent=e.user_agent,
                request_id=e.request_id,
                details=e.details,
            )
            for e in page
        ],
        next_cursor=_encode_cursor(page[-1]) if more and page else None,
    )
