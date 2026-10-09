"""Social login (GitHub, Google): sign-in, sign-up, linking and step-up.

Account-linking rules (ADR-028):

* A provider identity is matched **only** by (provider, subject), never by email.
* If an *unlinked* identity's verified email belongs to an existing Keygate account,
  sign-in is refused with guidance: accounts are never merged silently.
* Linking happens only from settings, by a stepped-up user, and needs an explicit
  confirmation of the identity that came back from the provider.
* Unverified provider emails can't create or be linked to an account.
"""

import secrets
import uuid
from typing import Literal

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.api.deps import (
    DB,
    AuditDep,
    Client,
    Limiter,
    MailerDep,
    OptionalSession,
    RedisDep,
    Sessions,
    SettingsDep,
)
from keygate.audit.models import AuditResult, Severity
from keygate.auth.accounts import WEBAUTHN_USER_HANDLE_BYTES, get_user_by_email
from keygate.auth.methods import count_sign_in_methods, last_method_error, lock_user
from keygate.auth.models import SessionLevel, User, UserStatus
from keygate.auth.notifications import security_notice
from keygate.auth.schemas import LinkedSocialOut
from keygate.auth.stepup import SteppedUpSession, require_recent_auth
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.errors import KeygateError
from keygate.security.rate_limit import LIMITS
from keygate.social.models import SocialAccount
from keygate.social.providers import PROVIDERS, Provider, SocialIdentity, enabled_providers
from keygate.social.service import SocialFlowError, SocialLogin

router = APIRouter(tags=["social"])


class ProviderOut(BaseModel):
    id: str
    name: str


class StartRequest(BaseModel):
    intent: Literal["signin", "link", "stepup"] = "signin"


class StartResponse(BaseModel):
    authorize_url: str


class PendingLinkOut(BaseModel):
    provider: str
    email: str | None
    display_name: str | None


class PendingLinkRequest(BaseModel):
    pending_id: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


def _provider(name: str, settings: Settings) -> Provider:
    provider = PROVIDERS.get(name)
    if provider is None or provider not in enabled_providers(settings):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown or disabled provider.")
    return provider


def _service(request: Request, settings: Settings, redis: RedisDep) -> SocialLogin:
    http: httpx.AsyncClient = request.app.state.http
    return SocialLogin(settings, redis, http)


@router.get("/auth/social/providers", response_model=list[ProviderOut])
async def list_providers(settings: SettingsDep) -> list[ProviderOut]:
    return [ProviderOut(id=p.id, name=p.name) for p in enabled_providers(settings)]


@router.post("/auth/social/{provider_name}/start", response_model=StartResponse)
async def start(
    provider_name: str,
    body: StartRequest,
    request: Request,
    response: Response,
    ctx: OptionalSession,
    settings: SettingsDep,
    redis: RedisDep,
    limiter: Limiter,
    client: Client,
) -> StartResponse:
    """Begin a flow. JSON + CSRF-protected (a POST from our own UI), returning the URL
    the browser should navigate to; sets the browser-binding cookie."""
    provider = _provider(provider_name, settings)
    await limiter.hit("social_start:ip", client.ip or "unknown", LIMITS["social_start:ip"])

    user_id: uuid.UUID | None = None
    if body.intent in ("link", "stepup"):
        if ctx is None or ctx.session.level is not SessionLevel.FULL:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required.")
        if body.intent == "link":
            # Linking adds a sign-in method: needs recent authentication.
            await require_recent_auth(ctx, settings)
        user_id = ctx.user.id

    flow = await _service(request, settings, redis).start(provider, body.intent, user_id)
    response.set_cookie(
        settings.oauth_cookie_name,
        flow.binding,
        max_age=settings.social_flow_ttl_seconds,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        # Lax (not Strict) so the cookie is sent on the provider's top-level redirect back.
        samesite="lax",
    )
    return StartResponse(authorize_url=flow.authorize_url)


def _redirect(path: str, settings: Settings) -> RedirectResponse:
    response = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(
        settings.oauth_cookie_name, path="/", secure=settings.secure_cookies, httponly=True
    )
    return response


async def _find_link(db: AsyncSession, identity: SocialIdentity) -> SocialAccount | None:
    return (
        await db.execute(
            select(SocialAccount).where(
                SocialAccount.provider == identity.provider,
                SocialAccount.subject == identity.subject,
            )
        )
    ).scalar_one_or_none()


@router.get("/auth/social/{provider_name}/callback", include_in_schema=False)
async def callback(
    provider_name: str,
    request: Request,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    sessions: Sessions,
    ctx: OptionalSession,
    audit: AuditDep,
    client: Client,
    code: str | None = Query(default=None, max_length=2048),
    state: str | None = Query(default=None, max_length=256),
    error: str | None = Query(default=None, max_length=256),
) -> Response:
    """The provider redirects the browser here. This is a state-changing GET by the
    nature of OAuth; it is protected by the single-use state, PKCE and the browser
    binding instead of the CSRF header."""
    provider = PROVIDERS.get(provider_name)
    if provider is None or provider not in enabled_providers(settings):
        return _redirect("/signin?error=social_failed", settings)

    service = _service(request, settings, redis)
    try:
        flow = await service.complete(
            provider,
            code=code,
            state=state,
            error=error,
            binding=request.cookies.get(settings.oauth_cookie_name),
        )
    except SocialFlowError as exc:
        await audit.record(
            "signin",
            result=AuditResult.FAILURE,
            severity=Severity.WARNING
            if "binding" in exc.reason or "state" in exc.reason
            else Severity.INFO,
            client=client,
            details={"method": provider.id, "reason": exc.reason},
        )
        return _redirect("/signin?error=social_failed", settings)

    identity = flow.identity
    existing = await _find_link(db, identity)

    # ----------------------------------------------------------------- link
    if flow.intent == "link":
        if ctx is None or flow.user_id != ctx.user.id:
            return _redirect("/signin?error=social_failed", settings)
        if not identity.email_verified:
            return _redirect("/account?social_error=unverified_email", settings)
        if existing is not None:
            reason = "already_linked" if existing.user_id == ctx.user.id else "linked_elsewhere"
            return _redirect(f"/account?social_error={reason}", settings)
        pending_id = await service.stash_pending_link(ctx.user.id, identity)
        # Fragment: the pending ID never reaches server logs.
        return _redirect(f"/account/link-social#pending={pending_id}", settings)

    # --------------------------------------------------------------- step-up
    if flow.intent == "stepup":
        if (
            ctx is None
            or flow.user_id != ctx.user.id
            or existing is None
            or existing.user_id != ctx.user.id
        ):
            await audit.record(
                "step_up",
                result=AuditResult.FAILURE,
                client=client,
                target_user_id=flow.user_id,
                details={"method": provider.id},
            )
            return _redirect("/account?social_error=stepup_failed", settings)
        response = _redirect("/account?stepped_up=1", settings)
        user_id = ctx.user.id
        existing.last_used_at = utcnow()
        await sessions.create(
            db,
            response,
            user=ctx.user,
            level=SessionLevel.FULL,
            auth_method=ctx.session.auth_method,
            client=client,
            replaces_token=ctx.token,
        )
        await db.commit()
        await audit.record(
            "step_up",
            result=AuditResult.SUCCESS,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"method": provider.id},
        )
        return response

    # ---------------------------------------------------------------- sign-in
    if existing is not None:
        user = await db.get(User, existing.user_id)
        if user is None or user.status is not UserStatus.ACTIVE:
            return _redirect("/signin?error=social_failed", settings)
        existing.last_used_at = utcnow()
        destination = "/account"
    else:
        if not identity.email_verified or identity.email is None:
            await audit.record(
                "signin",
                result=AuditResult.FAILURE,
                client=client,
                details={"method": provider.id, "reason": "unverified_email"},
            )
            return _redirect("/signin?error=social_unverified_email", settings)
        if await get_user_by_email(db, identity.email) is not None:
            # Never merge silently. The owner must sign in and link from settings.
            await audit.record(
                "signin",
                result=AuditResult.FAILURE,
                client=client,
                details={"method": provider.id, "reason": "email_in_use_not_linked"},
            )
            return _redirect("/signin?error=social_email_in_use", settings)
        user = User(
            email=identity.email,
            email_verified=True,
            display_name=(identity.display_name or identity.email.split("@")[0])[:100],
            webauthn_user_handle=secrets.token_bytes(WEBAUTHN_USER_HANDLE_BYTES),
        )
        db.add(user)
        await db.flush()
        db.add(_social_row(user.id, identity))
        destination = "/account?welcome=social"

    user_id = user.id
    response = _redirect(destination, settings)
    await sessions.create(
        db,
        response,
        user=user,
        level=SessionLevel.FULL,
        auth_method=provider.id,
        client=client,
        replaces_token=request.cookies.get(settings.session_cookie_name),
    )
    try:
        await db.commit()
    except IntegrityError:  # concurrent sign-up with the same identity or email
        await db.rollback()
        return _redirect("/signin?error=social_failed", settings)
    await audit.record(
        "signin",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"method": provider.id, "new_account": existing is None},
    )
    return response


def _social_row(user_id: uuid.UUID, identity: SocialIdentity) -> SocialAccount:
    return SocialAccount(
        user_id=user_id,
        provider=identity.provider,
        subject=identity.subject,
        email=identity.email,
        email_verified=identity.email_verified,
        display_name=identity.display_name,
    )


# --------------------------------------------------------------- account linking


@router.post("/account/social/pending", response_model=PendingLinkOut)
async def view_pending_link(
    body: PendingLinkRequest,
    ctx: SteppedUpSession,
    request: Request,
    settings: SettingsDep,
    redis: RedisDep,
) -> PendingLinkOut:
    """Show what's about to be linked, so the user confirms a specific identity."""
    try:
        identity = await _service(request, settings, redis).peek_pending_link(
            body.pending_id, ctx.user.id
        )
    except SocialFlowError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This link request has expired.") from None
    return PendingLinkOut(
        provider=identity.provider, email=identity.email, display_name=identity.display_name
    )


@router.post("/account/social/confirm", response_model=LinkedSocialOut)
async def confirm_link(
    body: PendingLinkRequest,
    ctx: SteppedUpSession,
    request: Request,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> LinkedSocialOut:
    user_id, email = ctx.user.id, ctx.user.email
    try:
        identity = await _service(request, settings, redis).take_pending_link(
            body.pending_id, user_id
        )
    except SocialFlowError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This link request has expired.") from None
    row = _social_row(user_id, identity)
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise KeygateError(
            status.HTTP_409_CONFLICT,
            "social_already_linked",
            "That account is already linked to a Keygate account.",
        ) from None
    await audit.record(
        "social.link",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"provider": identity.provider},
    )
    background.add_task(
        mailer.send,
        security_notice(
            settings, email, "social_linked", client, extra=f"Provider: {identity.provider}"
        ),
    )
    return LinkedSocialOut(
        id=row.id, provider=row.provider, email=row.email, display_name=row.display_name
    )


@router.delete("/account/social/{social_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unlink(
    social_id: uuid.UUID,
    ctx: SteppedUpSession,
    db: DB,
    settings: SettingsDep,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> None:
    user_id, email = ctx.user.id, ctx.user.email
    await lock_user(db, user_id)
    row = (
        await db.execute(
            select(SocialAccount).where(
                SocialAccount.id == social_id, SocialAccount.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Linked account not found.")
    if await count_sign_in_methods(db, user_id) <= 1:
        raise last_method_error()
    provider = row.provider
    await db.delete(row)
    await db.commit()
    await audit.record(
        "social.unlink",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"provider": provider},
    )
    background.add_task(
        mailer.send,
        security_notice(settings, email, "social_unlinked", client, extra=f"Provider: {provider}"),
    )
