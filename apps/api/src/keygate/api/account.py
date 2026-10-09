"""The signed-in user's own account: passkeys, authenticator app, recovery codes,
sessions and email address.

Every route is scoped to ``ctx.user``. Object IDs in paths are always looked up together
with the owner's user ID, so guessing another user's passkey or session ID gets a 404.
"""

import uuid
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, HTTPException, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.api.deps import (
    DB,
    AuditDep,
    Client,
    FullSession,
    Limiter,
    MailerDep,
    RedisDep,
    Sessions,
    SettingsDep,
)
from keygate.audit.models import AuditResult, Severity
from keygate.auth.accounts import get_user_by_email, normalize_email
from keygate.auth.email import OutgoingEmail
from keygate.auth.methods import count_sign_in_methods, last_method_error, lock_user
from keygate.auth.models import EmailToken, EmailTokenPurpose, User, WebAuthnCredential
from keygate.auth.notifications import security_notice
from keygate.auth.passkeys import PasskeyError, PasskeyService
from keygate.auth.schemas import (
    AcceptedResponse,
    AddPasskeyRequest,
    EmailChangeRequest,
    EmailVerifyRequest,
    LinkedSocialOut,
    PasskeyOut,
    PasskeyRename,
    RecoveryCodesOut,
    RevokedOut,
    SecurityOverview,
    SessionInfoOut,
    TotpCodeRequest,
    TotpEnrolmentOut,
    UserOut,
)
from keygate.auth.stepup import SteppedUpSession
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.errors import KeygateError
from keygate.mfa import recovery
from keygate.mfa.totp import TotpError, TotpService
from keygate.security.crypto import Encryptor
from keygate.security.rate_limit import LIMITS
from keygate.security.tokens import generate_token, hash_token
from keygate.social.models import SocialAccount

router = APIRouter(prefix="/account", tags=["account"])


def _passkey_out(c: WebAuthnCredential) -> PasskeyOut:
    return PasskeyOut(
        id=c.id,
        friendly_name=c.friendly_name,
        created_at=c.created_at,
        last_used_at=c.last_used_at,
        backup_eligible=c.backup_eligible,
        backup_state=c.backup_state,
        transports=c.transports,
    )


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        email_verified=user.email_verified,
        display_name=user.display_name,
    )


def _totp(settings: Settings) -> TotpService:
    return TotpService(settings, Encryptor.from_settings(settings))


def _notify(
    background: BackgroundTasks,
    mailer: MailerDep,
    settings: Settings,
    to: str,
    event: str,
    client: Client,
    extra: str = "",
) -> None:
    background.add_task(mailer.send, security_notice(settings, to, event, client, extra))


# ----------------------------------------------------------------------- overview


@router.get("", response_model=SecurityOverview)
async def get_account(ctx: FullSession, db: DB, settings: SettingsDep) -> SecurityOverview:
    creds = (
        await db.execute(
            select(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == ctx.user.id)
            .order_by(WebAuthnCredential.created_at)
        )
    ).scalars()
    reauth = ctx.session.reauthenticated_at
    social = (
        await db.execute(
            select(SocialAccount)
            .where(SocialAccount.user_id == ctx.user.id)
            .order_by(SocialAccount.created_at)
        )
    ).scalars()
    return SecurityOverview(
        user=_user_out(ctx.user),
        passkeys=[_passkey_out(c) for c in creds],
        social_accounts=[
            LinkedSocialOut(
                id=a.id, provider=a.provider, email=a.email, display_name=a.display_name
            )
            for a in social
        ],
        totp_enabled=await _totp(settings).is_enabled(db, ctx.user.id),
        recovery_codes_remaining=await recovery.remaining(db, ctx.user.id),
        step_up_valid_until=reauth + settings.step_up_ttl if reauth else None,
    )


# ----------------------------------------------------------------------- passkeys


async def _owned_passkey(
    db: AsyncSession, user_id: uuid.UUID, passkey_id: uuid.UUID
) -> WebAuthnCredential:
    row = (
        await db.execute(
            select(WebAuthnCredential).where(
                WebAuthnCredential.id == passkey_id, WebAuthnCredential.user_id == user_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey not found.")
    return row


@router.patch("/passkeys/{passkey_id}", response_model=PasskeyOut)
async def rename_passkey(
    passkey_id: uuid.UUID, body: PasskeyRename, ctx: FullSession, db: DB
) -> PasskeyOut:
    row = await _owned_passkey(db, ctx.user.id, passkey_id)
    row.friendly_name = body.friendly_name.strip()
    await db.commit()
    return _passkey_out(row)


@router.delete("/passkeys/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_passkey(
    passkey_id: uuid.UUID,
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
    row = await _owned_passkey(db, user_id, passkey_id)
    if await count_sign_in_methods(db, user_id) <= 1:
        raise last_method_error()
    await db.delete(row)
    await db.commit()
    await audit.record(
        "credential.remove",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"credential": str(passkey_id)},
    )
    _notify(background, mailer, settings, email, "passkey_removed", client)


@router.post("/passkeys/register/options")
async def add_passkey_options(
    ctx: SteppedUpSession, db: DB, settings: SettingsDep, redis: RedisDep, limiter: Limiter
) -> dict[str, object]:
    await limiter.hit(
        "passkey_register:session", str(ctx.session.id), LIMITS["passkey_register:session"]
    )
    return await PasskeyService(settings, redis).registration_options(db, ctx.user, ctx.session)


@router.post("/passkeys/register/verify", response_model=PasskeyOut)
async def add_passkey_verify(
    body: AddPasskeyRequest,
    ctx: SteppedUpSession,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> PasskeyOut:
    user_id, email = ctx.user.id, ctx.user.email
    try:
        row = await PasskeyService(settings, redis).verify_registration(
            db, ctx.user, ctx.session, body.credential, body.friendly_name
        )
    except PasskeyError as exc:
        await db.rollback()
        await audit.record(
            "credential.add",
            result=AuditResult.FAILURE,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"reason": exc.reason},
        )
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Passkey verification failed. Please try again."
        ) from None
    await db.commit()
    await audit.record(
        "credential.add",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"credential": str(row.id), "aaguid": row.aaguid},
    )
    _notify(background, mailer, settings, email, "passkey_added", client)
    return _passkey_out(row)


# ------------------------------------------------------------------- TOTP (MFA app)


@router.post("/totp/setup", response_model=TotpEnrolmentOut)
async def totp_setup(ctx: SteppedUpSession, db: DB, settings: SettingsDep) -> TotpEnrolmentOut:
    try:
        enrolment = await _totp(settings).begin_enrolment(db, ctx.user)
    except TotpError:
        raise KeygateError(
            status.HTTP_409_CONFLICT,
            "totp_already_enabled",
            "An authenticator app is already set up.",
        ) from None
    await db.commit()
    return TotpEnrolmentOut(
        secret=enrolment.secret,
        otpauth_uri=enrolment.otpauth_uri,
        qr_svg_data_uri=enrolment.qr_svg_data_uri,
    )


@router.post("/totp/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def totp_confirm(
    body: TotpCodeRequest,
    ctx: SteppedUpSession,
    db: DB,
    settings: SettingsDep,
    limiter: Limiter,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> None:
    user_id, email = ctx.user.id, ctx.user.email
    await limiter.hit("totp:user", email, LIMITS["totp:user"])
    try:
        await _totp(settings).confirm_enrolment(db, ctx.user, body.code)
    except TotpError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "That code isn't valid. Try again."
        ) from None
    await db.commit()
    await audit.record(
        "mfa.totp.enable",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    _notify(background, mailer, settings, email, "totp_enabled", client)


@router.delete("/totp", status_code=status.HTTP_204_NO_CONTENT)
async def totp_disable(
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
    service = _totp(settings)
    if not await service.is_enabled(db, user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No authenticator app is set up.")
    if await count_sign_in_methods(db, user_id) <= 1:
        raise last_method_error()
    await service.disable(db, user_id)
    await db.commit()
    await audit.record(
        "mfa.totp.disable",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    _notify(background, mailer, settings, email, "totp_disabled", client)


# ------------------------------------------------------------------ recovery codes


@router.post("/recovery-codes", response_model=RecoveryCodesOut)
async def regenerate_recovery_codes(
    ctx: SteppedUpSession,
    response: Response,
    db: DB,
    settings: SettingsDep,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> RecoveryCodesOut:
    user_id, email = ctx.user.id, ctx.user.email
    codes = await recovery.regenerate(db, user_id)
    await db.commit()
    await audit.record(
        "mfa.recovery_codes.regenerate",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    _notify(background, mailer, settings, email, "recovery_codes_regenerated", client)
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodesOut(codes=codes)


# ----------------------------------------------------------------------- sessions


@router.get("/sessions", response_model=list[SessionInfoOut])
async def list_sessions(ctx: FullSession, db: DB, sessions: Sessions) -> list[SessionInfoOut]:
    return [
        SessionInfoOut(
            id=s.id,
            current=s.id == ctx.session.id,
            auth_method=s.auth_method,
            ip_address=s.ip_address,
            user_agent=s.user_agent,
            created_at=s.created_at,
            last_seen_at=s.last_seen_at,
        )
        for s in await sessions.list_active(db, ctx.user.id)
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID,
    ctx: FullSession,
    db: DB,
    sessions: Sessions,
    audit: AuditDep,
    client: Client,
) -> None:
    user_id = ctx.user.id
    if await sessions.revoke_for_user(db, user_id, session_id=session_id) == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found.")
    await db.commit()
    await audit.record(
        "session.revoke",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"session": str(session_id)},
    )


@router.post("/sessions/revoke-others", response_model=RevokedOut)
async def revoke_other_sessions(
    ctx: FullSession, db: DB, sessions: Sessions, audit: AuditDep, client: Client
) -> RevokedOut:
    user_id = ctx.user.id
    count = await sessions.revoke_for_user(db, user_id, except_session_id=ctx.session.id)
    await db.commit()
    await audit.record(
        "session.revoke_others",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"revoked": count},
    )
    return RevokedOut(revoked=count)


# -------------------------------------------------------------------- email change

EMAIL_CHANGE_ACCEPTED = "If that address can be used, we've sent it a confirmation link."


@router.post("/email", response_model=AcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
async def request_email_change(
    body: EmailChangeRequest,
    ctx: SteppedUpSession,
    db: DB,
    settings: SettingsDep,
    limiter: Limiter,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> AcceptedResponse:
    user_id, old_email = ctx.user.id, ctx.user.email
    new_email = normalize_email(body.new_email)
    await limiter.hit("email_change:user", str(user_id), LIMITS["email_change:user"])

    if new_email != old_email and await get_user_by_email(db, new_email) is None:
        token = generate_token()
        db.add(
            EmailToken(
                token_hash=hash_token(token),
                email=new_email,
                purpose=EmailTokenPurpose.EMAIL_CHANGE,
                user_id=user_id,
                expires_at=utcnow() + timedelta(minutes=settings.magic_link_ttl_minutes),
            )
        )
        await db.commit()
        background.add_task(
            mailer.send,
            OutgoingEmail(
                to=new_email,
                subject="Confirm your new Keygate email address",
                text=(
                    "Confirm this address for your Keygate account (you must be signed in):\n\n"
                    f"{settings.public_url}/account/confirm-email#token={token}\n\n"
                    f"The link expires in {settings.magic_link_ttl_minutes} minutes."
                ),
            ),
        )
    _notify(
        background,
        mailer,
        settings,
        old_email,
        "email_change_requested",
        client,
        extra=f"Requested new address: {new_email}",
    )
    await audit.record(
        "account.email_change.request",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    # Same response whether or not the address is already taken (no enumeration).
    return AcceptedResponse(message=EMAIL_CHANGE_ACCEPTED)


@router.post("/email/confirm", response_model=UserOut)
async def confirm_email_change(
    body: EmailVerifyRequest,
    ctx: FullSession,
    db: DB,
    settings: SettingsDep,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> UserOut:
    """The link must be opened while signed in *as the same user*, so a link forwarded
    to (or intercepted by) someone else is useless."""
    user_id, old_email = ctx.user.id, ctx.user.email
    now = utcnow()
    row = (
        await db.execute(
            update(EmailToken)
            .where(
                EmailToken.token_hash == hash_token(body.token),
                EmailToken.purpose == EmailTokenPurpose.EMAIL_CHANGE,
                EmailToken.user_id == user_id,
                EmailToken.used_at.is_(None),
                EmailToken.expires_at > now,
            )
            .values(used_at=now)
            .returning(EmailToken.email)
        )
    ).first()
    if row is None:
        await db.rollback()
        await audit.record(
            "account.email_change.confirm",
            result=AuditResult.FAILURE,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is invalid or has expired.")

    user = await lock_user(db, user_id)
    user.email = row[0]
    user.email_verified = True
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise KeygateError(
            status.HTTP_409_CONFLICT, "email_taken", "That address is no longer available."
        ) from None
    await audit.record(
        "account.email_change.confirm",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
    )
    _notify(
        background,
        mailer,
        settings,
        old_email,
        "email_changed",
        client,
        extra=f"New address: {user.email}",
    )
    return _user_out(user)
