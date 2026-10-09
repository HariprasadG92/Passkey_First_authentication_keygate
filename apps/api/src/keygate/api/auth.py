"""Sign-up, email verification, passkey registration/sign-in, sign-out."""

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError

from keygate.api.deps import (
    DB,
    AuditDep,
    Client,
    FullSession,
    Limiter,
    MailerDep,
    OptionalSession,
    RedisDep,
    RegistrationSession,
    Sessions,
    SettingsDep,
)
from keygate.audit.models import AuditResult, Severity
from keygate.auth.accounts import (
    InvalidTokenError,
    consume_signup_token,
    credential_count,
    get_user_by_email,
    normalize_email,
    start_signup,
)
from keygate.auth.models import SessionLevel, User, UserStatus
from keygate.auth.notifications import security_notice
from keygate.auth.passkeys import PasskeyError, PasskeyService
from keygate.auth.schemas import (
    AcceptedResponse,
    EmailVerifyRequest,
    EmailVerifyResponse,
    LoginOptionsRequest,
    LoginOptionsResponse,
    LoginVerifyRequest,
    RecoveryLoginRequest,
    RegisterVerifyRequest,
    SessionOut,
    SignupStartRequest,
    StepUpPasskeyRequest,
    TotpCodeRequest,
    TotpLoginRequest,
    UserOut,
)
from keygate.config import Settings
from keygate.mfa import recovery
from keygate.mfa.totp import TotpService
from keygate.rbac.service import permissions_for
from keygate.security.crypto import Encryptor
from keygate.security.csrf import issue_csrf_token
from keygate.security.rate_limit import LIMITS

router = APIRouter(prefix="/auth", tags=["auth"])

SIGNUP_ACCEPTED = "If this email can be used, we've sent a link to continue. Check your inbox."
INVALID_LINK = "This link is invalid or has expired. Request a new one."
PASSKEY_FAILED = "Passkey verification failed. Please try again."


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        email_verified=user.email_verified,
        display_name=user.display_name,
    )


# ------------------------------------------------------------------ session status


@router.get("/session", response_model=SessionOut)
async def get_session(
    ctx: OptionalSession, response: Response, settings: SettingsDep, db: DB
) -> SessionOut:
    """Current session state, plus a fresh CSRF token bound to it. ``permissions`` is for
    showing/hiding UI only; the API enforces every permission itself."""
    csrf = issue_csrf_token(settings, response, ctx.token if ctx else None)
    if ctx is None:
        return SessionOut(authenticated=False, csrf_token=csrf)
    full = ctx.session.level is SessionLevel.FULL
    return SessionOut(
        authenticated=full,
        level=ctx.session.level.value,
        user=_user_out(ctx.user),
        csrf_token=csrf,
        permissions=sorted(await permissions_for(db, ctx.user.id)) if full else [],
    )


# ------------------------------------------------------------------------ sign-up


@router.post("/signup", response_model=AcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
async def signup(
    body: SignupStartRequest,
    background: BackgroundTasks,
    db: DB,
    settings: SettingsDep,
    mailer: MailerDep,
    limiter: Limiter,
    client: Client,
) -> AcceptedResponse:
    email = normalize_email(body.email)
    await limiter.hit("signup:ip", client.ip or "unknown", LIMITS["signup:ip"])
    await limiter.hit("signup:email", email, LIMITS["signup:email"])

    message = await start_signup(db, settings, email)
    # Send after the response: identical timing whether or not the account exists.
    background.add_task(mailer.send, message)
    return AcceptedResponse(message=SIGNUP_ACCEPTED)


@router.post("/email/verify", response_model=EmailVerifyResponse)
async def verify_email(
    body: EmailVerifyRequest,
    request: Request,
    response: Response,
    db: DB,
    sessions: Sessions,
    settings: SettingsDep,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> EmailVerifyResponse:
    await limiter.hit("email_verify:ip", client.ip or "unknown", LIMITS["email_verify:ip"])
    try:
        user = await consume_signup_token(db, body.token)
    except (InvalidTokenError, IntegrityError):
        await db.rollback()
        await audit.record("email.verify", result=AuditResult.FAILURE, client=client)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_LINK) from None

    await sessions.create(
        db,
        response,
        user=user,
        level=SessionLevel.REGISTRATION,
        auth_method="magic_link",
        client=client,
        replaces_token=request.cookies.get(settings.session_cookie_name),
        reauthenticated=False,  # email alone is not a sign-in factor
    )
    await db.commit()
    await audit.record(
        "email.verify",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user.id,
        target_user_id=user.id,
    )
    return EmailVerifyResponse(email=user.email, next="register_passkey")


# ----------------------------------------------------------- passkey registration


def _passkeys(settings: SettingsDep, redis: RedisDep) -> PasskeyService:
    return PasskeyService(settings, redis)


@router.post("/passkeys/register/options")
async def passkey_register_options(
    ctx: RegistrationSession,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    limiter: Limiter,
) -> dict[str, object]:
    await limiter.hit(
        "passkey_register:session", str(ctx.session.id), LIMITS["passkey_register:session"]
    )
    if await credential_count(db, ctx.user) > 0:
        # Registration sessions exist only to enrol the *first* passkey. Adding more
        # requires a full session and step-up re-authentication (Phase 2).
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account already has a passkey.")
    return await _passkeys(settings, redis).registration_options(db, ctx.user, ctx.session)


@router.post("/passkeys/register/verify", response_model=SessionOut)
async def passkey_register_verify(
    body: RegisterVerifyRequest,
    ctx: RegistrationSession,
    response: Response,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    sessions: Sessions,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    user_id = ctx.user.id
    if await credential_count(db, ctx.user) > 0:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account already has a passkey.")
    try:
        credential = await _passkeys(settings, redis).verify_registration(
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
        raise HTTPException(status.HTTP_400_BAD_REQUEST, PASSKEY_FAILED) from None

    # Privilege change (registration -> full): rotate the session.
    new = await sessions.create(
        db,
        response,
        user=ctx.user,
        level=SessionLevel.FULL,
        auth_method="passkey",
        client=client,
        replaces_token=ctx.token,
    )
    await db.commit()
    await audit.record(
        "credential.add",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=ctx.user.id,
        target_user_id=ctx.user.id,
        details={"credential": str(credential.id), "aaguid": credential.aaguid},
    )
    return SessionOut(
        authenticated=True, level="full", user=_user_out(ctx.user), csrf_token=new.csrf_token
    )


# ---------------------------------------------------------------- passkey sign-in


@router.post("/passkeys/login/options", response_model=LoginOptionsResponse)
async def passkey_login_options(
    body: LoginOptionsRequest,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    limiter: Limiter,
    client: Client,
) -> LoginOptionsResponse:
    await limiter.hit(
        "passkey_login_options:ip", client.ip or "unknown", LIMITS["passkey_login_options:ip"]
    )
    email = normalize_email(body.email) if body.email else None
    ceremony_id, options = await _passkeys(settings, redis).authentication_options(db, email)
    return LoginOptionsResponse(ceremony_id=ceremony_id, options=options)


@router.post("/passkeys/login/verify", response_model=SessionOut)
async def passkey_login_verify(
    body: LoginVerifyRequest,
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    await limiter.hit(
        "passkey_login_verify:ip", client.ip or "unknown", LIMITS["passkey_login_verify:ip"]
    )
    try:
        result = await _passkeys(settings, redis).verify_authentication(
            db, body.ceremony_id, body.credential
        )
    except PasskeyError as exc:
        await db.rollback()
        if exc.suspicious:
            await audit.record(
                "credential.sign_count_regression",
                result=AuditResult.FAILURE,
                severity=Severity.HIGH,
                client=client,
                target_user_id=exc.user_id,
                details={
                    "credential": str(exc.credential_id) if exc.credential_id else None,
                    "hint": "possible cloned authenticator",
                },
            )
        await audit.record(
            "signin",
            result=AuditResult.FAILURE,
            severity=Severity.WARNING if exc.suspicious else Severity.INFO,
            client=client,
            target_user_id=exc.user_id,
            details={"method": "passkey", "reason": exc.reason},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, PASSKEY_FAILED) from None

    new = await sessions.create(
        db,
        response,
        user=result.user,
        level=SessionLevel.FULL,
        auth_method="passkey",
        client=client,
        replaces_token=request.cookies.get(settings.session_cookie_name),
    )
    await db.commit()
    await audit.record(
        "signin",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=result.user.id,
        target_user_id=result.user.id,
        details={"method": "passkey", "credential": str(result.credential.id)},
    )
    return SessionOut(
        authenticated=True, level="full", user=_user_out(result.user), csrf_token=new.csrf_token
    )


# ----------------------------------------------------------------------- sign-out


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    ctx: OptionalSession,
    response: Response,
    db: DB,
    sessions: Sessions,
    audit: AuditDep,
    client: Client,
) -> Response:
    if ctx is not None:
        await sessions.revoke_token(db, ctx.token)
        await db.commit()
        await audit.record(
            "signout",
            result=AuditResult.SUCCESS,
            client=client,
            actor_user_id=ctx.user.id,
            target_user_id=ctx.user.id,
        )
    sessions.clear_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


# ------------------------------------------------- fallback sign-in: TOTP / recovery

INVALID_CODE = "That email and code don't match. Check the code and try again."


async def _start_full_session(
    request: Request,
    response: Response,
    db: DB,
    sessions: Sessions,
    settings: Settings,
    user: User,
    method: str,
    client: Client,
) -> SessionOut:
    new = await sessions.create(
        db,
        response,
        user=user,
        level=SessionLevel.FULL,
        auth_method=method,
        client=client,
        replaces_token=request.cookies.get(settings.session_cookie_name),
    )
    out = SessionOut(
        authenticated=True, level="full", user=_user_out(user), csrf_token=new.csrf_token
    )
    await db.commit()
    return out


@router.post("/totp/login", response_model=SessionOut)
async def totp_login(
    body: TotpLoginRequest,
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    """Fallback sign-in with an authenticator app code. Phishable (unlike passkeys), so
    it's rate-limited per account and every use is audited."""
    email = normalize_email(body.email)
    await limiter.hit("totp_login:ip", client.ip or "unknown", LIMITS["totp_login:ip"])
    await limiter.hit("totp:user", email, LIMITS["totp:user"])

    user = await get_user_by_email(db, email)
    known_id = user.id if user else None  # read before any rollback expires `user`
    totp = TotpService(settings, Encryptor.from_settings(settings))
    ok = (
        user is not None
        and user.status is UserStatus.ACTIVE
        and await totp.verify(db, user.id, body.code)
    )
    if not ok or user is None:
        await db.rollback()
        await audit.record(
            "signin",
            result=AuditResult.FAILURE,
            client=client,
            target_user_id=known_id,
            details={"method": "totp"},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    user_id = user.id
    out = await _start_full_session(request, response, db, sessions, settings, user, "totp", client)
    await audit.record(
        "signin",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"method": "totp"},
    )
    return out


@router.post("/recovery/login", response_model=SessionOut)
async def recovery_login(
    body: RecoveryLoginRequest,
    request: Request,
    response: Response,
    db: DB,
    settings: SettingsDep,
    sessions: Sessions,
    limiter: Limiter,
    background: BackgroundTasks,
    mailer: MailerDep,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    """Regain access with a single-use recovery code (e.g. all devices lost). The
    resulting session counts as freshly authenticated, so the user can immediately add
    a new passkey."""
    email = normalize_email(body.email)
    await limiter.hit("recovery_login:ip", client.ip or "unknown", LIMITS["recovery_login:ip"])
    await limiter.hit("recovery:user", email, LIMITS["recovery:user"])

    user = await get_user_by_email(db, email)
    known_id = user.id if user else None  # read before any rollback expires `user`
    active = user is not None and user.status is UserStatus.ACTIVE
    ok = await recovery.consume(db, known_id if active else None, body.code)
    if not ok or user is None:
        await db.rollback()
        await audit.record(
            "signin",
            result=AuditResult.FAILURE,
            severity=Severity.WARNING,
            client=client,
            target_user_id=known_id,
            details={"method": "recovery_code"},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, INVALID_CODE)

    user_id, user_email = user.id, user.email
    left = await recovery.remaining(db, user_id)
    out = await _start_full_session(
        request, response, db, sessions, settings, user, "recovery_code", client
    )
    await audit.record(
        "signin",
        result=AuditResult.SUCCESS,
        severity=Severity.WARNING,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"method": "recovery_code", "codes_remaining": left},
    )
    background.add_task(
        mailer.send,
        security_notice(
            settings, user_email, "recovery_code_used", client, extra=f"Codes left: {left}"
        ),
    )
    return out


# ------------------------------------------------------------------------ step-up


async def _rotate_after_step_up(
    ctx: FullSession, response: Response, db: DB, sessions: Sessions, client: Client
) -> SessionOut:
    """Elevation is a privilege change: rotate the session (and its CSRF token)."""
    user = ctx.user
    new = await sessions.create(
        db,
        response,
        user=user,
        level=SessionLevel.FULL,
        auth_method=ctx.session.auth_method,
        client=client,
        replaces_token=ctx.token,
    )
    out = SessionOut(
        authenticated=True, level="full", user=_user_out(user), csrf_token=new.csrf_token
    )
    await db.commit()
    return out


@router.post("/step-up/passkey/options")
async def step_up_passkey_options(
    ctx: FullSession, db: DB, settings: SettingsDep, redis: RedisDep, limiter: Limiter
) -> dict[str, object]:
    await limiter.hit("step_up:session", str(ctx.session.id), LIMITS["step_up:session"])
    return await _passkeys(settings, redis).step_up_options(db, ctx.user, ctx.session)


@router.post("/step-up/passkey/verify", response_model=SessionOut)
async def step_up_passkey_verify(
    body: StepUpPasskeyRequest,
    ctx: FullSession,
    response: Response,
    db: DB,
    settings: SettingsDep,
    redis: RedisDep,
    sessions: Sessions,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    user_id = ctx.user.id
    try:
        await _passkeys(settings, redis).verify_step_up(db, ctx.user, ctx.session, body.credential)
    except PasskeyError as exc:
        await db.rollback()
        await audit.record(
            "step_up",
            result=AuditResult.FAILURE,
            severity=Severity.HIGH if exc.suspicious else Severity.INFO,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"method": "passkey", "reason": exc.reason},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, PASSKEY_FAILED) from None
    out = await _rotate_after_step_up(ctx, response, db, sessions, client)
    await audit.record(
        "step_up",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"method": "passkey"},
    )
    return out


@router.post("/step-up/totp", response_model=SessionOut)
async def step_up_totp(
    body: TotpCodeRequest,
    ctx: FullSession,
    response: Response,
    db: DB,
    settings: SettingsDep,
    sessions: Sessions,
    limiter: Limiter,
    audit: AuditDep,
    client: Client,
) -> SessionOut:
    user_id = ctx.user.id
    await limiter.hit("totp:user", ctx.user.email, LIMITS["totp:user"])
    totp = TotpService(settings, Encryptor.from_settings(settings))
    if not await totp.verify(db, user_id, body.code):
        await db.rollback()
        await audit.record(
            "step_up",
            result=AuditResult.FAILURE,
            client=client,
            actor_user_id=user_id,
            target_user_id=user_id,
            details={"method": "totp"},
        )
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code isn't valid.")
    out = await _rotate_after_step_up(ctx, response, db, sessions, client)
    await audit.record(
        "step_up",
        result=AuditResult.SUCCESS,
        client=client,
        actor_user_id=user_id,
        target_user_id=user_id,
        details={"method": "totp"},
    )
    return out
