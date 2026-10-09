"""The signed-in user's own account."""

from fastapi import APIRouter
from sqlalchemy import select

from keygate.api.deps import DB, FullSession
from keygate.auth.models import WebAuthnCredential
from keygate.auth.schemas import AccountOut, PasskeyOut, UserOut

router = APIRouter(prefix="/account", tags=["account"])


@router.get("", response_model=AccountOut)
async def get_account(ctx: FullSession, db: DB) -> AccountOut:
    creds = (
        await db.execute(
            select(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == ctx.user.id)
            .order_by(WebAuthnCredential.created_at)
        )
    ).scalars()
    return AccountOut(
        user=UserOut(
            id=ctx.user.id,
            email=ctx.user.email,
            email_verified=ctx.user.email_verified,
            display_name=ctx.user.display_name,
        ),
        passkeys=[
            PasskeyOut(
                id=c.id,
                friendly_name=c.friendly_name,
                created_at=c.created_at,
                last_used_at=c.last_used_at,
                backup_eligible=c.backup_eligible,
                backup_state=c.backup_state,
                transports=c.transports,
            )
            for c in creds
        ],
    )
