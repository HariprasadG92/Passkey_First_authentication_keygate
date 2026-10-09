"""Step-up re-authentication ("sudo mode").

Sensitive actions (adding/removing sign-in methods, regenerating recovery codes,
changing email) require the user to have proved possession of a sign-in factor within
the last few minutes, not just to hold a session cookie. A stolen session cookie on its
own therefore can't be turned into persistent account access.
"""

from typing import Annotated

from fastapi import Depends, status

from keygate.api.deps import FullSession, SettingsDep
from keygate.auth.sessions import SessionContext
from keygate.db.types import utcnow
from keygate.errors import KeygateError


def step_up_required() -> KeygateError:
    return KeygateError(
        status.HTTP_403_FORBIDDEN, "step_up_required", "Please confirm it's you to continue."
    )


async def require_recent_auth(ctx: FullSession, settings: SettingsDep) -> SessionContext:
    reauth = ctx.session.reauthenticated_at
    if reauth is None or utcnow() - reauth > settings.step_up_ttl:
        raise step_up_required()
    return ctx


SteppedUpSession = Annotated[SessionContext, Depends(require_recent_auth)]
