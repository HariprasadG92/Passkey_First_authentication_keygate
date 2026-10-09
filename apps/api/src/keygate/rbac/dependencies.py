"""``require_permission(...)``: route-level authorization.

Routes declare the permissions they need, never role names. Denials are audited, so
probing for admin endpoints shows up in the log. With ``step_up=True`` the caller must
also have re-authenticated recently; the permission is checked *first*, so a user
without it gets a plain 403 rather than a re-authentication prompt.
"""

from collections.abc import Awaitable, Callable

from fastapi import status

from keygate.api.deps import DB, AuditDep, Client, FullSession, SettingsDep
from keygate.audit.models import AuditResult, Severity
from keygate.auth.sessions import SessionContext
from keygate.auth.stepup import require_recent_auth
from keygate.errors import KeygateError
from keygate.rbac.service import permissions_for


def require_permission(
    *required: str, step_up: bool = False
) -> Callable[..., Awaitable[SessionContext]]:
    async def dependency(
        ctx: FullSession, db: DB, audit: AuditDep, client: Client, settings: SettingsDep
    ) -> SessionContext:
        granted = await permissions_for(db, ctx.user.id)
        missing = set(required) - granted
        if missing:
            await audit.record(
                "authz.denied",
                result=AuditResult.FAILURE,
                severity=Severity.WARNING,
                client=client,
                actor_user_id=ctx.user.id,
                details={"missing": sorted(missing)},
            )
            raise KeygateError(
                status.HTTP_403_FORBIDDEN, "forbidden", "You don't have permission to do that."
            )
        if step_up:
            await require_recent_auth(ctx, settings)
        return ctx

    return dependency
