"""Operator commands, run inside the API container:

    docker compose exec api python -m keygate.cli grant-role --email you@example.com --role admin

Bootstrapping the first admin needs shell access to the deployment, deliberately: there
is no web path to become an administrator when none exists.
"""

import argparse
import asyncio
import sys

from keygate.audit.models import AuditResult, Severity
from keygate.audit.service import AuditLog
from keygate.auth.accounts import get_user_by_email
from keygate.config import get_settings
from keygate.db.session import create_engine, create_sessionmaker
from keygate.rbac.service import RoleChangeError, roles_for, set_roles


async def grant_role(email: str, role: str) -> int:
    settings = get_settings()
    engine = create_engine(settings)
    sessionmaker = create_sessionmaker(engine)
    try:
        async with sessionmaker() as db:
            user = await get_user_by_email(db, email)
            if user is None:
                print(f"No account with email {email!r}. Sign up first.", file=sys.stderr)
                return 1
            current = set(await roles_for(db, user.id))
            try:
                granted, _ = await set_roles(
                    db, actor_id=None, target_id=user.id, roles=current | {role}
                )
            except RoleChangeError as exc:
                print(exc.message, file=sys.stderr)
                return 1
            await db.commit()
            user_id = user.id
        await AuditLog(sessionmaker).record(
            "role.grant",
            result=AuditResult.SUCCESS,
            severity=Severity.HIGH if role == "admin" else Severity.WARNING,
            target_user_id=user_id,
            details={"roles": sorted(granted), "via": "cli"},
        )
        print(f"{email}: granted {sorted(granted) or 'nothing (already had it)'}")
        return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="keygate.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    grant = sub.add_parser("grant-role", help="Grant a role to an existing account")
    grant.add_argument("--email", required=True)
    grant.add_argument("--role", required=True, choices=["admin", "auditor"])
    args = parser.parse_args(argv)
    if args.command == "grant-role":
        return asyncio.run(grant_role(args.email, args.role))
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
