"""Operator commands, run inside the API container:

    docker compose exec api python -m keygate.cli grant-role --email you@example.com --role admin

Bootstrapping the first admin needs shell access to the deployment, deliberately: there
is no web path to become an administrator when none exists.
"""

import argparse
import asyncio
import os
import sys
from datetime import timedelta

from sqlalchemy import select

from keygate.audit.models import AuditResult, Severity
from keygate.audit.service import AuditLog
from keygate.auth.accounts import get_user_by_email
from keygate.config import get_settings
from keygate.db.session import create_engine, create_sessionmaker
from keygate.oidc.clients import build_client
from keygate.oidc.keys import KeyStore
from keygate.oidc.models import OAuthClient
from keygate.rbac.service import RoleChangeError, roles_for, set_roles
from keygate.security.crypto import Encryptor
from keygate.security.tokens import hash_token

MIN_CLIENT_SECRET_LENGTH = 32


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


async def ensure_client(
    *,
    client_id: str,
    name: str,
    secret: str,
    redirect_uris: list[str],
    post_logout_redirect_uris: list[str],
    scopes: list[str],
) -> int:
    """Idempotently register (or update) a confidential client with a known secret.
    Used to seed the Notes demo client in development; production clients are
    registered through the admin UI, which generates the secret."""
    settings = get_settings()
    if len(secret) < MIN_CLIENT_SECRET_LENGTH:
        print(f"Client secret must be at least {MIN_CLIENT_SECRET_LENGTH} chars.", file=sys.stderr)
        return 1
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db:
            existing = (
                await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
            ).scalar_one_or_none()
            if existing is None:
                created = build_client(
                    name=name,
                    confidential=True,
                    redirect_uris=redirect_uris,
                    post_logout_redirect_uris=post_logout_redirect_uris,
                    allowed_scopes=scopes,
                    created_by=None,
                    client_id=client_id,
                    secret=secret,
                )
                db.add(created.client)
                action = "registered"
            else:
                existing.name = name
                existing.redirect_uris = redirect_uris
                existing.post_logout_redirect_uris = post_logout_redirect_uris
                existing.allowed_scopes = scopes
                existing.client_secret_hash = hash_token(secret)
                action = "updated"
            await db.commit()
        print(f"Client {client_id!r} {action}.")
        return 0
    finally:
        await engine.dispose()


async def rotate_signing_key() -> int:
    settings = get_settings()
    engine = create_engine(settings)
    try:
        async with create_sessionmaker(engine)() as db:
            store = KeyStore(Encryptor.from_settings(settings))
            kid = await store.rotate(db)
            # Unpublish keys retired longer ago than any token they signed can live.
            longest = max(
                settings.oidc_access_token_ttl_seconds, settings.oidc_id_token_ttl_seconds
            )
            removed = await store.remove_retired(db, timedelta(seconds=longest * 2))
            await db.commit()
        print(f"New signing key {kid!r} is active; {removed} old key(s) unpublished.")
        return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="keygate.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    grant = sub.add_parser("grant-role", help="Grant a role to an existing account")
    grant.add_argument("--email", required=True)
    grant.add_argument("--role", required=True, choices=["admin", "auditor"])

    client = sub.add_parser("ensure-client", help="Register/update a confidential OIDC client")
    client.add_argument("--client-id", required=True)
    client.add_argument("--name", required=True)
    client.add_argument(
        "--secret-env", required=True, help="Name of the env var holding the client secret"
    )
    client.add_argument("--redirect-uri", action="append", required=True)
    client.add_argument("--post-logout-redirect-uri", action="append", default=[])
    client.add_argument("--scopes", required=True, help="Space-separated")

    sub.add_parser("rotate-signing-key", help="Start signing tokens with a new key")

    args = parser.parse_args(argv)
    if args.command == "grant-role":
        return asyncio.run(grant_role(args.email, args.role))
    if args.command == "ensure-client":
        secret = os.environ.get(args.secret_env, "")
        return asyncio.run(
            ensure_client(
                client_id=args.client_id,
                name=args.name,
                secret=secret,
                redirect_uris=args.redirect_uri,
                post_logout_redirect_uris=args.post_logout_redirect_uri,
                scopes=args.scopes.split(),
            )
        )
    if args.command == "rotate-signing-key":
        return asyncio.run(rotate_signing_key())
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
