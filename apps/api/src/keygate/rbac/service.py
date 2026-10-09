"""Role assignment and permission resolution."""

import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from keygate.rbac.catalog import ADMIN_ROLE, DEFAULT_ROLE
from keygate.rbac.models import Permission, Role, UserRole, role_permissions


class RoleChangeError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


async def permissions_for(db: AsyncSession, user_id: uuid.UUID) -> set[str]:
    """Resolved fresh from the database on every check: revoking a role takes effect on
    the very next request, with no cached privileges in sessions or tokens."""
    rows = await db.execute(
        select(Permission.name)
        .join(role_permissions, role_permissions.c.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == role_permissions.c.role_id)
        .where(UserRole.user_id == user_id)
    )
    return set(rows.scalars())


async def roles_for(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    rows = await db.execute(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return sorted(rows.scalars())


async def _role_ids(db: AsyncSession, names: set[str]) -> dict[str, uuid.UUID]:
    rows = await db.execute(select(Role.name, Role.id).where(Role.name.in_(names)))
    # Not dict(rows): a Result has .keys(), which would make dict() treat it as a mapping.
    return {name: role_id for name, role_id in rows.all()}  # noqa: C416


async def assign_default_role(db: AsyncSession, user_id: uuid.UUID) -> None:
    ids = await _role_ids(db, {DEFAULT_ROLE})
    db.add(UserRole(user_id=user_id, role_id=ids[DEFAULT_ROLE]))


async def count_admins(db: AsyncSession) -> int:
    return (
        await db.execute(
            select(func.count())
            .select_from(UserRole)
            .join(Role, Role.id == UserRole.role_id)
            .where(Role.name == ADMIN_ROLE)
        )
    ).scalar_one()


async def set_roles(
    db: AsyncSession,
    *,
    actor_id: uuid.UUID | None,
    target_id: uuid.UUID,
    roles: set[str],
) -> tuple[set[str], set[str]]:
    """Replace the target's roles. Returns (granted, revoked).

    Rules: an admin can't change their own roles (no self-escalation or accidental
    self-lockout), every account keeps the default role, and the last admin can't be
    demoted (the caller holds a lock that serialises role changes)."""
    if actor_id is not None and actor_id == target_id:
        raise RoleChangeError("cannot_change_own_roles", "You can't change your own roles.")
    roles = roles | {DEFAULT_ROLE}
    known = await _role_ids(db, roles)
    unknown = roles - set(known)
    if unknown:
        raise RoleChangeError("unknown_role", f"Unknown role(s): {', '.join(sorted(unknown))}.")

    current = set(await roles_for(db, target_id))
    granted, revoked = roles - current, current - roles
    if ADMIN_ROLE in revoked and await count_admins(db) <= 1:
        raise RoleChangeError("last_admin", "The last admin can't be demoted.")

    if revoked:
        revoked_ids = (await _role_ids(db, revoked)).values()
        await db.execute(
            delete(UserRole).where(UserRole.user_id == target_id, UserRole.role_id.in_(revoked_ids))
        )
    for name in granted:
        db.add(UserRole(user_id=target_id, role_id=known[name], granted_by=actor_id))
    await db.flush()
    return granted, revoked
