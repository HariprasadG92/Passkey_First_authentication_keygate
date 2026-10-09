"""The permission and role catalogue: the single source of truth, seeded by migrations.

Permissions are fine-grained verbs on resources; routes depend on permissions, never on
role names, so roles can be re-shaped without touching endpoint code.
"""

PERMISSIONS: dict[str, str] = {
    "users:read": "Search and view user accounts",
    "users:write": "Suspend and unsuspend user accounts",
    "users:sessions:revoke": "Revoke other users' sessions",
    "roles:assign": "Grant and revoke roles",
    "audit:read": "Read the audit log",
}

ROLES: dict[str, tuple[str, list[str]]] = {
    "user": ("Default role: manages only their own account", []),
    "auditor": (
        "Read-only access to the audit log and user directory",
        ["audit:read", "users:read"],
    ),
    "admin": ("Full administrative access", list(PERMISSIONS)),
}

DEFAULT_ROLE = "user"
ADMIN_ROLE = "admin"
