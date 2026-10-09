"""Scopes Keygate can grant, with the wording shown on the consent screen."""

SCOPES: dict[str, str] = {
    "openid": "Sign you in with your Keygate account",
    "profile": "See your name",
    "email": "See your email address",
    "notes:read": "Read your notes",
    "notes:write": "Create, change and delete your notes",
}

# Scopes whose tokens are meant for the Notes resource server.
NOTES_SCOPES = frozenset({"notes:read", "notes:write"})


def parse_scope(value: str | None) -> list[str]:
    """Space-delimited, de-duplicated, order-preserving."""
    seen: dict[str, None] = {}
    for item in (value or "").split():
        seen.setdefault(item, None)
    return list(seen)
