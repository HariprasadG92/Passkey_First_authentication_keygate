"""ORM model registry.

Import every model module here so ``Base.metadata`` is complete for Alembic autogenerate.
"""

from keygate.audit.models import AuditEvent
from keygate.auth.models import EmailToken, Session, User, WebAuthnCredential
from keygate.db.base import Base
from keygate.mfa.models import RecoveryCode, TotpCredential
from keygate.rbac.models import Permission, Role, UserRole
from keygate.social.models import SocialAccount

__all__ = [
    "AuditEvent",
    "Base",
    "EmailToken",
    "Permission",
    "RecoveryCode",
    "Role",
    "Session",
    "SocialAccount",
    "TotpCredential",
    "User",
    "UserRole",
    "WebAuthnCredential",
]
