"""ORM model registry.

Import every model module here so ``Base.metadata`` is complete for Alembic autogenerate.
"""

from keygate.audit.models import AuditEvent
from keygate.auth.models import EmailToken, Session, User, WebAuthnCredential
from keygate.db.base import Base
from keygate.mfa.models import RecoveryCode, TotpCredential

__all__ = [
    "AuditEvent",
    "Base",
    "EmailToken",
    "RecoveryCode",
    "Session",
    "TotpCredential",
    "User",
    "WebAuthnCredential",
]
