"""Append-only audit log.

Rows are inserted, never updated or deleted: a database trigger (see the migration)
rejects UPDATE and DELETE, so even a bug or compromised app code path can't quietly
rewrite history.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from keygate.db.base import Base


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


class AuditResult(enum.StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="audit_severity", values_callable=lambda e: [m.value for m in e])
    )
    result: Mapped[AuditResult] = mapped_column(
        Enum(AuditResult, name="audit_result", values_callable=lambda e: [m.value for m in e])
    )
    # No foreign keys: audit history must survive deletion of the users it mentions.
    actor_user_id: Mapped[uuid.UUID | None]
    target_user_id: Mapped[uuid.UUID | None]
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    __table_args__ = (
        Index("ix_audit_events_occurred_at", "occurred_at"),
        Index("ix_audit_events_event_type", "event_type"),
        Index("ix_audit_events_target_user_id", "target_user_id"),
        Index("ix_audit_events_actor_user_id", "actor_user_id"),
    )
