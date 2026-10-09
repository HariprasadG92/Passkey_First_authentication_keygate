"""Writing audit events.

Events are written in their *own* transaction so a failure that rolls back the main
request (e.g. a rejected sign-in) is still recorded. Details must never contain
secrets, tokens, codes or full credential data.
"""

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from keygate.audit.models import AuditEvent, AuditResult, Severity
from keygate.logging_setup import get_logger
from keygate.security.request_info import ClientInfo

log = get_logger("keygate.audit")


class AuditLog:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(
        self,
        event_type: str,
        *,
        result: AuditResult,
        client: ClientInfo | None = None,
        severity: Severity = Severity.INFO,
        actor_user_id: uuid.UUID | None = None,
        target_user_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        event = AuditEvent(
            event_type=event_type,
            result=result,
            severity=severity,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            ip_address=client.ip if client else None,
            user_agent=client.user_agent if client else None,
            request_id=client.request_id if client else None,
            details=details or {},
        )
        async with self._sessionmaker() as session, session.begin():
            session.add(event)
        log.info(
            "audit_event",
            event_type=event_type,
            result=result.value,
            severity=severity.value,
            actor_user_id=str(actor_user_id) if actor_user_id else None,
            target_user_id=str(target_user_id) if target_user_id else None,
        )
