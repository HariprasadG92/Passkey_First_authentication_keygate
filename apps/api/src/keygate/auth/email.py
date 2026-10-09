"""Outbound email.

``Mailer`` is a small protocol so tests can capture messages in memory; in development
SMTP goes to Mailpit.
"""

from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

import aiosmtplib

from keygate.config import Settings
from keygate.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class OutgoingEmail:
    to: str
    subject: str
    text: str


class Mailer(Protocol):
    async def send(self, message: OutgoingEmail) -> None: ...


class SMTPMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, message: OutgoingEmail) -> None:
        msg = EmailMessage()
        msg["From"] = self._settings.smtp_from
        msg["To"] = message.to
        msg["Subject"] = message.subject
        msg.set_content(message.text)
        password = self._settings.smtp_password
        try:
            await aiosmtplib.send(
                msg,
                hostname=self._settings.smtp_host,
                port=self._settings.smtp_port,
                username=self._settings.smtp_username,
                password=password.get_secret_value() if password else None,
                start_tls=self._settings.smtp_starttls,
                timeout=10,
            )
        except Exception as exc:
            # Never let email failures leak to the client (that would reveal which
            # addresses we tried to mail); log the failure type only.
            log.error("email_send_failed", error_type=type(exc).__name__)


@dataclass
class InMemoryMailer:
    """Test double that records sent messages."""

    outbox: list[OutgoingEmail] = field(default_factory=list)

    async def send(self, message: OutgoingEmail) -> None:
        self.outbox.append(message)
