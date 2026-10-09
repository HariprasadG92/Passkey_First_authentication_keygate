from keygate.auth.email import OutgoingEmail, SMTPMailer
from tests.conftest import make_settings


async def test_smtp_failure_is_swallowed_and_not_leaked() -> None:
    """A mail outage must not turn into a 500 (which would reveal the branch taken)."""
    mailer = SMTPMailer(make_settings(smtp_host="127.0.0.1", smtp_port=1))
    await mailer.send(OutgoingEmail(to="a@example.com", subject="s", text="t"))
