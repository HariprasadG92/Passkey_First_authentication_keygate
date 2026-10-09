"""Security notification emails.

Every change to how an account can be signed in to is announced to the account's email
address. If an attacker gets in (e.g. a phished TOTP code), the real owner hears about
it immediately.
"""

from keygate.auth.email import OutgoingEmail
from keygate.config import Settings
from keygate.db.types import utcnow
from keygate.security.request_info import ClientInfo

EVENTS = {
    "passkey_added": "A new passkey was added to your account.",
    "passkey_removed": "A passkey was removed from your account.",
    "totp_enabled": "An authenticator app was set up for your account.",
    "totp_disabled": "The authenticator app was removed from your account.",
    "recovery_codes_regenerated": "New recovery codes were generated. Old codes no longer work.",
    "recovery_code_used": "A recovery code was used to sign in to your account.",
    "email_change_requested": "A request was made to change your account's email address.",
    "email_changed": "Your account's email address was changed.",
}


def security_notice(
    settings: Settings, to: str, event: str, client: ClientInfo, extra: str = ""
) -> OutgoingEmail:
    when = utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return OutgoingEmail(
        to=to,
        subject="Keygate security alert",
        text=(
            f"{EVENTS[event]}\n\n"
            f"When: {when}\n"
            f"IP address: {client.ip or 'unknown'}\n"
            f"Device: {client.user_agent or 'unknown'}\n"
            f"{extra}\n"
            "If this was you, no action is needed. If not, sign in at "
            f"{settings.public_url}/account, revoke unknown sessions and review your "
            "passkeys immediately."
        ),
    )
