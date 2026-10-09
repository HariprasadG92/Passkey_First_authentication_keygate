import pytest

from keygate.logging_setup import REDACTED, is_sensitive_key, redact_sensitive


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "client_secret",
        "access_token",
        "Authorization",
        "Set-Cookie",
        "session_id",
        "totp",
        "code_verifier",
        "recovery_code",
        "challenge",
    ],
)
def test_sensitive_keys_detected(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["status_code", "error_code", "path", "method", "user_id", "event"])
def test_ordinary_keys_not_redacted(key: str) -> None:
    assert not is_sensitive_key(key)


def test_redaction_is_recursive_and_keeps_event() -> None:
    event = {
        "event": "token_issued",
        "access_token": "eyJ...",
        "user_id": "u1",
        "headers": {"authorization": "Bearer x", "accept": "json"},
        "items": [{"client_secret": "s"}],
    }
    out = redact_sensitive(None, "info", event)
    assert out["event"] == "token_issued"
    assert out["access_token"] == REDACTED
    assert out["user_id"] == "u1"
    assert out["headers"] == {"authorization": REDACTED, "accept": "json"}
    assert out["items"] == [{"client_secret": REDACTED}]
