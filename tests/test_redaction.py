from __future__ import annotations

from citius_ui.auth.redaction import REDACTED, redact


def test_redact_replaces_sensitive_keys() -> None:
    payload = {
        "key_name": "demo-key",
        "authorization": "Bearer secret",
        "nested": {"access_token": "abc", "plaintext": "keep"},
        "list": [{"client_secret": "s"}, {"note": "safe"}],
    }
    redacted = redact(payload)
    assert redacted["key_name"] == "demo-key"
    assert redacted["authorization"] == REDACTED
    assert redacted["nested"]["access_token"] == REDACTED
    assert redacted["nested"]["plaintext"] == "keep"
    assert redacted["list"][0]["client_secret"] == REDACTED
    assert redacted["list"][1]["note"] == "safe"


def test_redact_does_not_mutate_input() -> None:
    payload = {"password": "p", "keep": "v"}
    redact(payload)
    assert payload["password"] == "p"


def test_redact_passes_through_scalars() -> None:
    assert redact("value") == "value"
    assert redact(7) == 7
