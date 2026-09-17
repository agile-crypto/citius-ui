"""Redaction of sensitive values before recording or logging."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

REDACTED = "***redacted***"

_SENSITIVE_KEY_FRAGMENTS = (
    "token",
    "password",
    "passwd",
    "secret",
    "authorization",
    "client_secret",
    "private_key",
    "privatekey",
    "key_material",
    "unwrapping_key",
    "wrapping_key",
    "credential",
    "bearer",
)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def redact(value: Any) -> Any:
    """Return a deep copy with sensitive keys replaced by a redaction marker."""
    if isinstance(value, Mapping):
        return {key: REDACTED if _is_sensitive(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value
