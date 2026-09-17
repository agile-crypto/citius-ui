from __future__ import annotations

import pytest

from citius_ui.actions import Availability, RpcAction
from citius_ui.actions.registry import ActionRegistry


def _action(service: str, method: str) -> RpcAction:
    return RpcAction(service=service, method=method, permission="citius:x", availability=Availability.AVAILABLE)


def test_register_and_get() -> None:
    registry = ActionRegistry()
    action = _action("CryptoService", "Sign")
    registry.register(action)
    assert registry.get("CryptoService", "Sign") is action
    assert registry.has("CryptoService", "Sign")
    assert len(registry) == 1


def test_register_rejects_duplicates() -> None:
    registry = ActionRegistry()
    registry.register(_action("CryptoService", "Sign"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_action("CryptoService", "Sign"))


def test_get_unknown_raises() -> None:
    registry = ActionRegistry()
    with pytest.raises(KeyError, match="no action registered"):
        registry.get("CryptoService", "Missing")


def test_services_and_methods_are_sorted() -> None:
    registry = ActionRegistry()
    registry.register_all(
        [
            _action("CryptoService", "Verify"),
            _action("CryptoService", "Sign"),
            _action("KeyManagementService", "CreateKey"),
        ]
    )
    assert registry.services() == ["CryptoService", "KeyManagementService"]
    assert registry.methods("CryptoService") == ["Sign", "Verify"]
