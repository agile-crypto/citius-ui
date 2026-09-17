"""Registry mapping service/method pairs to reusable RPC actions."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from citius_ui.actions.model import RpcAction


class ActionRegistry:
    """Holds the registered RPC actions keyed by their qualified name."""

    def __init__(self) -> None:
        self._actions: dict[tuple[str, str], RpcAction] = {}

    def register(self, action: RpcAction) -> None:
        """Register an action, rejecting duplicate service/method pairs."""
        key = (action.service, action.method)
        if key in self._actions:
            raise ValueError(f"action already registered for {action.qualified_name}")
        self._actions[key] = action

    def register_all(self, actions: Iterable[RpcAction]) -> None:
        for action in actions:
            self.register(action)

    def get(self, service: str, method: str) -> RpcAction:
        try:
            return self._actions[(service, method)]
        except KeyError as exc:
            raise KeyError(f"no action registered for {service}.{method}") from exc

    def has(self, service: str, method: str) -> bool:
        return (service, method) in self._actions

    def services(self) -> list[str]:
        return sorted({service for service, _ in self._actions})

    def methods(self, service: str) -> list[str]:
        return sorted(method for svc, method in self._actions if svc == service)

    def __iter__(self) -> Iterator[RpcAction]:
        return iter(self._actions.values())

    def __len__(self) -> int:
        return len(self._actions)
