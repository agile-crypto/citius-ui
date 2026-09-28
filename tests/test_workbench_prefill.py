"""Runbook Prefill: the handler fills the step's Workbench form and switches to it."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.showcases.runbooks import R5_PORTABILITY, RUNBOOKS
from citius_ui.workbench.app import build_workbench


def _prefill_handlers(tmp_path: Path) -> list[Any]:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    blocks = build_workbench(config, SessionStore(), MemoryHistoryStore())
    return [f for f in blocks.fns.values() if getattr(f.fn, "__name__", "") == "_prefill"]


def _value(update: Any) -> Any:
    return update.get("value") if isinstance(update, dict) else getattr(update, "value", None)


def test_every_runbook_gets_a_prefill_that_fills_its_step(tmp_path: Path) -> None:
    handlers = _prefill_handlers(tmp_path)
    assert len(handlers) == len(RUNBOOKS)

    # R5's handler: pick "Provider switch" (step 5), a MigrateKey.
    r5 = next(h for h in handlers if any("demo-r5" in label for label, _ in h.inputs[0].choices))
    label = next(value for value, _ in r5.inputs[0].choices if value.startswith("5."))
    updates = r5.fn(label)
    assert len(updates) == len(r5.outputs)
    values = [_value(u) for u in updates]
    step = R5_PORTABILITY.steps[4]
    assert step.method == "MigrateKey"
    # The method dropdown is set, and the step's request values appear in order.
    assert "MigrateKey" in values
    for value in step.request.values():  # type: ignore[union-attr]
        assert value in values
