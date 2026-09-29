"""Runbook Prefill and Run step: Prefill fills the step's Workbench form; Run step runs it in place."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from citius_ui.actions.model import Availability, ResultStatus, RpcAction, RpcResult
from citius_ui.actions.registry import ActionRegistry
from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.showcases.diagram import FILL
from citius_ui.showcases.model import StepState
from citius_ui.showcases.runbooks import R4_AGILITY, R5_PORTABILITY, RUNBOOKS
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


class _FakeClients:
    closed = 0

    def __init__(self, *_: Any) -> None:
        pass

    async def close(self) -> None:
        _FakeClients.closed += 1


def _ok_registry(_clients: Any) -> ActionRegistry:
    registry = ActionRegistry()
    for service, method in R4_AGILITY.required_actions():

        async def invoke(request: dict[str, Any]) -> RpcResult:
            return RpcResult(status=ResultStatus.OK)

        registry.register(
            RpcAction(service=service, method=method, permission="", availability=Availability.AVAILABLE, invoke=invoke)
        )
    return registry


def _handler(blocks: Any, name: str, runbook_key: str) -> Any:
    for f in blocks.fns.values():
        if getattr(f.fn, "__name__", "") == name and any(
            runbook_key in label for label, _ in f.inputs[0].choices if hasattr(f.inputs[0], "choices")
        ):
            return f
    raise AssertionError(f"no {name} for {runbook_key}")


def test_run_step_runs_through_the_executor_and_colours_the_step(tmp_path: Path, monkeypatch: Any) -> None:
    import citius_ui.workbench.app as app

    monkeypatch.setattr(app, "CitiusClients", _FakeClients)
    monkeypatch.setattr(app, "build_registry", _ok_registry)
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    sessions, history = SessionStore(), MemoryHistoryStore()
    session = sessions.create(subject="ciso", display_name="CISO")
    blocks = build_workbench(config, sessions, history)
    run = _handler(blocks, "_run_runbook_step", "Create policy demo-r4-policy")
    request = SimpleNamespace(cookies={config.session_cookie_name: session.id})
    first = run.inputs[0].choices[0][0]

    goal, diagram, outcome, state, picker = asyncio.run(run.fn(first, None, request))
    assert f"rect {FILL[StepState.PASSED]}" in diagram and "Green: as expected" in diagram
    assert "**Step 1** (CISO, CreateCryptoPolicy): OK, as expected." in outcome
    assert state["results"][1].state is StepState.PASSED
    # The picker moves on to the next step, and the call is in the session's history.
    assert picker["value"].startswith("2.")
    [record] = history.list(session.history_id)
    assert (record.method, record.scenario_run_id) == ("CreateCryptoPolicy", "r4-agility:1")
    assert _FakeClients.closed >= 1

    # Step 2 expects a template in the response; an empty OK differs.
    _, diagram, outcome, state, picker = asyncio.run(run.fn(picker["value"], state, request))
    assert f"rect {FILL[StepState.DIFFERS]}" in diagram and "a value differs" in outcome
    assert picker["value"].startswith("2.")  # it stays on the step that did not pass

    resets = [f for f in blocks.fns.values() if getattr(f.fn, "__name__", "") == "_reset_runbook"]
    assert len(resets) == len(RUNBOOKS)
    goal, diagram, outcome, state, _ = resets[3].fn()
    assert state is None and outcome == "" and FILL[StepState.PASSED] not in diagram


def test_each_runbooks_text_sits_in_a_closed_details_section(tmp_path: Path) -> None:
    import gradio as gr

    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    blocks = build_workbench(config, SessionStore(), MemoryHistoryStore())
    details = [b for b in blocks.blocks.values() if isinstance(b, gr.Accordion) and b.label == "Details"]
    assert len(details) == len(RUNBOOKS)
    assert not any(d.open for d in details)
    texts = [child.value for d in details for child in d.children if isinstance(child, gr.Markdown)]
    assert [any(rb.summary in text for text in texts) for rb in RUNBOOKS] == [True] * len(RUNBOOKS)


def test_run_step_without_a_session_changes_nothing(tmp_path: Path) -> None:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    blocks = build_workbench(config, SessionStore(), MemoryHistoryStore())
    run = _handler(blocks, "_run_runbook_step", "Create policy demo-r4-policy")
    request = SimpleNamespace(cookies={})
    _, _, outcome, state, _ = asyncio.run(run.fn(run.inputs[0].choices[0][0], None, request))
    assert "No active session" in outcome and state == {"results": {}, "bundles": {}}
