"""Runbook Prefill and Run step: Prefill fills the step's Workbench form; Run step runs it in place."""

from __future__ import annotations

import asyncio
import json
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
from citius_ui.workbench.shared_runs import SharedRuns


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


class _Artifact:
    def __init__(self, bundle: dict[str, Any]) -> None:
        self._bundle = bundle

    def bundle(self) -> dict[str, Any]:
        return self._bundle


def _ok_registry(_clients: Any) -> ActionRegistry:
    registry = ActionRegistry()
    for service, method in R4_AGILITY.required_actions():

        async def invoke(request: dict[str, Any]) -> RpcResult:
            return RpcResult(status=ResultStatus.OK, message="done", response={"echo": request.get("name")})

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
    sessions, history, shared = SessionStore(), MemoryHistoryStore(), SharedRuns()
    session = sessions.create(subject="ciso", display_name="CISO")
    blocks = build_workbench(config, sessions, history, shared_runs=shared)
    run = _handler(blocks, "_run_runbook_step", "Create policy demo-r4-policy")
    request = SimpleNamespace(cookies={config.session_cookie_name: session.id})
    first = run.inputs[0].choices[0][0]

    goal, diagram, outcome, seen, picker, box, shown = asyncio.run(run.fn(first, 0, request))
    assert f"rect {FILL[StepState.PASSED]}" in diagram and "Green: as expected" in diagram
    assert "**Step 1** (CISO, CreateCryptoPolicy): OK, as expected." in outcome
    assert shared.results("r4-agility")[1].state is StepState.PASSED
    assert seen == shared.version("r4-agility") > 0
    # The exact request and response are there for a closer look.
    assert box["label"] == "Response · step 1 (CreateCryptoPolicy, OK)"
    body = json.loads(shown)
    assert body["status"] == "OK" and body["message"] == "done"
    assert body["request"]["name"] == "demo-r4-policy"
    assert body["response"] == {"echo": "demo-r4-policy"}
    # The picker moves on to the next step, and the call is in the session's history.
    assert picker["value"].startswith("2.")
    [record] = history.list(session.history_id)
    assert (record.method, record.scenario_run_id) == ("CreateCryptoPolicy", "r4-agility:1")
    assert _FakeClients.closed >= 1

    # Step 2 expects a template in the response; an empty OK differs.
    _, diagram, outcome, seen, picker, box, shown = asyncio.run(run.fn(picker["value"], seen, request))
    assert f"rect {FILL[StepState.DIFFERS]}" in diagram and "a value differs" in outcome
    assert picker["value"].startswith("2.")  # it stays on the step that did not pass
    assert box["label"].startswith("Response · step 2")

    # Picking step 1 again shows its response; picking one not run leaves the view alone.
    show = _handler(blocks, "_show_response", "Create policy demo-r4-policy")
    box, shown = show.fn(first, request)
    assert box["label"].startswith("Response · step 1") and json.loads(shown)["request"]["name"] == "demo-r4-policy"
    not_run = run.inputs[0].choices[5][0]
    assert show.fn(not_run, request) == ({"__type__": "update"}, {"__type__": "update"})

    resets = [f for f in blocks.fns.values() if getattr(f.fn, "__name__", "") == "_reset_runbook"]
    assert len(resets) == len(RUNBOOKS)
    r4_reset = next(f for f in resets if any("demo-r4" in str(o) for o in f.outputs[4].choices))
    goal, diagram, outcome, seen, _, box, shown = r4_reset.fn()
    assert outcome == "" and FILL[StepState.PASSED] not in diagram
    assert shared.results("r4-agility") == {} and seen == shared.version("r4-agility")
    assert (box["label"], shown) == ("Response", "")


def test_another_browser_sees_the_step_and_gets_its_bundle(tmp_path: Path, monkeypatch: Any) -> None:
    import citius_ui.workbench.app as app

    calls: list[tuple[str, dict[str, Any]]] = []

    def registry(_clients: Any) -> ActionRegistry:
        registry = ActionRegistry()
        for service, method in R4_AGILITY.required_actions():

            async def invoke(request: dict[str, Any], _method: str = method) -> RpcResult:
                calls.append((_method, request))
                return RpcResult(status=ResultStatus.OK, response={"valid": True, "secret": "only-for-the-signer"})

            registry.register(
                RpcAction(
                    service=service,
                    method=method,
                    permission="",
                    availability=Availability.AVAILABLE,
                    invoke=invoke,
                    extract_artifacts=lambda request, _result: [_Artifact({"key_name": request["key_name"]})],
                )
            )
        return registry

    monkeypatch.setattr(app, "CitiusClients", _FakeClients)
    monkeypatch.setattr(app, "build_registry", registry)
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    sessions, shared = SessionStore(), SharedRuns()
    producer_id = sessions.create(subject="producer", display_name="Producer").id
    consumer_id = sessions.create(subject="consumer", display_name="Consumer").id
    producer = SimpleNamespace(cookies={config.session_cookie_name: producer_id})
    consumer = SimpleNamespace(cookies={config.session_cookie_name: consumer_id})
    blocks = build_workbench(config, sessions, MemoryHistoryStore(), shared_runs=shared)
    run = _handler(blocks, "_run_runbook_step", "Create policy demo-r4-policy")
    refresh = _handler(blocks, "_refresh", "Create policy demo-r4-policy")
    show = _handler(blocks, "_show_response", "Create policy demo-r4-policy")
    label = {value.split(".")[0]: value for value, _ in run.inputs[0].choices}

    # The producer signs (step 3) in their browser.
    asyncio.run(run.fn(label["3"], 0, producer))
    # The consumer's browser, still at version 0, redraws with the producer's step...
    goal, diagram, outcome, seen, picker = refresh.fn(label["1"], 0)
    assert "**Step 3** (Producer, Sign)" in outcome and f"rect {FILL[StepState.PASSED]}" in diagram
    assert seen == shared.version("r4-agility") and picker["value"] == label["1"]  # step 1 is next
    # ...and nothing more until something changes.
    assert refresh.fn(label["1"], seen)[3] == seen and refresh.fn(label["1"], seen)[0] == {"__type__": "update"}
    # It sees how the step went, not the producer's full response.
    _, note = show.fn(label["3"], consumer)
    assert "only-for-the-signer" not in note and "Producer's browser" in note
    assert "only-for-the-signer" in show.fn(label["3"], producer)[1]
    # The consumer verifies (step 5) with the bundle the producer's browser kept.
    asyncio.run(run.fn(label["5"], seen, consumer))
    verify = next(request for method, request in calls if method == "Verify")
    assert json.loads(verify["bundle"]) == {"key_name": "demo-r4-key"}


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
    _, _, outcome, seen, *_ = asyncio.run(run.fn(run.inputs[0].choices[0][0], 0, request))
    assert "No active session" in outcome and seen == 0
