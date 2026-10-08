"""Property sections: add a property to show it, ✕ to clear and hide it; whatever fills a form shows what it set."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import gradio as gr
import pytest

from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.showcases.runbooks import RUNBOOKS
from citius_ui.workbench.app import _example_loader, _FormLayout, _render_section, _SectionView, build_workbench
from citius_ui.workbench.forms import FORMS_BY_METHOD, Example, RpcFormSpec

CREATE_KEY = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]


def _value(update: Any) -> Any:
    return update.get("value") if isinstance(update, dict) else getattr(update, "value", None)


def _visible(update: Any) -> Any:
    return update.get("visible") if isinstance(update, dict) else getattr(update, "visible", None)


def _render(spec: RpcFormSpec) -> tuple[gr.Blocks, _FormLayout]:
    with gr.Blocks() as blocks:
        components: dict[str, gr.components.Component] = {}
        views = [_render_section(spec, section, fields, components) for section, fields in spec.sections()]
    return blocks, _FormLayout(spec, tuple(views))


def _handler(blocks: gr.Blocks, name: str, view: _SectionView, key: str = "") -> Any:
    """The section's add handler, or the drop handler of property ``key``."""
    for fn in blocks.fns.values():
        if getattr(fn.fn, "__name__", "") != name or view.shown not in fn.outputs:
            continue
        if name == "add" or fn.fn.__defaults__ == (key,):
            return fn.fn
    raise AssertionError(f"no {name} handler for {key or 'the section'}")


def _shown_rows(view: _SectionView, updates: list[Any]) -> list[str]:
    rows = updates[3 : 3 + len(view.fields)]
    return [field.key for field, row in zip(view.fields, rows, strict=True) if _visible(row)]


def _field_values(view: _SectionView, updates: list[Any]) -> dict[str, Any]:
    tail = updates[len(view.outputs()) :]
    return {field.key: _value(update) for field, update in zip(view.fields, tail, strict=True)}


def test_adding_a_property_shows_its_row_sets_it_and_takes_it_off_the_adder() -> None:
    blocks, layout = _render(CREATE_KEY)
    security = layout.sections[0]
    add = _handler(blocks, "add", security)

    updates = add("quantum_safe", [])
    assert updates[0] == ["quantum_safe"]
    assert _shown_rows(security, updates) == ["quantum_safe"]
    # Added as true: one adds a yes/no property to ask for it.
    assert _field_values(security, updates)["quantum_safe"] == "true"
    adder = updates[1]
    assert "quantum_safe" not in [key for _, key in adder["choices"]]
    assert adder["value"] is None
    assert _visible(updates[2]) is False  # "none set" note hidden

    # A second property keeps the first one on show, and leaves its value alone.
    updates = add("security_strength_bits", ["quantum_safe"])
    assert updates[0] == ["quantum_safe", "security_strength_bits"]
    assert _field_values(security, updates)["quantum_safe"] is None  # gr.update(): unchanged


def test_a_requirement_is_ticked_when_added() -> None:
    blocks, layout = _render(CREATE_KEY)
    requirements = layout.sections[1]
    updates = _handler(blocks, "add", requirements)("require_memory_safe", [])
    assert _field_values(requirements, updates)["require_memory_safe"] is True


def test_removing_a_property_clears_it_and_hides_its_row() -> None:
    blocks, layout = _render(CREATE_KEY)
    security = layout.sections[0]
    drop = _handler(blocks, "drop", security, "quantum_safe")

    updates = drop(["quantum_safe", "nist_status"])
    assert updates[0] == ["nist_status"]
    assert _shown_rows(security, updates) == ["nist_status"]
    assert _field_values(security, updates)["quantum_safe"] is None  # radio blank
    assert "quantum_safe" in [key for _, key in updates[1]["choices"]]

    updates = _handler(blocks, "drop", security, "nist_status")(["nist_status"])
    assert updates[0] == []
    assert _visible(updates[2]) is True  # "none set" note back


def test_the_adder_is_hidden_once_every_property_is_on_show() -> None:
    _, layout = _render(CREATE_KEY)
    security = layout.sections[0]
    updates = security.show(field.key for field in security.fields)
    assert _visible(updates[1]) is False


def test_a_fresh_form_shows_no_property() -> None:
    _, layout = _render(CREATE_KEY)
    updates = layout.updates(CREATE_KEY.example_values(Example("A fresh form")))
    for view in layout.sections:
        section = updates[: len(view.outputs())]
        updates = updates[len(view.outputs()) :]
        assert section[0] == []
        assert _shown_rows(view, section) == []


def _shown_by(layout: _FormLayout, updates: list[Any]) -> set[str]:
    shown: set[str] = set()
    for view in layout.sections:
        shown.update(updates[0])
        updates = updates[len(view.outputs()) :]
    return shown


def _set_keys(spec: RpcFormSpec, values: dict[str, Any]) -> set[str]:
    in_sections = {field.key: field for _, fields in spec.sections() for field in fields}
    return {key for key, value in values.items() if key in in_sections and value not in (None, "", False)}


@pytest.mark.parametrize(
    ("spec", "example"),
    [(spec, example) for spec in FORMS_BY_METHOD.values() if spec.sections() for example in spec.examples],
    ids=lambda item: getattr(item, "method", None) or getattr(item, "text", None),
)
def test_an_example_shows_exactly_the_properties_it_sets(spec: RpcFormSpec, example: Example) -> None:
    _, layout = _render(spec)
    index = spec.examples.index(example)
    loaded = _example_loader(spec, layout)(index)
    loaded = loaded if isinstance(loaded, list) else [loaded]
    assert len(loaded) == len(spec.fields) + len(layout.outputs())
    assert _shown_by(layout, loaded[len(spec.fields) :]) == _set_keys(spec, dict(example.values))


def test_every_yes_no_value_in_examples_and_runbooks_is_a_choice() -> None:
    def check(spec: RpcFormSpec, values: dict[str, Any], where: str) -> None:
        for field in spec.fields:
            if field.kind == "radio" and values.get(field.key) is not None:
                assert values[field.key] in field.choices, f"{where}: {field.key}={values[field.key]!r}"

    for spec in FORMS_BY_METHOD.values():
        for example in spec.examples:
            check(spec, dict(example.values), f"{spec.method} example {example.text!r}")
    for runbook in RUNBOOKS:
        for step in runbook.steps:
            spec = FORMS_BY_METHOD.get((step.service, step.method))
            if spec is not None:
                check(spec, dict(step.request or {}), f"{runbook.title} {step.title}")


def _prefill_handlers(tmp_path: Path) -> list[Any]:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    blocks = build_workbench(config, SessionStore(), MemoryHistoryStore())
    return [f for f in blocks.fns.values() if getattr(f.fn, "__name__", "") == "_prefill"]


def _runbook_of(labels: list[str]) -> Any:
    """The runbook whose step list is ``labels`` ("{number}. {persona} · {title}")."""

    def matches(runbook: Any, label: str) -> bool:
        number = int(label.split(".", 1)[0])
        return number <= len(runbook.steps) and label.endswith(runbook.steps[number - 1].title)

    return next(r for r in RUNBOOKS if all(matches(r, label) for label in labels))


def test_prefill_shows_the_properties_a_step_sets(tmp_path: Path) -> None:
    """Every runbook step with section properties shows them, as a State update, once prefilled."""
    checked = 0
    for handler in _prefill_handlers(tmp_path):
        labels = [value for value, _ in handler.inputs[0].choices]
        runbook = _runbook_of(labels)
        for label in labels:
            step = runbook.steps[int(label.split(".", 1)[0]) - 1]
            spec = FORMS_BY_METHOD.get((step.service, step.method))
            if spec is None or not spec.sections():
                continue
            wanted = _set_keys(spec, dict(step.request or {}))
            updates = handler.fn(label)
            assert len(updates) == len(handler.outputs)
            # The section States in the outputs: the ones updated with a list.
            shown: set[str] = set()
            for output, update in zip(handler.outputs, updates, strict=True):
                if isinstance(output, gr.State) and isinstance(update, list):
                    shown.update(update)
            assert shown == wanted, f"{runbook.title} {label}"
            checked += 1
    assert checked > 0
