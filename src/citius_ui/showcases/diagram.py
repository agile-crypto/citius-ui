"""A runbook as a Mermaid sequence diagram and a goal card.

Both are Markdown for ``gr.Markdown``, which renders fenced ``mermaid``
blocks. Each step is one request from its persona to Citius and the reply
the step expects, numbered as the UI numbers steps. Once a step has run, its
request and reply sit on a band coloured by how it went, and the first step
not yet run is marked as next. The goal card shows a proof in full once
every step it names went as expected.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping

from citius_ui.showcases.model import ExpectedOutcome, Runbook, RunbookStep, StepState
from citius_ui.showcases.replay import StepResult

Results = Mapping[int, StepResult]

# Semi-transparent bands keep the diagram's text readable on light and dark themes.
FILL = {
    StepState.PASSED: "rgba(34,197,94,0.22)",
    StepState.DIFFERS: "rgba(234,179,8,0.28)",
    StepState.FAILED: "rgba(239,68,68,0.24)",
}
NEXT_FILL = "rgba(99,132,230,0.22)"

LEGEND = "Green: as expected · Amber: a value differs · Red: not as expected · Blue: next step"

_REFUSAL = {
    ExpectedOutcome.METHOD_DENIED: "PERMISSION_DENIED",
    ExpectedOutcome.RESOURCE_DENIED: "PERMISSION_DENIED",
    ExpectedOutcome.POLICY_REJECTED: "PERMISSION_DENIED",
    ExpectedOutcome.NOT_FOUND: "NOT_FOUND",
    ExpectedOutcome.FAILED_PRECONDITION: "FAILED_PRECONDITION",
    ExpectedOutcome.INVALID_ARGUMENT: "INVALID_ARGUMENT",
}

# Mermaid ends a statement at ";" and reads "#...;" as an entity code.
_ENTITY = {"#": "#35;", ";": "#59;", "`": "'"}

_MAX_DETAIL = 60


def _text(value: str) -> str:
    return "".join(_ENTITY.get(char, char) for char in value)


def state_of(results: Results, index: int) -> StepState:
    result = results.get(index)
    return result.state if result is not None else StepState.NOT_RUN


def next_step(runbook: Runbook, results: Results) -> int | None:
    """The first step, numbered from 1, that has not gone as expected, or None when all have."""
    for index in range(1, len(runbook.steps) + 1):
        if state_of(results, index) is not StepState.PASSED:
            return index
    return None


def _resource(step: RunbookStep) -> str:
    request = step.request or {}
    for field in ("name", "key_name", "template_id"):
        if request.get(field):
            return str(request[field])
    return ""


def _expected_reply(step: RunbookStep) -> str:
    if step.expected is ExpectedOutcome.SIGNATURE_INVALID:
        return "valid: false"
    if step.expected in _REFUSAL:
        return _REFUSAL[step.expected]
    shown = []
    for path, value in (step.look_for or {}).items():
        field = path.rsplit(".", 1)[-1]
        shown.append(value if isinstance(value, str) else f"{field}: {json.dumps(value)}")
    reply = ", ".join(shown) or "OK"
    if step.copy_bundle and step.bundle:
        reply += f", keep {step.bundle}"
    return reply


def _reply(step: RunbookStep, result: StepResult | None) -> tuple[str, bool]:
    """The reply's text and whether it is a refusal."""
    if result is None or result.state is StepState.PASSED:
        return _expected_reply(step), step.expected in _REFUSAL
    if result.state is StepState.DIFFERS:
        detail = result.detail if len(result.detail) <= _MAX_DETAIL else result.detail[: _MAX_DETAIL - 1] + "…"
        return f"differs: {detail}", False
    return f"got {result.status}", result.status != "OK"


def sequence_diagram(runbook: Runbook, results: Results | None = None) -> str:
    """The runbook as a fenced Mermaid sequence diagram."""
    results = results or {}
    personas = list(dict.fromkeys(step.persona for step in runbook.steps))
    actor = {persona: f"a{number}" for number, persona in enumerate(personas)}
    upcoming = next_step(runbook, results)
    lines = ["sequenceDiagram"]
    lines += [f"  actor {actor[persona]} as {_text(persona)}" for persona in personas]
    lines.append("  participant S as Citius")
    for index, step in enumerate(runbook.steps, start=1):
        result = results.get(index)
        state = state_of(results, index)
        fill = FILL.get(state) or (NEXT_FILL if index == upcoming else "")
        who = actor[step.persona]
        request = f"{index}. {step.method} {_resource(step)}".rstrip()
        if step.bundle and not step.copy_bundle:
            request += f" with {step.bundle}"
        reply, refused = _reply(step, result)
        indent = "    " if fill else "  "
        if fill:
            lines.append(f"  rect {fill}")
        lines.append(f"{indent}{who}->>S: {_text(request)}")
        lines.append(f"{indent}S{'--x' if refused else '-->>'}{who}: {_text(reply)}")
        if fill:
            lines.append("  end")
    return "```mermaid\n" + "\n".join(lines) + "\n```"


def _numbers(steps: Iterable[int]) -> str:
    """Step numbers with consecutive runs joined, e.g. "2–8" or "3, 5"."""
    ordered = sorted(set(steps))
    runs: list[list[int]] = []
    for number in ordered:
        if runs and number == runs[-1][-1] + 1:
            runs[-1].append(number)
        else:
            runs.append([number])
    parts = [f"{run[0]}–{run[-1]}" if len(run) > 2 else ", ".join(map(str, run)) for run in runs]
    label = "step" if len(ordered) == 1 else "steps"
    return f"{label} {', '.join(parts)}"


def goal_card(runbook: Runbook, results: Results | None = None) -> str:
    """The runbook's goal: its claim, before and after, and the proofs, in bold once shown."""
    goal = runbook.goal
    if goal is None:
        return ""
    results = results or {}
    lines = [f"**{goal.claim}**  ", f"{goal.before} → **{goal.after}**", ""]
    for number, proof in enumerate(goal.proofs, start=1):
        shown = all(state_of(results, index) is StepState.PASSED for index in proof.steps)
        text = f"**{proof.text}**" if shown else proof.text
        lines.append(f"{number}. {text} ({_numbers(proof.steps)})")
    return "\n".join(lines)
