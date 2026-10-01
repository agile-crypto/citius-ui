"""A runbook as a Mermaid sequence diagram and a goal card.

Both are Markdown for ``gr.Markdown``, which renders fenced ``mermaid``
blocks. Each step is one request from its persona to Citius and the reply
the step expects, numbered as the UI numbers steps. Once a step has run, its
request and reply sit on a band coloured by how it went, and the first step
not yet run is marked as next. The goal card is a checklist of the proofs:
each is ticked, with the values that show it, once every step it names went
as expected.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping

from citius_ui.showcases.model import ExpectedOutcome, Proof, Runbook, RunbookStep, StepState
from citius_ui.showcases.replay import StepResult, evidence
from citius_ui.showcases.runbooks import RUNBOOKS_BY_KEY

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

# Draw the actors once, at the top: the runbooks are tall enough already.
_INIT = '%%{init: {"sequence": {"mirrorActors": false}}}%%'


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
    if not result.status:
        return "not sent", False
    return f"got {result.status}", result.status != "OK"


def sequence_diagram(runbook: Runbook, results: Results | None = None) -> str:
    """The runbook as a fenced Mermaid sequence diagram."""
    results = results or {}
    personas = list(dict.fromkeys(step.persona for step in runbook.steps))
    actor = {persona: f"a{number}" for number, persona in enumerate(personas)}
    upcoming = next_step(runbook, results)
    lines = [_INIT, "sequenceDiagram"]
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


def _value(value: object, join: str) -> str:
    if isinstance(value, list):
        return join.join(_value(item, join) for item in value)
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).replace("`", "'")


def _evidence(proof: Proof, results: Results) -> str:
    """The values that show a proof, each with its label: "sent `name, scope`, version `1`".

    An item whose label starts with an arrow continues the one before it:
    "quantum_safe `true` → `ml-dsa-65`".
    """
    text = ""
    for item in proof.shows:
        shown = f"`{_value(evidence(item, results), item.join)}`"
        part = f"{item.label} {shown}" if item.label else shown
        if text:
            text += " " if item.label.startswith("→") else ", "
        text += part
    return text


def proof_state(proof: Proof, results: Results) -> StepState:
    """PASSED once every step of a proof went as expected; FAILED once one did not; else NOT_RUN."""
    states = [state_of(results, index) for index in proof.steps]
    if any(state in (StepState.FAILED, StepState.DIFFERS) for state in states):
        return StepState.FAILED
    if all(state is StepState.PASSED for state in states):
        return StepState.PASSED
    return StepState.NOT_RUN


# A proof's mark on the goal card, styled by the Workbench (.proof-mark).
PROOF_MARK = {
    StepState.PASSED: '<span class="proof-mark proven">✓</span>',
    StepState.FAILED: '<span class="proof-mark refused">✕</span>',
    StepState.NOT_RUN: '<span class="proof-mark pending">○</span>',
}


def goal_card(runbook: Runbook, results: Results | None = None) -> str:
    """The runbook's goal: its claim, before and after, and a checklist of its proofs.

    A proof is ○ until every step it names has gone as expected, then ✓ in
    bold, with the values from those steps' requests and responses that show
    it. A step that did not go as expected marks its proofs ✕.
    """
    goal = runbook.goal
    if goal is None:
        return ""
    results = results or {}
    states = [proof_state(proof, results) for proof in goal.proofs]
    proven = sum(state is StepState.PASSED for state in states)
    checklist = []
    for proof, state in zip(goal.proofs, states, strict=True):
        where = _numbers(proof.steps)
        mark = PROOF_MARK[state]
        if state is StepState.PASSED:
            shown = _evidence(proof, results)
            checklist.append(f"{mark}**{proof.text}**" + (f" · {shown}" if shown else "") + f" · {where}")
        elif state is StepState.FAILED:
            checklist.append(f"{mark}{proof.text} · {where}: not as expected")
        else:
            checklist.append(f"{mark}{proof.text} · {where}")
    parts = [f"**{goal.claim}**  \n{goal.before} → **{goal.after}**"]
    if runbook.after:
        titles = [RUNBOOKS_BY_KEY[key].title if key in RUNBOOKS_BY_KEY else key for key in runbook.after]
        parts.append(f"_Continues from {', '.join(titles)}._")
    parts += ["  \n".join(checklist), f"**Proven: {proven} of {len(goal.proofs)}**"]
    return "\n\n".join(parts)
