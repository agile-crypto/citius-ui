from __future__ import annotations

import dataclasses

from citius_ui.showcases.diagram import (
    FILL,
    NEXT_FILL,
    PROOF_MARK,
    goal_card,
    next_step,
    sequence_diagram,
)
from citius_ui.showcases.model import Runbook, StepState
from citius_ui.showcases.replay import StepResult
from citius_ui.showcases.runbooks import (
    RUNBOOKS,
    SHOWCASE_CHOOSE,
    SHOWCASE_GOVERN,
    SHOWCASE_TRANSFORM,
    SHOWCASE_USE,
)


def _result(runbook: Runbook, index: int, state: StepState, status: str = "OK", detail: str = "") -> StepResult:
    return StepResult(index, runbook.steps[index - 1], status, state, detail)


def test_every_runbook_draws_each_step_as_a_numbered_request_and_reply() -> None:
    for runbook in RUNBOOKS:
        text = sequence_diagram(runbook)
        assert text.startswith("```mermaid\n%%{init:") and "\nsequenceDiagram\n" in text, runbook.key
        assert '"mirrorActors": false' in text and text.endswith("\n```"), runbook.key
        for index, step in enumerate(runbook.steps, start=1):
            assert f"->>S: {index}. {step.method}" in text, (runbook.key, index)
        # Nothing has run, so only the first step is marked, as next.
        assert text.count("rect ") == 1 and f"rect {NEXT_FILL}" in text


def test_personas_are_actors_in_order_of_appearance() -> None:
    text = sequence_diagram(SHOWCASE_TRANSFORM)
    assert text.index("as CISO") < text.index("as Producer") < text.index("as Consumer")
    assert "participant S as Citius" in text


def test_expected_refusals_and_bundles_show_in_the_diagram() -> None:
    text = sequence_diagram(SHOWCASE_GOVERN)
    assert "S--xa1: PERMISSION_DENIED" in text  # step 7, the producer's refused Sign
    assert "ecdsa-p256-sha256-der" in text  # what CreateKey should return
    use = sequence_diagram(SHOWCASE_USE)
    assert "1. Sign demo-signing-key" in use and "keep invoice-v1" in use
    assert "2. Verify demo-signing-key with invoice-v1" in use


def test_bands_follow_each_steps_last_result() -> None:
    results = {
        1: _result(SHOWCASE_GOVERN, 1, StepState.PASSED),
        2: _result(SHOWCASE_GOVERN, 2, StepState.DIFFERS, detail='key_metadata.template_id = "x", expected "y"'),
        3: _result(SHOWCASE_GOVERN, 3, StepState.FAILED, status="NOT_FOUND"),
    }
    text = sequence_diagram(SHOWCASE_GOVERN, results)
    for state in (StepState.PASSED, StepState.DIFFERS, StepState.FAILED):
        assert text.count(f"rect {FILL[state]}") == 1
    assert "differs: key_metadata.template_id" in text
    assert "S--xa0: got NOT_FOUND" in text
    # Step 2 is the first that did not go as expected; it keeps its amber band.
    assert next_step(SHOWCASE_GOVERN, results) == 2
    assert NEXT_FILL not in text


def test_the_first_step_not_run_is_next() -> None:
    results = {1: _result(SHOWCASE_GOVERN, 1, StepState.PASSED)}
    assert next_step(SHOWCASE_GOVERN, results) == 2
    lines = sequence_diagram(SHOWCASE_GOVERN, results).splitlines()
    assert lines[lines.index(f"  rect {NEXT_FILL}") + 1].endswith("2. CreateKey demo-governed-key-1")
    everything = {i: _result(SHOWCASE_GOVERN, i, StepState.PASSED) for i in range(1, len(SHOWCASE_GOVERN.steps) + 1)}
    assert next_step(SHOWCASE_GOVERN, everything) is None


def test_mermaid_separators_in_step_text_are_escaped() -> None:
    step = dataclasses.replace(SHOWCASE_GOVERN.steps[1], request={"name": "demo-a;b#c"})
    runbook = dataclasses.replace(SHOWCASE_GOVERN, steps=(step,))
    text = sequence_diagram(runbook)
    assert "demo-a#59;b#35;c" in text and "demo-a;b" not in text


def test_goal_card_ticks_a_proof_once_all_its_steps_passed() -> None:
    pending, proven, refused = (PROOF_MARK[s] for s in (StepState.NOT_RUN, StepState.PASSED, StepState.FAILED))
    goal = SHOWCASE_GOVERN.goal
    assert goal is not None
    card = goal_card(SHOWCASE_GOVERN)
    assert card.startswith(f"**{goal.claim}**")
    assert f"{goal.before} → **{goal.after}**" in card
    assert f"{pending}The same request gets a new answer after the CISO reorders the policy · steps 2–4" in card
    assert proven not in card and f"**Proven: 0 of {len(goal.proofs)}**" in card

    results = {i: _result(SHOWCASE_GOVERN, i, StepState.PASSED) for i in (2, 3, 4)}
    card = goal_card(SHOWCASE_GOVERN, results)
    # A proven claim shows its values (none here: the results carry no response).
    assert f"{proven}**The same request gets a new answer after the CISO reorders the policy** · before" in card
    # Steps 5–7 have not run, so the second proof is not shown yet.
    assert f"{pending}A policy change applies on the next call · steps 5–7" in card
    assert f"**Proven: 1 of {len(goal.proofs)}**" in card

    results |= {i: _result(SHOWCASE_GOVERN, i, StepState.PASSED) for i in (5, 6)}
    results[7] = _result(SHOWCASE_GOVERN, 7, StepState.FAILED, status="OK")
    card = goal_card(SHOWCASE_GOVERN, results)
    assert f"{refused}A policy change applies on the next call · steps 5–7: not as expected" in card


def test_goal_card_shows_the_values_that_prove_a_claim() -> None:
    step = SHOWCASE_CHOOSE.steps[2]
    result = StepResult(
        3,
        step,
        "OK",
        StepState.PASSED,
        request={"name": "demo-pqc-signing-key", "quantum_safe": "true"},
        response={"key_metadata": {"template_id": "ml-dsa-65"}},
    )
    card = goal_card(SHOWCASE_CHOOSE, {3: result})
    proven = PROOF_MARK[StepState.PASSED]
    assert f"{proven}**A filter narrows the choice** · quantum_safe `true` → `ml-dsa-65` · step 3" in card
    # A runbook that continues another says so.
    assert "_Continues from 1 · Choose._" in goal_card(SHOWCASE_USE)


def test_goal_card_joins_consecutive_steps() -> None:
    assert "· steps 2–4" in goal_card(SHOWCASE_GOVERN)
    assert "· step 2" in goal_card(SHOWCASE_CHOOSE)
