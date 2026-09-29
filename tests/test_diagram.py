from __future__ import annotations

import dataclasses

from citius_ui.showcases.diagram import (
    FILL,
    NEXT_FILL,
    goal_card,
    next_step,
    sequence_diagram,
)
from citius_ui.showcases.model import Runbook, StepState
from citius_ui.showcases.replay import StepResult
from citius_ui.showcases.runbooks import R3_POLICY, R4_AGILITY, RUNBOOKS


def _result(runbook: Runbook, index: int, state: StepState, status: str = "OK", detail: str = "") -> StepResult:
    return StepResult(index, runbook.steps[index - 1], status, state, detail)


def test_every_runbook_draws_each_step_as_a_numbered_request_and_reply() -> None:
    for runbook in RUNBOOKS:
        text = sequence_diagram(runbook)
        assert text.startswith("```mermaid\nsequenceDiagram\n") and text.endswith("\n```"), runbook.key
        for index, step in enumerate(runbook.steps, start=1):
            assert f"->>S: {index}. {step.method}" in text, (runbook.key, index)
        # Nothing has run, so only the first step is marked, as next.
        assert text.count("rect ") == 1 and f"rect {NEXT_FILL}" in text


def test_personas_are_actors_in_order_of_appearance() -> None:
    text = sequence_diagram(R4_AGILITY)
    assert text.index("as CISO") < text.index("as Producer") < text.index("as Consumer")
    assert "participant S as Citius" in text


def test_expected_refusals_and_bundles_show_in_the_diagram() -> None:
    text = sequence_diagram(R3_POLICY)
    assert "S--xa1: PERMISSION_DENIED" in text  # step 5, the producer's refused Sign
    r4 = sequence_diagram(R4_AGILITY)
    assert "3. Sign demo-r4-key" in r4 and "keep r4-ecdsa" in r4
    assert "5. Verify demo-r4-key with r4-ecdsa" in r4
    assert "ecdsa-p256-sha256-der" in r4  # what CreateKey should return


def test_bands_follow_each_steps_last_result() -> None:
    results = {
        1: _result(R4_AGILITY, 1, StepState.PASSED),
        2: _result(R4_AGILITY, 2, StepState.DIFFERS, detail='key_metadata.template_id = "x", expected "y"'),
        3: _result(R4_AGILITY, 3, StepState.FAILED, status="NOT_FOUND"),
    }
    text = sequence_diagram(R4_AGILITY, results)
    for state in (StepState.PASSED, StepState.DIFFERS, StepState.FAILED):
        assert text.count(f"rect {FILL[state]}") == 1
    assert "differs: key_metadata.template_id" in text
    assert "S--xa1: got NOT_FOUND" in text
    # Step 2 is the first that did not go as expected; it keeps its amber band.
    assert next_step(R4_AGILITY, results) == 2
    assert NEXT_FILL not in text


def test_the_first_step_not_run_is_next() -> None:
    results = {1: _result(R4_AGILITY, 1, StepState.PASSED)}
    assert next_step(R4_AGILITY, results) == 2
    lines = sequence_diagram(R4_AGILITY, results).splitlines()
    assert lines[lines.index(f"  rect {NEXT_FILL}") + 1].endswith("2. CreateKey demo-r4-key")
    everything = {i: _result(R4_AGILITY, i, StepState.PASSED) for i in range(1, len(R4_AGILITY.steps) + 1)}
    assert next_step(R4_AGILITY, everything) is None


def test_mermaid_separators_in_step_text_are_escaped() -> None:
    step = dataclasses.replace(R4_AGILITY.steps[1], request={"name": "demo-a;b#c"})
    runbook = dataclasses.replace(R4_AGILITY, steps=(step,))
    text = sequence_diagram(runbook)
    assert "demo-a#59;b#35;c" in text and "demo-a;b" not in text


def test_goal_card_shows_a_proof_in_bold_once_all_its_steps_passed() -> None:
    goal = R4_AGILITY.goal
    assert goal is not None
    card = goal_card(R4_AGILITY)
    assert card.startswith(f"**{goal.claim}**")
    assert f"{goal.before} → **{goal.after}**" in card
    assert "1. ECDSA to ML-DSA under the same name (steps 2, 4)" in card
    assert "**" not in card.split("\n", 3)[3]  # no proof is shown yet

    results = {i: _result(R4_AGILITY, i, StepState.PASSED) for i in (2, 3, 4)}
    card = goal_card(R4_AGILITY, results)
    assert "1. **ECDSA to ML-DSA under the same name** (steps 2, 4)" in card
    # Step 5 has not run, so the second proof is not shown yet.
    assert "2. The old signature still verifies (steps 3, 5)" in card


def test_goal_card_joins_consecutive_steps() -> None:
    r1 = RUNBOOKS[0]
    assert "(steps 2–8)" in goal_card(r1)
    assert "(step 2)" in goal_card(R3_POLICY)
