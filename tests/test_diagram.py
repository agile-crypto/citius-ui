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
    R1_INTENT,
    R3_POLICY,
    R4_AGILITY,
    RUNBOOKS,
    SHOWCASE_CHOOSE,
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


def test_goal_card_ticks_a_proof_once_all_its_steps_passed() -> None:
    pending, proven, refused = (PROOF_MARK[s] for s in (StepState.NOT_RUN, StepState.PASSED, StepState.FAILED))
    goal = R4_AGILITY.goal
    assert goal is not None
    card = goal_card(R4_AGILITY)
    assert card.startswith(f"**{goal.claim}**")
    assert f"{goal.before} → **{goal.after}**" in card
    assert f"{pending}ECDSA to ML-DSA under the same name · steps 2, 4" in card
    assert proven not in card and f"**Proven: 0 of {len(goal.proofs)}**" in card

    results = {i: _result(R4_AGILITY, i, StepState.PASSED) for i in (2, 3, 4)}
    card = goal_card(R4_AGILITY, results)
    assert f"{proven}**ECDSA to ML-DSA under the same name** · steps 2, 4" in card
    # Step 5 has not run, so the second proof is not shown yet.
    assert f"{pending}The old signature still verifies · steps 3, 5" in card
    assert f"**Proven: 1 of {len(goal.proofs)}**" in card

    results[5] = _result(R4_AGILITY, 5, StepState.FAILED, status="NOT_FOUND")
    card = goal_card(R4_AGILITY, results)
    assert f"{refused}The old signature still verifies · steps 3, 5: not as expected" in card


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
    assert "· steps 2–8" in goal_card(R1_INTENT)
    assert "· step 2" in goal_card(R3_POLICY)
