from __future__ import annotations

from citius_ui.showcases.model import StepState
from citius_ui.showcases.replay import StepResult
from citius_ui.showcases.runbooks import R4_AGILITY
from citius_ui.workbench.shared_runs import SharedRuns


def _result(index: int, state: StepState = StepState.PASSED) -> StepResult:
    return StepResult(index, R4_AGILITY.steps[index - 1], "OK", state)


def test_a_recorded_step_is_there_for_every_browser_with_who_ran_it() -> None:
    shared = SharedRuns()
    assert shared.version("r4-agility") == 0 and shared.results("r4-agility") == {}
    version = shared.record("r4-agility", _result(3), "producer", {"r4-ecdsa": "{}"})
    assert version > 0 and shared.version("r4-agility") == version
    assert shared.results("r4-agility")[3].index == 3
    assert shared.ran_by("r4-agility", 3) == "producer" and shared.ran_by("r4-agility", 4) is None
    assert shared.last("r4-agility") is not None and shared.last("r4-agility").index == 3  # type: ignore[union-attr]
    assert shared.bundles() == {"r4-ecdsa": "{}"}


def test_versions_never_repeat_and_reset_clears_only_that_runbooks_bundles() -> None:
    shared = SharedRuns()
    first = shared.record("use", _result(1), "producer", {"invoice-v1": "a"})
    shared.record("transform", _result(2), "producer", {"invoice-v2": "b"})
    reset = shared.reset("use")
    assert reset > first and shared.results("use") == {} and shared.last("use") is None
    # Transform's bundle stays; Use's is gone.
    assert shared.bundles() == {"invoice-v2": "b"}
    again = shared.record("use", _result(1), "producer", {})
    assert again not in (first, reset)


def test_bundles_are_a_copy() -> None:
    shared = SharedRuns()
    shared.record("use", _result(1), "producer", {"invoice-v1": "a"})
    shared.bundles()["invoice-v1"] = "changed"
    assert shared.bundles() == {"invoice-v1": "a"}
