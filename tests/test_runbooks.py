from __future__ import annotations

from collections.abc import Callable

from citius_ui.actions.model import Availability
from citius_ui.showcases.model import ExpectedOutcome
from citius_ui.showcases.runbooks import (
    ACCESS_CONTROL,
    CRYPTOGRAPHIC_AGILITY,
    POLICY_ENFORCEMENT,
    RUNBOOKS,
    is_runnable,
    render_markdown,
)
from citius_ui.workbench.actions import registry_overview


def _resolver_from_overview() -> Callable[[str, str], Availability]:
    overview = registry_overview()
    lookup = {(s, m): a for s, methods in overview.items() for m, a in methods}

    def resolve(service: str, method: str) -> Availability:
        return lookup.get((service, method), Availability.UNKNOWN)

    return resolve


def test_all_runbooks_reference_registered_actions() -> None:
    resolve = _resolver_from_overview()
    for runbook in RUNBOOKS:
        for service, method in runbook.required_actions():
            assert resolve(service, method) is not Availability.UNKNOWN


def test_policy_and_access_control_are_runnable() -> None:
    resolve = _resolver_from_overview()
    assert is_runnable(POLICY_ENFORCEMENT, resolve)
    assert is_runnable(ACCESS_CONTROL, resolve)
    assert is_runnable(CRYPTOGRAPHIC_AGILITY, resolve)


def test_runbook_marked_pending_when_action_unavailable() -> None:
    def resolve(service: str, method: str) -> Availability:
        return Availability.UNIMPLEMENTED

    assert not is_runnable(POLICY_ENFORCEMENT, resolve)
    assert "pending server RPCs" in render_markdown(POLICY_ENFORCEMENT, resolve)


def test_render_markdown_lists_personas_and_outcomes() -> None:
    resolve = _resolver_from_overview()
    text = render_markdown(ACCESS_CONTROL, resolve)
    assert "runnable now" in text
    assert "PERMISSION_DENIED (method)" in text
    assert "PERMISSION_DENIED (resource)" in text
    assert "never tokens" in text


def test_access_control_covers_method_and_resource_denials() -> None:
    outcomes = {step.expected for step in ACCESS_CONTROL.steps}
    assert ExpectedOutcome.METHOD_DENIED in outcomes
    assert ExpectedOutcome.RESOURCE_DENIED in outcomes
    assert ExpectedOutcome.SUCCESS in outcomes
