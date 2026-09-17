"""Declarative multi-browser runbook model.

A runbook is documentation over the registered RPC actions. Each step names the
persona/browser that must be signed in, the service and RPC to run in the
Workbench, an example request, the expected result category, and any safe bundle
to copy to another browser. Runbooks never switch identity or execute RPCs
themselves; the Workbench remains the single execution surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ExpectedOutcome(str, Enum):
    """The result category a presenter should expect from a step."""

    SUCCESS = "success"
    METHOD_DENIED = "method_denied"
    RESOURCE_DENIED = "resource_denied"
    POLICY_REJECTED = "policy_rejected"


@dataclass(frozen=True, slots=True)
class RunbookStep:
    """One documented step, pointing at a Workbench service and RPC."""

    persona: str
    title: str
    service: str
    method: str
    expected: ExpectedOutcome
    explanation: str
    copy_bundle: bool = False


@dataclass(frozen=True, slots=True)
class Runbook:
    """A named multi-browser demonstration composed of documented steps."""

    key: str
    title: str
    summary: str
    steps: tuple[RunbookStep, ...] = field(default_factory=tuple)

    def required_actions(self) -> set[tuple[str, str]]:
        """Return the (service, method) pairs the runbook references."""
        return {(step.service, step.method) for step in self.steps}
