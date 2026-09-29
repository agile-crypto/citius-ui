"""Declarative multi-browser runbook model.

A runbook is documentation over the registered RPC actions. Each step names the
persona/browser that must be signed in, the service and RPC to run in the
Workbench, an example request, the expected result category, and any safe bundle
to copy to another browser. Runbooks never switch identity or execute RPCs
themselves; the Workbench remains the single execution surface.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType


class ExpectedOutcome(str, Enum):
    """The result category a presenter should expect from a step."""

    SUCCESS = "success"
    METHOD_DENIED = "method_denied"
    RESOURCE_DENIED = "resource_denied"
    POLICY_REJECTED = "policy_rejected"
    NOT_FOUND = "not_found"
    FAILED_PRECONDITION = "failed_precondition"
    INVALID_ARGUMENT = "invalid_argument"
    # The call succeeds but reports the signature invalid (valid: false).
    SIGNATURE_INVALID = "signature_invalid"


# The status codes each expected outcome accepts. A policy refusal reaches the
# caller as PERMISSION_DENIED; the server carries only the code (decision A1),
# so the step's hint, not the response, says why.
ACCEPTED_STATUS: Mapping[ExpectedOutcome, frozenset[str]] = MappingProxyType(
    {
        ExpectedOutcome.SUCCESS: frozenset({"OK"}),
        ExpectedOutcome.METHOD_DENIED: frozenset({"PERMISSION_DENIED"}),
        ExpectedOutcome.RESOURCE_DENIED: frozenset({"PERMISSION_DENIED"}),
        ExpectedOutcome.POLICY_REJECTED: frozenset({"PERMISSION_DENIED"}),
        ExpectedOutcome.NOT_FOUND: frozenset({"NOT_FOUND"}),
        ExpectedOutcome.FAILED_PRECONDITION: frozenset({"FAILED_PRECONDITION"}),
        ExpectedOutcome.INVALID_ARGUMENT: frozenset({"INVALID_ARGUMENT"}),
        ExpectedOutcome.SIGNATURE_INVALID: frozenset({"OK"}),
    }
)


class StepState(str, Enum):
    """How a step's last run went, judged against what the step expects."""

    NOT_RUN = "not_run"
    # The expected status code, and every look_for field matches.
    PASSED = "passed"
    # The expected status code, but a look_for field has another value.
    DIFFERS = "differs"
    # Another status code than the step expects.
    FAILED = "failed"
    # Not run on purpose (the replay without the demo identities).
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class RunbookStep:
    """One documented step, pointing at a Workbench service and RPC.

    ``request`` holds the form values that prefill the Workbench for this
    step (keys are the form's field keys). ``bundle`` names a producer's
    response bundle: a step that copies one saves it under this name, and a
    consumer step (``request`` without a ``bundle`` value) pastes the one of
    that name. ``hint`` explains an expected refusal, because the server
    returns only the status code.
    """

    persona: str
    title: str
    service: str
    method: str
    expected: ExpectedOutcome
    explanation: str
    copy_bundle: bool = False
    request: Mapping[str, object] | None = None
    bundle: str = ""
    hint: str = ""
    # Response fields to point at, as dotted paths into the response JSON,
    # with the value the step should show (e.g. key_metadata.template_id).
    look_for: Mapping[str, object] | None = None


@dataclass(frozen=True, slots=True)
class Proof:
    """One thing a runbook proves, and the steps (numbered from 1) that prove it."""

    text: str
    steps: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Goal:
    """What a runbook shows, short enough to read at a glance.

    ``claim`` is the point in a few words; ``before`` and ``after`` contrast
    the usual way with what Citius changes; each proof is shown once all its
    steps have gone as expected.
    """

    claim: str
    before: str
    after: str
    proofs: tuple[Proof, ...]


@dataclass(frozen=True, slots=True)
class Runbook:
    """A named multi-browser demonstration composed of documented steps."""

    key: str
    title: str
    summary: str
    steps: tuple[RunbookStep, ...] = field(default_factory=tuple)
    goal: Goal | None = None

    def required_actions(self) -> set[tuple[str, str]]:
        """Return the (service, method) pairs the runbook references."""
        return {(step.service, step.method) for step in self.steps}
