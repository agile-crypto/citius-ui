"""The first multi-browser runbooks over the registered RPC actions."""

from __future__ import annotations

from collections.abc import Callable

from citius_ui.actions.model import Availability
from citius_ui.showcases.model import ExpectedOutcome, Runbook, RunbookStep

AvailabilityResolver = Callable[[str, str], Availability]

POLICY_ENFORCEMENT = Runbook(
    key="policy-enforcement",
    title="Policy enforcement",
    summary=("Show that a restrictive crypto policy governs which operations a key allows."),
    steps=(
        RunbookStep(
            persona="CISO",
            title="Create a restrictive signing policy",
            service="CryptoPolicyService",
            method="CreateCryptoPolicy",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Define demo-signing-policy permitting key lifecycle plus signing operations only.",
        ),
        RunbookStep(
            persona="Producer",
            title="Create a governed key under the policy",
            service="KeyManagementService",
            method="CreateKey",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Create demo-signing-key bound to demo-signing-policy.",
        ),
        RunbookStep(
            persona="Producer",
            title="Perform an allowed operation",
            service="CryptoService",
            method="Sign",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Signing is permitted by the policy.",
            copy_bundle=True,
        ),
        RunbookStep(
            persona="Producer",
            title="Attempt a forbidden operation",
            service="CryptoService",
            method="Encrypt",
            expected=ExpectedOutcome.POLICY_REJECTED,
            explanation="Encryption is outside the policy and is rejected server-side.",
        ),
    ),
)

ACCESS_CONTROL = Runbook(
    key="access-control",
    title="Identity and access control",
    summary=(
        "Show separation of duties across CISO, producer, and consumer browsers, "
        "including method-level and resource-level denials."
    ),
    steps=(
        RunbookStep(
            persona="CISO",
            title="Create the signing policy",
            service="CryptoPolicyService",
            method="CreateCryptoPolicy",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Sign in as CISO in browser one and create demo-signing-policy.",
        ),
        RunbookStep(
            persona="Producer",
            title="Create a key and sign a message",
            service="CryptoService",
            method="Sign",
            expected=ExpectedOutcome.SUCCESS,
            explanation="In browser two, create demo-signing-key and sign a message.",
            copy_bundle=True,
        ),
        RunbookStep(
            persona="Producer",
            title="Attempt Verify and observe the method denial",
            service="CryptoService",
            method="Verify",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="The producer lacks citius:crypto:verify.",
        ),
        RunbookStep(
            persona="Consumer",
            title="Verify the copied signature bundle",
            service="CryptoService",
            method="Verify",
            expected=ExpectedOutcome.SUCCESS,
            explanation="In browser three, paste the producer's bundle and verify it.",
        ),
        RunbookStep(
            persona="Consumer",
            title="Attempt Sign and observe the method denial",
            service="CryptoService",
            method="Sign",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="The consumer lacks citius:crypto:sign.",
        ),
        RunbookStep(
            persona="Producer",
            title="Attempt an allowed method on a denied resource",
            service="CryptoService",
            method="Sign",
            expected=ExpectedOutcome.RESOURCE_DENIED,
            explanation="Signing demo-restricted-key is denied by the deny pattern.",
        ),
    ),
)

REQUIREMENTS_DRIVEN_KEY = Runbook(
    key="requirements-driven-key",
    title="Requirements-driven key creation",
    summary=(
        "Create a key from cryptographic intent and requirements, then read back its resolved template and provider."
    ),
    steps=(
        RunbookStep(
            persona="Producer",
            title="Create a key with algorithm and implementation requirements",
            service="KeyManagementService",
            method="CreateKey",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Request a template and provider requirements in the CreateKey request.",
        ),
        RunbookStep(
            persona="Producer",
            title="Read back the resolved key metadata",
            service="KeyManagementService",
            method="ReadKey",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Inspect the selected template, version, and provider metadata.",
        ),
    ),
)

CRYPTOGRAPHIC_AGILITY = Runbook(
    key="cryptographic-agility",
    title="Cryptographic agility",
    summary=(
        "Transform a key to a new template and confirm a pre-transform signature "
        "still verifies through its recorded key version."
    ),
    steps=(
        RunbookStep(
            persona="Producer",
            title="Sign a message under the current key version",
            service="CryptoService",
            method="Sign",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Retain the signature bundle including its key_version.",
            copy_bundle=True,
        ),
        RunbookStep(
            persona="CISO",
            title="Transform the key to a new template",
            service="KeyManagementService",
            method="TransformKey",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Move demo-signing-key to a post-quantum template.",
        ),
        RunbookStep(
            persona="Consumer",
            title="Verify the pre-transform signature by its recorded key version",
            service="CryptoService",
            method="Verify",
            expected=ExpectedOutcome.SUCCESS,
            explanation="Replay the retained metadata so the original version is used.",
        ),
    ),
)

RUNBOOKS: tuple[Runbook, ...] = (
    POLICY_ENFORCEMENT,
    ACCESS_CONTROL,
    REQUIREMENTS_DRIVEN_KEY,
    CRYPTOGRAPHIC_AGILITY,
)


def is_runnable(runbook: Runbook, resolver: AvailabilityResolver) -> bool:
    """Report whether every action a runbook references is available."""
    return all(resolver(service, method) is Availability.AVAILABLE for service, method in runbook.required_actions())


_OUTCOME_LABEL = {
    ExpectedOutcome.SUCCESS: "expect success",
    ExpectedOutcome.METHOD_DENIED: "expect PERMISSION_DENIED (method)",
    ExpectedOutcome.RESOURCE_DENIED: "expect PERMISSION_DENIED (resource)",
    ExpectedOutcome.POLICY_REJECTED: "expect policy rejection",
}


def render_markdown(runbook: Runbook, resolver: AvailabilityResolver) -> str:
    """Render a runbook as read-only guidance over the Workbench actions."""
    status = "runnable now" if is_runnable(runbook, resolver) else "pending server RPCs"
    lines = [f"### {runbook.title} — _{status}_", "", runbook.summary, ""]
    for index, step in enumerate(runbook.steps, start=1):
        bundle = " · copy the response bundle to the next browser" if step.copy_bundle else ""
        lines.append(
            f"{index}. **{step.persona}** → `{step.service}.{step.method}` "
            f"({_OUTCOME_LABEL[step.expected]}){bundle}  \n   {step.explanation}"
        )
    lines.append("")
    lines.append(
        "> Each step runs in the Workbench under the named identity. Switching "
        "identity requires logging out; use a separate browser per persona. Only "
        "safe bundles (key name, value, metadata) cross browsers — never tokens."
    )
    return "\n".join(lines)
