"""Demo runbooks: the six-part showcase.

The showcase tells one story in six short runbooks (Choose, Use, Govern,
Transform, Move, Know), run in that order on a fresh server: one key,
``demo-signing-key``, is created, used, transformed and moved, and every
claim on a runbook's goal card names the response values that show it.

Every step names the persona (browser) to use, prefills the Workbench form
for its RPC, and says what to look for in the response. Steps that are
expected to be refused carry a hint saying why, because the server returns
only the status code (decision A1).

Key and policy names start with ``demo-``, the prefix the demo identities
may use. Run on a fresh server, or rename the keys: CreateKey refuses a
name that exists.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from citius_ui.actions.model import Availability
from citius_ui.showcases.model import Evidence, ExpectedOutcome, Goal, Proof, Runbook, RunbookStep

AvailabilityResolver = Callable[[str, str], Availability]

_POLICY = "CryptoPolicyService"
_KEYS = "KeyManagementService"
_CRYPTO = "CryptoService"
_DISCOVERY = "AlgorithmDiscoveryService"

OK = ExpectedOutcome.SUCCESS


def _policy(templates: list[str], operations: list[str], **extra: object) -> str:
    """A policy document in the server's rules_json schema; list order is preference order."""
    return json.dumps(
        {
            "version": "1",
            "allowed_operations": {"key_operations": operations},
            "allowed_templates": templates,
            **extra,
        },
        indent=2,
    )


def _create_policy(name: str, document: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=f"Create policy {name}",
        service=_POLICY,
        method="CreateCryptoPolicy",
        expected=OK,
        explanation=explanation,
        request={"name": name, "policy_document": document, "format": "json"},
    )


def _update_policy(name: str, document: str, explanation: str, title: str) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=title,
        service=_POLICY,
        method="UpdateCryptoPolicy",
        expected=OK,
        explanation=explanation,
        request={"name": name, "policy_document": document, "format": "json"},
    )


def _create_key(
    title: str,
    request: Mapping[str, object],
    explanation: str,
    *,
    template: str = "",
    provider: str = "",
) -> RunbookStep:
    look_for: dict[str, object] = {}
    if template:
        look_for["key_metadata.template_id"] = template
    if provider:
        look_for["key_metadata.provider"] = provider
    return RunbookStep(
        persona="Producer",
        title=title,
        service=_KEYS,
        method="CreateKey",
        expected=OK,
        explanation=explanation,
        request=request,
        look_for=look_for or None,
    )


def _timeline(key: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=f"Show the version timeline of {key}",
        service=_KEYS,
        method="ReadKey",
        expected=OK,
        explanation=explanation,
        request={"name": key, "all_versions": True},
    )


# ── The showcase: one key's story in six parts ─────────────────────────────────
#
# demo-signing-key is created in Choose (v1, ECDSA P-256 on software) and signs
# an invoice in Use. Transform makes v2 (ML-DSA-65), Move rekeys it into the
# FIPS module as v3, and Know shows its whole life. Govern stands alone, with
# its own policy, so changing the rules there leaves the story key alone.

_SIGNING_POLICY = "demo-signing-policy"
_SIGNING_KEY = "demo-signing-key"
# Preference order: the classical default first, then the quantum-safe choices.
_SIGNING_TEMPLATES = ["ecdsa-p256-sha256-der", "ml-dsa-65", "ml-dsa-87"]
_SIGNING_OPS = ["create_key", "read_key", "sign", "verify"]
_INVOICE = "Invoice 2026-0042: EUR 1,250.00"


def _sign_invoice(title: str, bundle: str, explanation: str, **look_for: object) -> RunbookStep:
    return RunbookStep(
        persona="Producer",
        title=title,
        service=_CRYPTO,
        method="Sign",
        expected=OK,
        explanation=explanation,
        copy_bundle=True,
        request={"key_name": _SIGNING_KEY, "message": _INVOICE},
        bundle=bundle,
        look_for=look_for or None,
    )


def _verify_invoice(title: str, bundle: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="Consumer",
        title=title,
        service=_CRYPTO,
        method="Verify",
        expected=OK,
        explanation=explanation,
        request={"key_name": _SIGNING_KEY},
        bundle=bundle,
        look_for={"valid": True},
    )


def _choose_key(
    name: str, title: str, explanation: str, *, template: str, provider: str = "", **fields: object
) -> RunbookStep:
    return _create_key(
        title,
        {"name": name, "policy": _SIGNING_POLICY, **fields},
        explanation,
        template=template,
        provider=provider,
    )


SHOWCASE_CHOOSE = Runbook(
    key="choose",
    title="1 · Choose",
    summary=(
        "The Producer asks for keys by what they must do. No request names an algorithm or a "
        "module unless it wants to: the platform takes the first template in the policy's list "
        "that fits, and the first provider instance that meets the requirements."
    ),
    steps=(
        _create_policy(
            _SIGNING_POLICY,
            _policy(_SIGNING_TEMPLATES, _SIGNING_OPS),
            "The allowed templates in preference order: ECDSA P-256, then ML-DSA-65, then ML-DSA-87.",
        ),
        _choose_key(
            _SIGNING_KEY,
            "A signature key, nothing else asked",
            "The first allowed template that offers a standard signature.",
            template="ecdsa-p256-sha256-der",
            provider="software",
            scope="SIGNATURE_STANDARD",
        ),
        _choose_key(
            "demo-pqc-signing-key",
            "Add: quantum-safe",
            "ECDSA is not quantum-safe, so the next template in the list wins.",
            template="ml-dsa-65",
            scope="SIGNATURE_STANDARD",
            quantum_safe="true",
        ),
        _choose_key(
            "demo-exact-key",
            "Or name the template exactly",
            "Naming a template is still possible; the policy must allow it. The scope is still "
            "given: a template can serve more than one.",
            template="ml-dsa-65",
            scope="SIGNATURE_STANDARD",
            template_id="ml-dsa-65",
        ),
        _choose_key(
            "demo-fips-signing-key",
            "Add: a FIPS 140 certified module",
            "A provider requirement: only the openssl-fips instance is FIPS 140 certified.",
            template="ml-dsa-65",
            provider="openssl-fips",
            scope="SIGNATURE_STANDARD",
            quantum_safe="true",
            require_fips_140=True,
        ),
    ),
    goal=Goal(
        claim="Ask for what the key must do. The platform picks the algorithm and where it lives.",
        before="Code names the algorithm, curve and library",
        after="code states what the key must do",
        proofs=(
            Proof("The request names no algorithm", (2,), (Evidence(2, "request", "sent"),)),
            Proof(
                "The first template in the policy's list that fits is chosen",
                (1, 2),
                (
                    Evidence(1, "request.policy_document.allowed_templates", "policy lists"),
                    Evidence(2, "key_metadata.template_id", "→"),
                ),
            ),
            Proof(
                "ECDSA P-256 on software, version 1",
                (2,),
                (Evidence(2, "key_metadata.provider", "on"), Evidence(2, "key_metadata.version", "version")),
            ),
            Proof(
                "A filter narrows the choice",
                (3,),
                (Evidence(3, "request.quantum_safe", "quantum_safe"), Evidence(3, "key_metadata.template_id", "→")),
            ),
            Proof(
                "Or name the template exactly",
                (4,),
                (Evidence(4, "request.template_id", "template_id"), Evidence(4, "key_metadata.template_id", "→")),
            ),
            Proof(
                "A requirement chooses where the key lives",
                (5,),
                (
                    Evidence(5, "request.require_fips_140", "FIPS 140 required"),
                    Evidence(5, "key_metadata.provider", "→"),
                ),
            ),
        ),
    ),
)

SHOWCASE_USE = Runbook(
    key="use",
    title="2 · Use",
    summary=(
        "The Producer signs an invoice and the Consumer verifies it, by key name only. Each "
        "identity can do its own job and nothing else: the server checks every call against "
        "what the identity is granted and which keys it may touch. Needs the server with "
        "authentication for steps 3–5."
    ),
    after=("choose",),
    steps=(
        _sign_invoice(
            "Sign an invoice", "invoice-v1", "Keep the bundle: the Consumer verifies it.", **{"metadata.key_version": 1}
        ),
        _verify_invoice("Verify the invoice", "invoice-v1", "Another application, another identity."),
        RunbookStep(
            persona="Consumer",
            title="Try to sign",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="The Consumer may verify, not sign.",
            request={"key_name": _SIGNING_KEY, "message": _INVOICE},
            hint="The consumer lacks citius:crypto:sign.",
        ),
        RunbookStep(
            persona="Producer",
            title="Try to change the policy",
            service=_POLICY,
            method="UpdateCryptoPolicy",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="The Producer tries to allow ECDSA P-384 as well.",
            request={
                "name": _SIGNING_POLICY,
                "policy_document": _policy([*_SIGNING_TEMPLATES, "ecdsa-p384-sha384-der"], _SIGNING_OPS),
                "format": "json",
            },
            hint="The producer lacks citius:policy:write: only the CISO sets the rules.",
        ),
        RunbookStep(
            persona="Producer",
            title="Sign with a key outside your pattern",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.RESOURCE_DENIED,
            explanation="The Producer may sign, but not with this key.",
            request={"key_name": "demo-restricted-key", "message": _INVOICE},
            hint="demo-restricted-* is on the producer's deny list.",
        ),
    ),
    goal=Goal(
        claim="Apps sign and verify by key name, and only as far as they are allowed.",
        before="Each app holds keys and decides for itself",
        after="every call is checked against the caller's grants",
        proofs=(
            Proof("Signing names only the key and the message", (1,), (Evidence(1, "request", "sent"),)),
            Proof(
                "The signature records the key version it was made with",
                (1,),
                (Evidence(1, "metadata.key_version", "key_version"),),
            ),
            Proof("Another application verifies it", (1, 2), (Evidence(2, "valid", "valid"),)),
            Proof("The Consumer cannot sign", (3,), (Evidence(3, "status"),)),
            Proof("The Producer cannot change a policy", (4,), (Evidence(4, "status"),)),
            Proof("A user touches only the keys they are granted", (5,), (Evidence(5, "status"),)),
        ),
    ),
)

_GOVERNED_POLICY = "demo-governed-policy"
_GOVERNED_TEMPLATES = ["ecdsa-p256-sha256-der", "ml-dsa-65"]


def _governed_key(name: str, title: str, explanation: str, template: str) -> RunbookStep:
    return _create_key(
        title,
        {"name": name, "policy": _GOVERNED_POLICY, "scope": "SIGNATURE_STANDARD"},
        explanation,
        template=template,
    )


SHOWCASE_GOVERN = Runbook(
    key="govern",
    title="3 · Govern",
    summary=(
        "The CISO's policy decides what a request resolves to and what is allowed, and a change "
        "applies on the next call. The Producer's requests stay the same; only the key name "
        "differs, because names are unique."
    ),
    steps=(
        _create_policy(
            _GOVERNED_POLICY,
            _policy(_GOVERNED_TEMPLATES, _SIGNING_OPS),
            "ECDSA P-256 first, then ML-DSA-65.",
        ),
        _governed_key(
            "demo-governed-key-1", "A signature key", "The policy's first signature template.", "ecdsa-p256-sha256-der"
        ),
        _update_policy(
            _GOVERNED_POLICY,
            _policy(list(reversed(_GOVERNED_TEMPLATES)), _SIGNING_OPS),
            "The same templates, ML-DSA-65 first.",
            "Put ML-DSA-65 first",
        ),
        _governed_key(
            "demo-governed-key-2", "The same request again", "Now ML-DSA-65 is the first that fits.", "ml-dsa-65"
        ),
        RunbookStep(
            persona="Producer",
            title="Sign",
            service=_CRYPTO,
            method="Sign",
            expected=OK,
            explanation="Allowed under the policy.",
            request={"key_name": "demo-governed-key-2", "message": _INVOICE},
        ),
        _update_policy(
            _GOVERNED_POLICY,
            _policy(list(reversed(_GOVERNED_TEMPLATES)), ["create_key", "read_key", "verify"]),
            "Verification stays allowed; signing does not.",
            "Stop signing under the policy",
        ),
        RunbookStep(
            persona="Producer",
            title="The same Sign again",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.POLICY_REJECTED,
            explanation="The identical request, one policy change later.",
            request={"key_name": "demo-governed-key-2", "message": _INVOICE},
            hint="The policy no longer allows sign; the check happens on every call.",
        ),
    ),
    goal=Goal(
        claim="The CISO's policy decides, and a change applies on the next call.",
        before="Rules live in each app's code",
        after="one policy, enforced on every call",
        proofs=(
            Proof(
                "The same request gets a new answer after the CISO reorders the policy",
                (2, 3, 4),
                (Evidence(2, "key_metadata.template_id", "before"), Evidence(4, "key_metadata.template_id", "after")),
            ),
            Proof(
                "A policy change applies on the next call",
                (5, 6, 7),
                (Evidence(5, "status", "before"), Evidence(7, "status", "after")),
            ),
        ),
    ),
)

SHOWCASE_TRANSFORM = Runbook(
    key="transform",
    title="4 · Transform",
    summary=(
        "The CISO moves demo-signing-key to a quantum-safe algorithm by intent. The Producer's "
        "sign call does not change, and signatures made before the change still verify."
    ),
    after=("use",),
    steps=(
        RunbookStep(
            persona="CISO",
            title="Transform by intent: quantum-safe",
            service=_KEYS,
            method="TransformKey",
            expected=OK,
            explanation="The first quantum-safe template in the key's policy becomes version 2.",
            request={"name": _SIGNING_KEY, "scope": "SIGNATURE_STANDARD", "quantum_safe": "true"},
            look_for={"key_metadata.template_id": "ml-dsa-65", "key_metadata.version": 2},
        ),
        _sign_invoice(
            "Sign the invoice again, unchanged",
            "invoice-v2",
            "The same request as in Use.",
            **{"metadata.key_version": 2},
        ),
        _verify_invoice("Verify the version 1 signature", "invoice-v1", "Made with ECDSA, before the change."),
        _verify_invoice("Verify the version 2 signature", "invoice-v2", "Made with ML-DSA-65."),
    ),
    goal=Goal(
        claim="Change the algorithm. Old signatures still verify.",
        before="Every app's create, sign and verify code changes",
        after="the CISO changes the key; no app code changes",
        proofs=(
            Proof(
                "The CISO changes the algorithm by intent, as version 2",
                (1,),
                (
                    Evidence(1, "request.quantum_safe", "quantum_safe"),
                    Evidence(1, "key_metadata.template_id", "→"),
                    Evidence(1, "key_metadata.version", "version"),
                ),
            ),
            Proof(
                "The app's sign call is unchanged; it now signs with version 2",
                (2,),
                (Evidence(2, "request", "sent"), Evidence(2, "metadata.key_version", "key_version")),
            ),
            Proof(
                "The version 1 signature still verifies",
                (3,),
                (Evidence(3, "request.bundle.metadata.key_version", "key_version"), Evidence(3, "valid", "valid")),
            ),
            Proof(
                "The new signature verifies",
                (4,),
                (Evidence(4, "request.bundle.metadata.key_version", "key_version"), Evidence(4, "valid", "valid")),
            ),
        ),
    ),
)

SHOWCASE_MOVE = Runbook(
    key="move",
    title="5 · Move",
    summary=(
        "The CISO requires FIPS 140 custody in the key's policy, checks the move, and rekeys "
        "demo-signing-key into the FIPS module by naming only the provider type. Signatures "
        "from earlier versions still verify. Needs the server started with --fips-config."
    ),
    after=("transform",),
    steps=(
        _update_policy(
            _SIGNING_POLICY,
            _policy(_SIGNING_TEMPLATES, _SIGNING_OPS, provider_requirements={"fips_140_certified": True}),
            "From now on every new key version under this policy must be placed in a FIPS 140 module.",
            "Require FIPS 140 custody",
        ),
        RunbookStep(
            persona="CISO",
            title="Check the move first",
            service=_KEYS,
            method="ValidateKeyOperation",
            expected=OK,
            explanation="Nothing changes: each strategy is assessed, with why it would or would not work.",
            request={
                "name": _SIGNING_KEY,
                "target_instance_id": "openssl-fips",
                "preferred_strategy": "REKEY_AND_ARCHIVE",
            },
        ),
        RunbookStep(
            persona="CISO",
            title="Try to move to plain openssl",
            service=_KEYS,
            method="MigrateKey",
            expected=ExpectedOutcome.FAILED_PRECONDITION,
            explanation="The policy now decides where keys may go.",
            request={"name": _SIGNING_KEY, "strategy": "REKEY_AND_ARCHIVE", "target_instance_id": "openssl"},
            hint="The policy's provider_requirements need fips_140_certified; plain openssl is not.",
        ),
        RunbookStep(
            persona="CISO",
            title="Rekey, naming only the provider type",
            service=_KEYS,
            method="MigrateKey",
            expected=OK,
            explanation="Of the openssl instances, only openssl-fips meets the policy.",
            request={"name": _SIGNING_KEY, "strategy": "REKEY_AND_ARCHIVE", "target_provider_id": "openssl"},
            look_for={"migration.target.instance_id": "openssl-fips", "migration.new_version": 3},
        ),
        _verify_invoice("Verify the version 1 signature", "invoice-v1", "Against the archived version 1."),
        _verify_invoice("Verify the version 2 signature", "invoice-v2", "Against the archived version 2."),
    ),
    goal=Goal(
        claim="Move keys into certified custody. Old data still works.",
        before="A migration project per application",
        after="the CISO moves the key; apps notice nothing",
        proofs=(
            Proof(
                "The policy sets provider rules too: plain openssl is refused",
                (1, 3),
                (
                    Evidence(
                        1, "request.policy_document.provider_requirements.fips_140_certified", "fips_140_certified"
                    ),
                    Evidence(3, "status", "→"),
                ),
            ),
            Proof("Check the move first", (2,), (Evidence(2, "recommended_strategy", "recommended"),)),
            Proof(
                "Name a provider type; the platform picks the certified instance",
                (4,),
                (
                    Evidence(4, "request.target_provider_id", "type"),
                    Evidence(4, "migration.target.instance_id", "→"),
                    Evidence(4, "migration.target.implementation.fips_140", "certified"),
                ),
            ),
            Proof(
                "Rekeyed as version 3; the old versions stay archived",
                (4,),
                (
                    Evidence(4, "migration.new_version", "version"),
                    Evidence(4, "migration.archived.provider", "archived on"),
                ),
            ),
            Proof(
                "Earlier versions still verify",
                (5, 6),
                (Evidence(5, "valid", "v1 valid"), Evidence(6, "valid", "v2 valid")),
            ),
        ),
    ),
)

SHOWCASE_KNOW = Runbook(
    key="know",
    title="6 · Know",
    summary=(
        "What an intent resolves to, and what every key is. A template is the full description "
        "of an algorithm; the key's timeline shows each version's template and module. For the "
        "whole estate, open the Crypto inventory tab and download the CBOM."
    ),
    after=("move",),
    steps=(
        RunbookStep(
            persona="CISO",
            title="What ML-DSA-65 is",
            service=_DISCOVERY,
            method="GetTemplate",
            expected=OK,
            explanation="Operations, security properties, standard and OID: what the catalogue knows.",
            request={"template_id": "ml-dsa-65"},
            look_for={"summary.standards": ["FIPS 204"]},
        ),
        _timeline(_SIGNING_KEY, "v1 ECDSA P-256 on software, v2 ML-DSA-65 on software, v3 ML-DSA-65 in openssl-fips."),
    ),
    goal=Goal(
        claim="See exactly what every key is, and export it.",
        before="Spreadsheets and code searches",
        after="the platform knows every key and algorithm",
        proofs=(
            Proof(
                "A template is the full description of an algorithm",
                (1,),
                (
                    Evidence(1, "summary.standards", "standard"),
                    Evidence(1, "summary.nist_quantum_security_level", "NIST level"),
                    Evidence(1, "full_response.algorithm.oid", "OID"),
                ),
            ),
            Proof(
                "The key's whole life in one view",
                (2,),
                (
                    Evidence(2, "timeline.*.template_id", "templates", " → "),
                    Evidence(2, "timeline.*.provider", "modules", " → "),
                ),
            ),
        ),
    ),
)

SHOWCASE: tuple[Runbook, ...] = (
    SHOWCASE_CHOOSE,
    SHOWCASE_USE,
    SHOWCASE_GOVERN,
    SHOWCASE_TRANSFORM,
    SHOWCASE_MOVE,
    SHOWCASE_KNOW,
)

RUNBOOKS: tuple[Runbook, ...] = SHOWCASE
RUNBOOKS_BY_KEY: Mapping[str, Runbook] = {runbook.key: runbook for runbook in RUNBOOKS}


def is_runnable(runbook: Runbook, resolver: AvailabilityResolver) -> bool:
    """Report whether every action a runbook references is available."""
    return all(resolver(service, method) is Availability.AVAILABLE for service, method in runbook.required_actions())


def look_up(response: Mapping[str, Any], path: str) -> object:
    """The value at a dotted path in a response, or None where it is absent.

    A JSON string on the way is read as JSON (a policy document, a pasted
    bundle), and ``*`` takes the rest of the path from every item of a list.
    """
    return _look_up(response, path.split("."))


def _look_up(value: object, parts: list[str]) -> object:
    for position, part in enumerate(parts):
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None
        if part == "*":
            if not isinstance(value, list):
                return None
            return [_look_up(item, parts[position + 1 :]) for item in value]
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


_OUTCOME_LABEL = {
    ExpectedOutcome.SUCCESS: "expect success",
    ExpectedOutcome.METHOD_DENIED: "expect PERMISSION_DENIED (method)",
    ExpectedOutcome.RESOURCE_DENIED: "expect PERMISSION_DENIED (resource)",
    ExpectedOutcome.POLICY_REJECTED: "expect PERMISSION_DENIED (policy)",
    ExpectedOutcome.NOT_FOUND: "expect NOT_FOUND",
    ExpectedOutcome.FAILED_PRECONDITION: "expect FAILED_PRECONDITION",
    ExpectedOutcome.INVALID_ARGUMENT: "expect INVALID_ARGUMENT",
    ExpectedOutcome.SIGNATURE_INVALID: "expect valid: false",
}


def render_markdown(runbook: Runbook, resolver: AvailabilityResolver) -> str:
    """Render a runbook as read-only guidance over the Workbench actions."""
    status = "runnable now" if is_runnable(runbook, resolver) else "pending server RPCs"
    lines = [f"### {runbook.title} — _{status}_", "", runbook.summary, ""]
    if runbook.after:
        titles = [RUNBOOKS_BY_KEY[key].title for key in runbook.after if key in RUNBOOKS_BY_KEY]
        lines += [f"Continues from {', '.join(titles)}: run that first, on the same server.", ""]
    for index, step in enumerate(runbook.steps, start=1):
        lines.append(
            f"{index}. **{step.persona}** → `{step.service}.{step.method}` · {step.title} "
            f"({_OUTCOME_LABEL[step.expected]})  \n   {step.explanation}"
        )
        if step.copy_bundle and step.bundle:
            lines.append(f"   Copy the response bundle as **{step.bundle}**.")
        elif step.bundle:
            lines.append(f"   Paste the **{step.bundle}** bundle.")
        if step.hint:
            lines.append(f"   _Why:_ {step.hint}")
        if step.look_for:
            shown = ", ".join(f"`{path}` = `{json.dumps(value)}`" for path, value in step.look_for.items())
            lines.append(f"   Look for {shown}.")
    lines.append("")
    lines.append(
        "> Each step runs in the Workbench under the named identity. Switching identity "
        "requires logging out; use a separate browser per persona. Only safe bundles "
        "(key name, value, metadata) cross browsers — never tokens."
    )
    return "\n".join(lines)
