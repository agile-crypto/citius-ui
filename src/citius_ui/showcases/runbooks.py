"""Demo runbooks: the six-part showcase, then the deep dives R1–R8.

The showcase tells one story in six short runbooks (Choose, Use, Govern,
Transform, Move, Know), run in that order on a fresh server: one key,
``demo-signing-key``, is created, used, transformed and moved, and every
claim on a runbook's goal card names the response values that show it. The
deep dives each tell one story from UI_DEMO_EVALUATION.md §3.

Every step names the persona (browser) to use, prefills the Workbench form
for its RPC, and says what to look for in the response. Steps that are
expected to be refused carry a hint saying why, because the server returns
only the status code (decision A1).

Key and policy names start with ``demo-``, the prefix the demo identities
may use. The deep dives each use their own names, so they do not interfere
with each other or with the showcase. Run on a fresh server, or rename the
keys: CreateKey refuses a name that exists.
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
_PROVIDERS = "ProviderService"
_DISCOVERY = "AlgorithmDiscoveryService"

_MESSAGE = "Hello from Citius"
_PLAINTEXT = "Quarterly figures: confidential"
# SHA-256 of _MESSAGE, base64: the input for DigestSign.
_MESSAGE_SHA256 = "dd37/hdyzzn7BLltwfCmNXDQt612QJj3aIVjbPLQQKA="

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


def _sign(key: str, bundle: str, explanation: str, **extra: object) -> RunbookStep:
    return RunbookStep(
        persona="Producer",
        title=f"Sign with {key}",
        service=_CRYPTO,
        method="Sign",
        expected=OK,
        explanation=explanation,
        copy_bundle=True,
        request={"key_name": key, "message": _MESSAGE, **extra},
        bundle=bundle,
    )


def _verify(key: str, bundle: str, explanation: str, **extra: object) -> RunbookStep:
    return RunbookStep(
        persona="Consumer",
        title=f"Verify the {bundle} bundle",
        service=_CRYPTO,
        method="Verify",
        expected=OK,
        explanation=explanation,
        request={"key_name": key, **extra},
        bundle=bundle,
        look_for={"valid": True},
    )


def _encrypt(key: str, bundle: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="Producer",
        title=f"Encrypt with {key}",
        service=_CRYPTO,
        method="Encrypt",
        expected=OK,
        explanation=explanation,
        copy_bundle=True,
        request={"key_name": key, "plaintext": _PLAINTEXT, "aad": "tenant=demo"},
        bundle=bundle,
    )


def _decrypt(key: str, bundle: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="Consumer",
        title=f"Decrypt the {bundle} bundle",
        service=_CRYPTO,
        method="Decrypt",
        expected=OK,
        explanation=explanation,
        request={"key_name": key, "aad": "tenant=demo"},
        bundle=bundle,
        look_for={"plaintext.utf8": _PLAINTEXT},
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


def _transform(key: str, template: str, explanation: str, **look_for: object) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=f"Transform {key} to {template}",
        service=_KEYS,
        method="TransformKey",
        expected=OK,
        explanation=explanation,
        request={"name": key, "template_id": template},
        look_for={"key_metadata.template_id": template, **look_for},
    )


def _migrate(key: str, strategy: str, target: str, explanation: str, **look_for: object) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=f"{strategy.replace('_', ' ').capitalize()}: move {key} to {target}",
        service=_KEYS,
        method="MigrateKey",
        expected=OK,
        explanation=explanation,
        request={"name": key, "strategy": strategy, "target_instance_id": target},
        look_for={"migration.target.instance_id": target, **look_for},
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


def _list_keys(policy: str, title: str, explanation: str) -> RunbookStep:
    return RunbookStep(
        persona="CISO",
        title=title,
        service=_KEYS,
        method="ListKeys",
        expected=OK,
        explanation=explanation,
        request={"policy": policy},
    )


# ── R1 — Intent, not algorithms ───────────────────────────────────────────────

_R1_POLICY = "demo-r1-policy"
_R1_TEMPLATES = [
    "ecdsa-p256-sha256-der",
    "ecdsa-p384-sha384-der",
    "ed25519",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "rsa-pkcs1v15-sha256-2048",
    "rsa-pss-sha256-mgf1-32-2048",
    "aes-256-gcm-128-96",
    "chacha20-poly1305",
]


def _r1_key(suffix: str, template: str, title: str, explanation: str, **fields: object) -> RunbookStep:
    return _create_key(
        title,
        {"name": f"demo-r1-{suffix}", "policy": _R1_POLICY, "scope": "SIGNATURE_STANDARD", **fields},
        explanation,
        template=template,
    )


R1_INTENT = Runbook(
    key="r1-intent",
    title="R1 · Intent, not algorithms",
    summary=(
        "The same CreateKey with different requirements. No request names an algorithm: "
        "the caller states requirements, and the platform picks the first template in the "
        "policy's list that meets them."
    ),
    steps=(
        _create_policy(
            _R1_POLICY,
            _policy(_R1_TEMPLATES, ["create_key", "read_key", "sign", "verify", "encrypt", "decrypt"]),
            "The allowed templates are listed in preference order: classical first, then post-quantum.",
        ),
        _r1_key(
            "default",
            "ecdsa-p256-sha256-der",
            "A standard signature key, nothing else asked",
            "The first allowed template that offers a standard signature.",
        ),
        _r1_key(
            "pq",
            "ml-dsa-44",
            "Add: quantum-safe",
            "The first quantum-safe signature template in the list.",
            quantum_safe="true",
        ),
        _r1_key(
            "pq-l3",
            "ml-dsa-65",
            "Add: quantum-safe at NIST level 3",
            "ML-DSA-44 is level 2, so the next one wins.",
            quantum_safe="true",
            nist_security_level="LEVEL_3",
        ),
        _r1_key(
            "256",
            "ml-dsa-87",
            "Instead: at least 256-bit strength",
            "Only ML-DSA-87 reaches 256 bits among the allowed signature templates.",
            security_strength_bits=256,
        ),
        _r1_key(
            "192",
            "ecdsa-p384-sha384-der",
            "Instead: at least 192-bit strength",
            "ECDSA P-384 comes before ML-DSA-65 in the policy's list.",
            security_strength_bits=192,
        ),
        _create_key(
            "Instead: deterministic signatures",
            {
                "name": "demo-r1-det",
                "policy": _R1_POLICY,
                "scope_spec": json.dumps({"signature": {"scope": "SIGNATURE_SCOPE_STANDARD", "deterministic": True}}),
            },
            "A property of the signature primitive, set through the scope specification (Advanced section).",
            template="ed25519",
        ),
        _create_key(
            "Instead: authenticated encryption",
            {"name": "demo-r1-aead", "policy": _R1_POLICY, "scope": "AEAD_STANDARD"},
            "A different scope, the same kind of request.",
            template="aes-256-gcm-128-96",
        ),
        _list_keys(
            _R1_POLICY,
            "List what was created",
            "Seven requests, seven algorithms, and none of them was named. Try the Crypto inventory tab too.",
        ),
    ),
    goal=Goal(
        claim="Ask for properties, get the right algorithm",
        before="Code names the algorithm",
        after="code states what it needs",
        proofs=(
            Proof("No request names an algorithm", (2, 3, 4, 5, 6, 7, 8)),
            Proof("Seven requests, seven algorithms", (2, 3, 4, 5, 6, 7, 8, 9)),
        ),
    ),
)

# ── R2 — Implementation requirements choose the provider ─────────────────────

_R2_POLICY = "demo-r2-policy"
_R2_TEMPLATE = "aes-256-gcm-128-96"


def _r2_key(suffix: str, provider: str, title: str, explanation: str, **fields: object) -> RunbookStep:
    return _create_key(
        title,
        {"name": f"demo-r2-{suffix}", "policy": _R2_POLICY, "template_id": _R2_TEMPLATE, **fields},
        explanation,
        provider=provider,
    )


R2_PROVIDERS = Runbook(
    key="r2-providers",
    title="R2 · Implementation requirements choose the provider",
    summary=(
        "The same template with different implementation requirements. Algorithm choice and "
        "implementation choice are separate axes. The FIPS step needs the server started with "
        "--fips-config (scripts/fips_setup.sh)."
    ),
    steps=(
        _create_policy(
            _R2_POLICY,
            _policy([_R2_TEMPLATE], ["create_key", "read_key", "encrypt", "decrypt"]),
            "One template: only the provider changes in this runbook.",
        ),
        RunbookStep(
            persona="Producer",
            title="Preview the ranking",
            service=_PROVIDERS,
            method="MatchProviders",
            expected=OK,
            explanation="The instances that can hold the key, in CreateKey's order, and why the rest lost.",
            request={"template_id": _R2_TEMPLATE},
        ),
        _r2_key("default", "software", "No requirement", "The first registered instance that implements the template."),
        _r2_key(
            "memsafe",
            "software",
            "Require a memory-safe implementation",
            "The Go provider meets it; OpenSSL (C) does not.",
            require_memory_safe=True,
        ),
        _r2_key(
            "hw",
            "openssl",
            "Prefer hardware acceleration",
            "A preference, not a requirement: it reorders the instances that qualify.",
            prefer_hardware_accelerated=True,
        ),
        _r2_key(
            "fips",
            "openssl-fips",
            "Require FIPS 140",
            "Only the FIPS instance qualifies. Without --fips-config this is NOT_FOUND.",
            require_fips_140=True,
        ),
        RunbookStep(
            persona="Producer",
            title="Pin a provider that contradicts a requirement",
            service=_KEYS,
            method="CreateKey",
            expected=ExpectedOutcome.FAILED_PRECONDITION,
            explanation="A pin is honoured only if it satisfies the requirements.",
            request={
                "name": "demo-r2-conflict",
                "policy": _R2_POLICY,
                "template_id": _R2_TEMPLATE,
                "provider_id": "openssl",
                "require_memory_safe": True,
            },
            hint="openssl is written in C, so it cannot meet require_memory_safe.",
        ),
    ),
    goal=Goal(
        claim="Where a key lives is a separate choice",
        before="The algorithm picks the library",
        after="requirements pick the provider",
        proofs=(
            Proof("One template, the provider follows the requirement", (3, 4, 5, 6)),
            Proof("A pin that breaks a requirement is refused", (7,)),
        ),
    ),
)

# ── R3 — Policy as guardrail ──────────────────────────────────────────────────

_R3_POLICY = "demo-r3-policy"
_R3_KEY = "demo-r3-key"

R3_POLICY = Runbook(
    key="r3-policy",
    title="R3 · Policy as guardrail",
    summary="The CISO's policy decides what a request can get and what a key may do, and a change applies at once.",
    steps=(
        _create_policy(
            _R3_POLICY,
            _policy(["ml-dsa-87"], ["create_key", "read_key", "sign", "verify"]),
            "Only ML-DSA-87 is allowed for signatures.",
        ),
        _create_key(
            "Ask for any quantum-safe signature key",
            {"name": _R3_KEY, "policy": _R3_POLICY, "scope": "SIGNATURE_STANDARD", "quantum_safe": "true"},
            "Without the policy this request gets ML-DSA-44 (R1); the policy narrows it to ML-DSA-87.",
            template="ml-dsa-87",
        ),
        _sign(_R3_KEY, "r3-sig", "Signing is allowed."),
        _update_policy(
            _R3_POLICY,
            _policy(["ml-dsa-87"], ["create_key", "read_key", "verify"]),
            "Remove sign from the allowed operations. Nothing about the key changes.",
            "Stop signing under the policy",
        ),
        RunbookStep(
            persona="Producer",
            title="Sign again",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.POLICY_REJECTED,
            explanation="The same request as before.",
            request={"key_name": _R3_KEY, "message": _MESSAGE},
            hint="The policy no longer allows sign; the check happens on every call.",
        ),
        RunbookStep(
            persona="CISO",
            title="Transform to a template outside the policy",
            service=_KEYS,
            method="TransformKey",
            expected=ExpectedOutcome.POLICY_REJECTED,
            explanation="ML-DSA-65 is not in the policy's allowed templates.",
            request={"name": _R3_KEY, "template_id": "ml-dsa-65"},
            hint="A transform places a new version, which must use an allowed template.",
        ),
        _update_policy(
            _R3_POLICY,
            _policy(["ml-dsa-87", "ml-dsa-65"], ["create_key", "read_key", "verify"]),
            "Allow ML-DSA-65 as well.",
            "Allow the target template",
        ),
        _transform(_R3_KEY, "ml-dsa-65", "The same request now succeeds."),
    ),
    goal=Goal(
        claim="The policy is enforced on every call",
        before="Rules in a document",
        after="rules applied at once",
        proofs=(
            Proof("The policy narrows what a request gets", (2,)),
            Proof("The same Sign is allowed, then blocked", (3, 4, 5)),
            Proof("A policy change takes effect at once", (6, 7, 8)),
        ),
    ),
)

# ── R4 — Crypto agility with backward compatibility ──────────────────────────

_R4_POLICY = "demo-r4-policy"
_R4_KEY = "demo-r4-key"

R4_AGILITY = Runbook(
    key="r4-agility",
    title="R4 · Crypto agility with backward compatibility",
    summary=(
        "Move a key from ECDSA to ML-DSA under the same name. Old signatures still verify, "
        "because each bundle records its key version, and the producer's call does not change."
    ),
    steps=(
        _create_policy(
            _R4_POLICY,
            _policy(
                ["ecdsa-p256-sha256-der", "ml-dsa-65", "rsa-pss-sha256-mgf1-32-2048", "rsa-pkcs1v15-sha256-2048"],
                ["create_key", "read_key", "sign", "verify"],
            ),
            "Classical and post-quantum signature templates.",
        ),
        _create_key(
            "Create an ECDSA signing key",
            {"name": _R4_KEY, "policy": _R4_POLICY, "template_id": "ecdsa-p256-sha256-der"},
            "Version 1.",
            template="ecdsa-p256-sha256-der",
        ),
        _sign(_R4_KEY, "r4-ecdsa", "Keep the bundle: it records key_version 1."),
        _transform(
            _R4_KEY,
            "ml-dsa-65",
            "Version 2 is a new ML-DSA key; version 1 stays for verification.",
            **{"key_metadata.version": 2},
        ),
        _verify(_R4_KEY, "r4-ecdsa", "The pre-transform signature verifies against version 1."),
        _sign(_R4_KEY, "r4-mldsa", "The same request as before; the signature is now ML-DSA, from version 2."),
        _verify(_R4_KEY, "r4-mldsa", "The new signature verifies too."),
        _timeline(_R4_KEY, "v1 ECDSA, v2 ML-DSA-65, same provider."),
        _create_key(
            "Create an RSA-PSS key",
            {"name": "demo-r4-rsa", "policy": _R4_POLICY, "template_id": "rsa-pss-sha256-mgf1-32-2048"},
            "Variant: change only the padding, keeping the key pair.",
            template="rsa-pss-sha256-mgf1-32-2048",
        ),
        RunbookStep(
            persona="CISO",
            title="Retain the key bytes, switch to PKCS#1 v1.5",
            service=_KEYS,
            method="TransformKey",
            expected=OK,
            explanation="The same RSA key pair under a different padding scheme.",
            request={"name": "demo-r4-rsa", "template_id": "rsa-pkcs1v15-sha256-2048", "retain_key_bytes": True},
            look_for={"key_metadata.template_id": "rsa-pkcs1v15-sha256-2048"},
        ),
    ),
    goal=Goal(
        claim="Change the algorithm, don't break the past",
        before="Swap the algorithm and re-sign everything",
        after="same key name, old signatures still valid",
        proofs=(
            Proof("ECDSA to ML-DSA under the same name", (2, 4)),
            Proof("The old signature still verifies", (3, 5)),
            Proof("The caller's request does not change", (6, 7)),
        ),
    ),
)

# ── R5 — Provider portability ─────────────────────────────────────────────────

_R5_POLICY = "demo-r5-policy"

R5_PORTABILITY = Runbook(
    key="r5-portability",
    title="R5 · Provider portability",
    summary=(
        "Move keys between providers without touching the data they protect: a provider "
        "switch copies the key, a rekey leaves the old version where it was."
    ),
    steps=(
        _create_policy(
            _R5_POLICY,
            _policy(
                ["aes-256-gcm-128-96", "ecdsa-p256-sha256-der"],
                ["create_key", "read_key", "encrypt", "decrypt", "sign", "verify"],
            ),
            "An encryption and a signature template.",
        ),
        _create_key(
            "Create an AES-GCM key on software",
            {
                "name": "demo-r5-data",
                "policy": _R5_POLICY,
                "template_id": "aes-256-gcm-128-96",
                "provider_id": "software",
            },
            "Pinned to the Go provider.",
            provider="software",
        ),
        _encrypt("demo-r5-data", "r5-ct", "Keep the bundle."),
        RunbookStep(
            persona="CISO",
            title="Check the move first",
            service=_KEYS,
            method="ValidateKeyOperation",
            expected=OK,
            explanation="Nothing changes: every strategy is assessed, with why each would or would not work.",
            request={"name": "demo-r5-data", "target_instance_id": "openssl"},
        ),
        _migrate(
            "demo-r5-data",
            "PROVIDER_SWITCH",
            "openssl",
            "The key bytes move; the key keeps its name.",
            **{"migration.key_bytes_preserved": True},
        ),
        _decrypt("demo-r5-data", "r5-ct", "The ciphertext from before the move decrypts on openssl."),
        _create_key(
            "Create an ECDSA key on software",
            {
                "name": "demo-r5-sign",
                "policy": _R5_POLICY,
                "template_id": "ecdsa-p256-sha256-der",
                "provider_id": "software",
            },
            "For the second strategy.",
            provider="software",
        ),
        _sign("demo-r5-sign", "r5-sig", "Keep the bundle."),
        _migrate(
            "demo-r5-sign",
            "REKEY_AND_ARCHIVE",
            "openssl",
            "A new key is generated on openssl; version 1 stays on software for old signatures.",
            **{"migration.archived.provider": "software"},
        ),
        _verify("demo-r5-sign", "r5-sig", "The old signature verifies against the archived version."),
        _timeline("demo-r5-sign", "v1 on software, v2 on openssl."),
    ),
    goal=Goal(
        claim="Move keys between providers, data untouched",
        before="Re-encrypt everything",
        after="move the key",
        proofs=(
            Proof("Old ciphertext decrypts on the new provider", (2, 3, 5, 6)),
            Proof("A rekey keeps the old version for old signatures", (7, 8, 9, 10)),
        ),
    ),
)

# ── R6 — The scope is a contract ──────────────────────────────────────────────

_R6_POLICY = "demo-r6-policy"

R6_SCOPE = Runbook(
    key="r6-scope",
    title="R6 · The scope is a contract",
    summary=(
        "A key's scope fixes what callers pass in: a transform may change the algorithm but "
        "never the input contract, and a context-bound signature verifies only in its context."
    ),
    steps=(
        _create_policy(
            _R6_POLICY,
            _policy(
                ["ecdsa-p256-sha256-der", "ecdsa-p256-prehashed-der", "ml-dsa-65"],
                ["create_key", "read_key", "sign", "verify", "digest_sign", "digest_verify"],
            ),
            "Standard, prehashed and context-capable signature templates.",
        ),
        _create_key(
            "Create a standard signature key",
            {"name": "demo-r6-std", "policy": _R6_POLICY, "template_id": "ecdsa-p256-sha256-der"},
            "Its callers pass whole messages.",
            template="ecdsa-p256-sha256-der",
        ),
        RunbookStep(
            persona="CISO",
            title="Transform it to a prehashed template",
            service=_KEYS,
            method="TransformKey",
            expected=ExpectedOutcome.FAILED_PRECONDITION,
            explanation="The same curve, but callers would have to pass digests instead of messages.",
            request={"name": "demo-r6-std", "template_id": "ecdsa-p256-prehashed-der", "scope": "SIGNATURE_PREHASHED"},
            hint="A transform keeps the key's scope; SIGNATURE_PREHASHED is a different contract.",
        ),
        RunbookStep(
            persona="Producer",
            title="DigestSign with the standard key",
            service=_CRYPTO,
            method="DigestSign",
            expected=ExpectedOutcome.INVALID_ARGUMENT,
            explanation="A digest is not what this key's callers agreed to pass.",
            request={"key_name": "demo-r6-std", "digest": _MESSAGE_SHA256, "hash_algorithm": "SHA256"},
            hint="DigestSign needs a key with a prehashed scope.",
        ),
        _create_key(
            "Create an ML-DSA key with signing context",
            {
                "name": "demo-r6-ctx",
                "policy": _R6_POLICY,
                "template_id": "ml-dsa-65",
                "scope": "SIGNATURE_WITH_CONTEXT",
            },
            "Each signature is bound to a context string.",
            template="ml-dsa-65",
        ),
        _sign("demo-r6-ctx", "r6-ctx", "Bound to payments-v1.", domain_context="payments-v1"),
        RunbookStep(
            persona="Consumer",
            title="Verify under another context",
            service=_CRYPTO,
            method="Verify",
            expected=ExpectedOutcome.SIGNATURE_INVALID,
            explanation="Paste the r6-ctx bundle, then set the context to invoices-v1.",
            request={"key_name": "demo-r6-ctx", "domain_context": "invoices-v1"},
            bundle="r6-ctx",
            hint="The signature is valid only for payments-v1.",
            look_for={"valid": False},
        ),
        _verify("demo-r6-ctx", "r6-ctx", "Under its own context it verifies.", domain_context="payments-v1"),
    ),
    goal=Goal(
        claim="A key's scope is a contract with its callers",
        before="Callers break silently",
        after="changes that would break them are refused",
        proofs=(
            Proof("The input contract cannot change", (3, 4)),
            Proof("A signature is bound to its context", (6, 7, 8)),
        ),
    ),
)

# ── R7 — Separation of duties ─────────────────────────────────────────────────

R7_DUTIES = Runbook(
    key="r7-duties",
    title="R7 · Separation of duties",
    summary=(
        "Three browsers, three identities: the CISO governs, the producer signs, the consumer "
        "verifies, and none can do the others' work. Needs the server with authentication."
    ),
    steps=(
        _create_policy(
            "demo-r7-policy",
            _policy(["ecdsa-p256-sha256-der"], ["create_key", "read_key", "sign", "verify"]),
            "Sign in as CISO in browser one.",
        ),
        _create_key(
            "Create the signing key",
            {"name": "demo-r7-sign", "policy": "demo-r7-policy", "template_id": "ecdsa-p256-sha256-der"},
            "In browser two, as the producer.",
        ),
        _sign("demo-r7-sign", "r7-sig", "Copy the bundle to browser three."),
        RunbookStep(
            persona="Producer",
            title="Try to verify",
            service=_CRYPTO,
            method="Verify",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="Paste the producer's own bundle.",
            request={"key_name": "demo-r7-sign"},
            bundle="r7-sig",
            hint="The producer lacks citius:crypto:verify.",
        ),
        _verify("demo-r7-sign", "r7-sig", "In browser three, as the consumer."),
        RunbookStep(
            persona="Consumer",
            title="Try to sign",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.METHOD_DENIED,
            explanation="The consumer's identity has no signing permission.",
            request={"key_name": "demo-r7-sign", "message": "Consumer must not sign"},
            hint="The consumer lacks citius:crypto:sign.",
        ),
        RunbookStep(
            persona="Producer",
            title="Sign with a key outside your pattern",
            service=_CRYPTO,
            method="Sign",
            expected=ExpectedOutcome.RESOURCE_DENIED,
            explanation="The producer may sign, but not with this key.",
            request={"key_name": "demo-restricted-key", "message": _MESSAGE},
            hint="demo-restricted-* is on the producer's deny list.",
        ),
    ),
    goal=Goal(
        claim="Nobody can do another person's job",
        before="Shared admin credentials",
        after="each person limited to their own operations",
        proofs=(
            Proof("The producer cannot verify", (4,)),
            Proof("The consumer cannot sign", (6,)),
            Proof("A key outside your pattern is denied", (7,)),
        ),
    ),
)

# ── R8 — PQ migration campaign ────────────────────────────────────────────────

_R8_POLICY = "demo-r8-policy"
_R8_TEMPLATES = ["ecdsa-p256-sha256-der", "rsa-pss-sha256-mgf1-32-2048", "aes-256-gcm-128-96", "ml-dsa-65"]
_R8_OPS = ["create_key", "read_key", "sign", "verify", "encrypt", "decrypt"]


def _r8_rekey(key: str) -> RunbookStep:
    return _migrate(
        key,
        "REKEY_AND_ARCHIVE",
        "openssl-fips",
        "New material is generated inside the FIPS module; the old version stays archived.",
    )


R8_CAMPAIGN = Runbook(
    key="r8-campaign",
    title="R8 · PQ migration campaign",
    summary=(
        "Inventory classical keys, require FIPS custody, move them into the FIPS module, move the "
        "signing keys to ML-DSA, and show that every old artifact still verifies or decrypts while "
        "the application's calls stay the same. Needs the server started with --fips-config."
    ),
    steps=(
        _create_policy(
            _R8_POLICY,
            _policy(_R8_TEMPLATES, _R8_OPS),
            "Classical templates first, so intent-based requests get classical algorithms today.",
        ),
        _create_key(
            "Create a standard signature key",
            {"name": "demo-r8-ecdsa", "policy": _R8_POLICY, "scope": "SIGNATURE_STANDARD"},
            "From intent: ECDSA, the policy's first signature template.",
            template="ecdsa-p256-sha256-der",
        ),
        _create_key(
            "Create an RSA-PSS signature key",
            {"name": "demo-r8-rsa", "policy": _R8_POLICY, "template_id": "rsa-pss-sha256-mgf1-32-2048"},
            "A legacy system's choice.",
            template="rsa-pss-sha256-mgf1-32-2048",
        ),
        _create_key(
            "Create a data encryption key",
            {"name": "demo-r8-data", "policy": _R8_POLICY, "scope": "AEAD_STANDARD"},
            "From intent: AES-256-GCM.",
            template="aes-256-gcm-128-96",
        ),
        _sign("demo-r8-ecdsa", "r8-ecdsa", "Keep the bundle."),
        _sign("demo-r8-rsa", "r8-rsa", "Keep the bundle."),
        _encrypt("demo-r8-data", "r8-ct", "Keep the bundle."),
        _list_keys(
            _R8_POLICY,
            "Take the inventory",
            "Three keys, none quantum-safe, none in a FIPS module. Open the Crypto inventory tab "
            "for the PQ-readiness report and the CBOM download.",
        ),
        _update_policy(
            _R8_POLICY,
            _policy(_R8_TEMPLATES, _R8_OPS, provider_requirements={"fips_140_certified": True}),
            "From now on every new key version under this policy must be placed in a FIPS 140 module.",
            "Require FIPS custody",
        ),
        RunbookStep(
            persona="CISO",
            title="Try to move the data key to plain openssl",
            service=_KEYS,
            method="MigrateKey",
            expected=ExpectedOutcome.FAILED_PRECONDITION,
            explanation="The policy now decides where keys may go.",
            request={"name": "demo-r8-data", "strategy": "REKEY_AND_ARCHIVE", "target_instance_id": "openssl"},
            hint="The policy's provider_requirements need fips_140_certified; openssl is not.",
        ),
        _r8_rekey("demo-r8-ecdsa"),
        _r8_rekey("demo-r8-rsa"),
        _r8_rekey("demo-r8-data"),
        _transform(
            "demo-r8-ecdsa",
            "ml-dsa-65",
            "The ECDSA key regenerates as ML-DSA inside the FIPS module.",
            **{"key_metadata.provider": "openssl-fips"},
        ),
        _transform(
            "demo-r8-rsa",
            "ml-dsa-65",
            "RSA material cannot become ML-DSA, so this key regenerates too.",
            **{"key_metadata.provider": "openssl-fips"},
        ),
        _verify("demo-r8-ecdsa", "r8-ecdsa", "The original ECDSA signature verifies against the archived v1."),
        _verify("demo-r8-rsa", "r8-rsa", "So does the RSA one."),
        _decrypt("demo-r8-data", "r8-ct", "The original ciphertext decrypts."),
        _sign("demo-r8-ecdsa", "r8-pq", "The same request as before: now an ML-DSA signature, from the FIPS module."),
        _timeline("demo-r8-ecdsa", "v1 ECDSA on software, v2 ECDSA in openssl-fips, v3 ML-DSA-65 in openssl-fips."),
        _list_keys(
            _R8_POLICY,
            "Take the inventory again",
            "Every key in openssl-fips; both signing keys quantum-safe. The AES-256 key is unchanged: "
            "the catalogue does not mark AES as quantum-safe. Rebuild the Crypto inventory to compare.",
        ),
    ),
    goal=Goal(
        claim="PQ migration with nothing broken",
        before="A big-bang migration",
        after="keys moved one at a time, everything still works",
        proofs=(
            Proof("Inventory before and after", (8, 21)),
            Proof("FIPS custody is enforced", (9, 10)),
            Proof("Every old signature and ciphertext still works", (16, 17, 18)),
        ),
    ),
)

DEEP_DIVES: tuple[Runbook, ...] = (
    R1_INTENT,
    R2_PROVIDERS,
    R3_POLICY,
    R4_AGILITY,
    R5_PORTABILITY,
    R6_SCOPE,
    R7_DUTIES,
    R8_CAMPAIGN,
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
            "Naming a template is still possible; the policy must allow it.",
            template="ml-dsa-65",
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

RUNBOOKS: tuple[Runbook, ...] = (*SHOWCASE, *DEEP_DIVES)
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
