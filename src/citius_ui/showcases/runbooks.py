"""Demo runbooks R1–R8 over the registered RPC actions.

Each runbook tells one story from UI_DEMO_EVALUATION.md §3. Every step names
the persona (browser) to use, prefills the Workbench form for its RPC, and
says what to look for in the response. Steps that are expected to be refused
carry a hint saying why, because the server returns only the status code
(decision A1).

Key and policy names start with ``demo-``, the prefix the demo identities
may use, and each runbook uses its own names, so runbooks do not interfere.
Run a runbook on a fresh server, or rename its keys: CreateKey refuses a name
that exists.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from citius_ui.actions.model import Availability
from citius_ui.showcases.model import ExpectedOutcome, Runbook, RunbookStep

AvailabilityResolver = Callable[[str, str], Availability]

_POLICY = "CryptoPolicyService"
_KEYS = "KeyManagementService"
_CRYPTO = "CryptoService"
_PROVIDERS = "ProviderService"

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
)

RUNBOOKS: tuple[Runbook, ...] = (
    R1_INTENT,
    R2_PROVIDERS,
    R3_POLICY,
    R4_AGILITY,
    R5_PORTABILITY,
    R6_SCOPE,
    R7_DUTIES,
    R8_CAMPAIGN,
)


def is_runnable(runbook: Runbook, resolver: AvailabilityResolver) -> bool:
    """Report whether every action a runbook references is available."""
    return all(resolver(service, method) is Availability.AVAILABLE for service, method in runbook.required_actions())


def look_up(response: Mapping[str, Any], path: str) -> object:
    """The value at a dotted path in a response, or None where it is absent."""
    value: object = response
    for part in path.split("."):
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
