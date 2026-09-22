"""Per-RPC form definitions for the implemented Workbench RPCs.

Each form declares the request fields exposed directly in the UI, aligned with
the Citius protobuf request messages in api/proto and with the request keys the
corresponding action reads. Advanced or mutually-exclusive scope/context
parameters are represented as an optional JSON overrides block rather than a
generated widget per oneof branch.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import citius_sdk as _sdk


@dataclass(frozen=True, slots=True)
class FormField:
    """One request field rendered as an individual control.

    ``group`` places the field inside a collapsible section (added on demand)
    rather than the always-visible core of the form; an empty group means the
    field is a core field shown up front.
    """

    key: str
    label: str
    kind: str = "text"  # text | area | number | bool | dropdown
    placeholder: str = ""
    choices: tuple[str, ...] = ()
    optional: bool = False
    group: str = ""


@dataclass(frozen=True, slots=True)
class RpcFormSpec:
    """The form for one implemented RPC: fields, examples, and output shape."""

    service: str
    method: str
    action_label: str
    fields: tuple[FormField, ...]
    examples: tuple[tuple[object, ...], ...] = ()
    produces: str = ""  # "" | Signature | Ciphertext
    consumes: str = ""  # "" | Signature | Ciphertext: accepts a pasted producer bundle
    advanced_hint: str = ""

    def core_fields(self) -> tuple[FormField, ...]:
        """Fields shown up front (no group), in declaration order."""
        return tuple(field for field in self.fields if not field.group)

    def grouped_fields(self) -> tuple[tuple[str, tuple[FormField, ...]], ...]:
        """Optional filter sections as ``(group_name, fields)`` in first-seen order."""
        order: list[str] = []
        by_group: dict[str, list[FormField]] = {}
        for field in self.fields:
            if not field.group:
                continue
            if field.group not in by_group:
                by_group[field.group] = []
                order.append(field.group)
            by_group[field.group].append(field)
        return tuple((name, tuple(by_group[name])) for name in order)


# Collapsible filter-section names for the key-creation form, aligned with the
# API: UniversalSecurityProperties, per-scope primitive properties, and
# ProviderRequirements. An advanced section exposes the raw JSON escape hatches.
GROUP_UNIVERSAL = "Universal security properties"
GROUP_PROVIDER = "Provider requirements"
GROUP_ADVANCED = "Advanced — raw JSON overrides"
# Consumer RPCs (Verify/Decrypt) take a pasted bundle up front; the raw
# value + metadata fields it fills are demoted into this manual section.
GROUP_MANUAL = "Advanced — enter value and metadata manually"


_POLICY_FORMATS = ("json", "rego", "cedar", "yaml")

# Full intent-oriented scope vocabulary, sourced from the SDK Scope enum so the
# dropdown and the SDK stay in lock-step. A blank leading entry keeps "infer
# from template" as the default.
_KEY_SCOPES: tuple[str, ...] = ("", *(scope.name for scope in _sdk.Scope))

# Optional filter-property choices, aligned with the SDK enums. A blank entry
# means "leave unset" so the property is not sent to the server.
_NIST_LEVELS: tuple[str, ...] = ("", *(level.name for level in _sdk.NistSecurityLevel))
_NIST_STATUSES: tuple[str, ...] = ("", *(status.name for status in _sdk.NistStatus))
_FIPS_LEVELS: tuple[str, ...] = ("", *(level.name for level in _sdk.Fips140Level))
_TRISTATE: tuple[str, ...] = ("", "true", "false")
_HASH_ALGORITHMS: tuple[str, ...] = ("", *(algorithm.name for algorithm in _sdk.HashAlgorithm))

# Policy documents must match the server's rules_json schema exactly: JSON with
# version "1", allowed_operations.key_operations using lowercase operation
# names, and allowed_templates using catalog template IDs. The evaluator is
# deny-by-default, so create_key/read_key must be granted explicitly for the
# key-management examples to work against the same policy.
_SAMPLE_SIGNING_POLICY = json.dumps(
    {
        "version": "1",
        "allowed_operations": {
            "key_operations": ["create_key", "read_key", "rotate_key", "sign", "verify", "digest_sign", "digest_verify"]
        },
        "allowed_templates": ["ecdsa-p256-sha256-der", "ml-dsa-65"],
    },
    indent=2,
)
_SAMPLE_ENCRYPTION_POLICY = json.dumps(
    {
        "version": "1",
        "allowed_operations": {"key_operations": ["create_key", "read_key", "encrypt", "decrypt"]},
        "allowed_templates": ["aes-256-gcm-128-96"],
    },
    indent=2,
)
_SAMPLE_RESTRICTED_POLICY = json.dumps(
    {
        "version": "1",
        "allowed_operations": {"key_operations": ["read_key", "verify"]},
        "allowed_templates": ["ecdsa-p256-sha256-der"],
    },
    indent=2,
)
_SAMPLE_SIGNING_POLICY_V2 = json.dumps(
    {
        "version": "1",
        "allowed_operations": {
            "key_operations": ["create_key", "read_key", "rotate_key", "sign", "verify", "digest_sign", "digest_verify"]
        },
        "allowed_templates": ["ecdsa-p256-sha256-der", "ecdsa-p384-sha384-der", "ml-dsa-65"],
    },
    indent=2,
)

FORMS: tuple[RpcFormSpec, ...] = (
    RpcFormSpec(
        "CryptoPolicyService",
        "CreateCryptoPolicy",
        "Create",
        (
            FormField("name", "Policy name", placeholder="demo-signing-policy"),
            FormField(
                "policy_document",
                "Policy document",
                kind="area",
                placeholder='{"version": "1", "allowed_operations": {"key_operations": ["sign"]}, …}',
            ),
            FormField("format", "Format", kind="dropdown", choices=_POLICY_FORMATS, optional=True),
        ),
        examples=(
            ("demo-signing-policy", _SAMPLE_SIGNING_POLICY, "json"),
            ("demo-encryption-policy", _SAMPLE_ENCRYPTION_POLICY, "json"),
            ("demo-restricted-policy", _SAMPLE_RESTRICTED_POLICY, "json"),
        ),
    ),
    RpcFormSpec(
        "CryptoPolicyService",
        "ReadCryptoPolicy",
        "Read",
        (FormField("name", "Policy name", placeholder="demo-signing-policy"),),
        examples=(("demo-signing-policy",),),
    ),
    RpcFormSpec(
        "CryptoPolicyService",
        "UpdateCryptoPolicy",
        "Update",
        (
            FormField("name", "Policy name", placeholder="demo-signing-policy"),
            FormField(
                "policy_document",
                "Policy document",
                kind="area",
                placeholder='{"version": "1", "allowed_operations": {"key_operations": ["sign"]}, …}',
            ),
            FormField("format", "Format", kind="dropdown", choices=_POLICY_FORMATS, optional=True),
            FormField("expected_version", "Expected version", kind="number", optional=True),
        ),
        examples=(("demo-signing-policy", _SAMPLE_SIGNING_POLICY_V2, "json", 1),),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "CreateKey",
        "Create",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("policy", "Policy", placeholder="demo-signing-policy"),
            FormField("template_id", "Template ID", placeholder="ecdsa-p256-sha256-der", optional=True),
            FormField("provider_id", "Provider ID", placeholder="software", optional=True),
            FormField(
                "scope",
                "Scope (inferred from template when blank)",
                kind="dropdown",
                choices=_KEY_SCOPES,
                optional=True,
            ),
            # Security-property filters (all optional; blank = leave unset).
            FormField(
                "security_strength_bits",
                "Min security strength (bits)",
                kind="number",
                optional=True,
                group=GROUP_UNIVERSAL,
            ),
            FormField(
                "nist_security_level",
                "NIST security level",
                kind="dropdown",
                choices=_NIST_LEVELS,
                optional=True,
                group=GROUP_UNIVERSAL,
            ),
            FormField(
                "nist_status",
                "NIST status",
                kind="dropdown",
                choices=_NIST_STATUSES,
                optional=True,
                group=GROUP_UNIVERSAL,
            ),
            FormField(
                "quantum_safe", "Quantum-safe", kind="dropdown", choices=_TRISTATE, optional=True, group=GROUP_UNIVERSAL
            ),
            FormField(
                "fips_approved",
                "FIPS approved",
                kind="dropdown",
                choices=_TRISTATE,
                optional=True,
                group=GROUP_UNIVERSAL,
            ),
            # Provider-requirement filters (all optional).
            FormField("require_fips_140", "Require FIPS 140 certified", kind="bool", group=GROUP_PROVIDER),
            FormField(
                "min_fips_level",
                "Min FIPS 140 level",
                kind="dropdown",
                choices=_FIPS_LEVELS,
                optional=True,
                group=GROUP_PROVIDER,
            ),
            FormField("require_memory_safe", "Require memory-safe", kind="bool", group=GROUP_PROVIDER),
            FormField("require_constant_time", "Require constant-time", kind="bool", group=GROUP_PROVIDER),
            FormField(
                "require_side_channel_hardened", "Require side-channel hardened", kind="bool", group=GROUP_PROVIDER
            ),
            FormField("require_no_known_cve", "Require no known CVEs", kind="bool", group=GROUP_PROVIDER),
            FormField("prefer_hardware_accelerated", "Prefer hardware acceleration", kind="bool", group=GROUP_PROVIDER),
            # Advanced escape hatch: a full ScopeSpecification / ProviderRequirements JSON wins.
            FormField(
                "scope_spec",
                "Scope specification (JSON, overrides scope + filters)",
                kind="area",
                placeholder='{"signature": {"scope": "SIGNATURE_SCOPE_STANDARD"}}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
            FormField(
                "provider_requirements",
                "Provider requirements (JSON, overrides toggles)",
                kind="area",
                placeholder='{"fips_140_certified": true, "min_fips_level": "FIPS_140_LEVEL_3"}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(
            (
                "demo-signing-key",
                "demo-signing-policy",
                "ecdsa-p256-sha256-der",
                "software",
                "SIGNATURE_STANDARD",
                None,
                "",
                "",
                "",
                "",
                False,
                "",
                False,
                False,
                False,
                False,
                False,
                "",
                "",
            ),
            (
                "demo-encryption-key",
                "demo-encryption-policy",
                "aes-256-gcm-128-96",
                "software",
                "AEAD_STANDARD",
                None,
                "",
                "",
                "",
                "",
                False,
                "",
                False,
                False,
                False,
                False,
                False,
                "",
                "",
            ),
            # Exercises the filter sections: a quantum-safe, NIST-approved
            # signing key that must run on a FIPS 140 L3, memory-safe provider.
            (
                "demo-pqc-signing-key",
                "demo-signing-policy",
                "ml-dsa-65",
                "software",
                "SIGNATURE_STANDARD",
                192,
                "LEVEL_3",
                "APPROVED",
                "true",
                "true",
                True,
                "LEVEL_3",
                True,
                False,
                False,
                True,
                False,
                "",
                "",
            ),
        ),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "ReadKey",
        "Read",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("version", "Version", kind="number", optional=True),
        ),
        examples=(("demo-signing-key", None),),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "TransformKey",
        "Transform",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("template_id", "Template ID", placeholder="ml-dsa-65", optional=True),
            FormField("retain_key_bytes", "Retain key bytes", kind="bool"),
            FormField(
                "scope",
                "Scope (inferred from template when blank)",
                kind="dropdown",
                choices=_KEY_SCOPES,
                optional=True,
            ),
            FormField(
                "scope_spec",
                "Scope specification (JSON, overrides scope)",
                kind="area",
                placeholder='{"signature": {"scope": "SIGNATURE_SCOPE_STANDARD"}}',
                optional=True,
            ),
        ),
        examples=(("demo-signing-key", "ml-dsa-65", False, "SIGNATURE_STANDARD", ""),),
    ),
    RpcFormSpec(
        "CryptoService",
        "Sign",
        "Sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("message", "Message", kind="area", placeholder="Hello from Citius"),
            FormField(
                "domain_context",
                "Domain context (text)",
                placeholder="e.g. Ed25519ctx domain separation",
                optional=True,
            ),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"no_context": {}} or {"vendor_context": {"params": {"vendor": "acme"}}}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(
            ("demo-signing-key", "Hello from Citius", "", ""),
            # Domain-separated signature: a plain-text separation tag.
            ("demo-signing-key", "Hello from Citius", "citius-demo", ""),
        ),
        produces="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "Verify",
        "Verify",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField(
                "bundle",
                "Signature bundle (paste from a Sign response)",
                kind="area",
                placeholder='{"key_name": "...", "signature": "...", "metadata": {...}, "message": "..."}',
                optional=True,
            ),
            FormField("message", "Message", kind="area", placeholder="Hello from Citius"),
            FormField(
                "domain_context",
                "Domain context (text, must match sign)",
                placeholder="e.g. Ed25519ctx domain separation",
                optional=True,
            ),
            FormField("signature", "Signature (base64)", kind="area", group=GROUP_MANUAL),
            FormField("metadata", "Operation metadata (JSON)", kind="area", group=GROUP_MANUAL),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"no_context": {}} or {"domain_context": {"context": "<base64>"}}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(
            # Bundle-first: paste one bundle, leave the manual fields blank.
            ("demo-signing-key", "<paste Sign bundle>", "", "", "", "", ""),
        ),
        consumes="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "Encrypt",
        "Encrypt",
        (
            FormField("key_name", "Key name", placeholder="demo-encryption-key"),
            FormField("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
            FormField(
                "aad",
                "Additional authenticated data (text)",
                placeholder="authenticated but not encrypted",
                optional=True,
            ),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"aead_params": {"aad": "<base64>"}} or {"no_params": {}}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(
            ("demo-encryption-key", "Sensitive demo payload", "", ""),
            # AEAD with additional authenticated data: a plain-text context tag.
            ("demo-encryption-key", "Sensitive demo payload", "context-v1", ""),
        ),
        produces="Ciphertext",
    ),
    RpcFormSpec(
        "CryptoService",
        "Decrypt",
        "Decrypt",
        (
            FormField("key_name", "Key name", placeholder="demo-encryption-key"),
            FormField(
                "bundle",
                "Ciphertext bundle (paste from an Encrypt response)",
                kind="area",
                placeholder='{"key_name": "...", "ciphertext": "...", "metadata": {...}}',
                optional=True,
            ),
            FormField(
                "aad",
                "Additional authenticated data (text, must match encrypt)",
                placeholder="authenticated but not encrypted",
                optional=True,
            ),
            FormField("ciphertext", "Ciphertext (base64)", kind="area", group=GROUP_MANUAL),
            FormField("metadata", "Operation metadata (JSON)", kind="area", group=GROUP_MANUAL),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"aead_params": {"aad": "<base64>"}} or {"no_params": {}}',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(("demo-encryption-key", "<paste Encrypt bundle>", "", "", "", ""),),
        consumes="Ciphertext",
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestSign",
        "Digest sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("digest", "Digest (base64)", kind="area"),
            FormField("hash_algorithm", "Hash algorithm", kind="dropdown", choices=_HASH_ALGORITHMS, optional=True),
            FormField(
                "domain_context",
                "Domain context (text)",
                placeholder="e.g. prehash domain separation",
                optional=True,
            ),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"no_context": {}}, optionally with "hash_algorithm": "HASH_ALGORITHM_SHA256"',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(
            ("demo-signing-key", "<paste digest>", "", "", ""),
            # Declare the hash that produced the digest.
            ("demo-signing-key", "<paste digest>", "SHA256", "", ""),
        ),
        produces="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestVerify",
        "Digest verify",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField(
                "bundle",
                "Signature bundle (paste from a Digest sign response)",
                kind="area",
                placeholder='{"key_name": "...", "signature": "...", "metadata": {...}, "digest": "..."}',
                optional=True,
            ),
            FormField("digest", "Digest (base64)", kind="area"),
            FormField("hash_algorithm", "Hash algorithm", kind="dropdown", choices=_HASH_ALGORITHMS, optional=True),
            FormField(
                "domain_context",
                "Domain context (text, must match sign)",
                placeholder="e.g. prehash domain separation",
                optional=True,
            ),
            FormField("signature", "Signature (base64)", kind="area", group=GROUP_MANUAL),
            FormField("metadata", "Operation metadata (JSON)", kind="area", group=GROUP_MANUAL),
            FormField(
                "scope_params",
                "Scope parameters (JSON, advanced override)",
                kind="area",
                placeholder='{"no_context": {}}, optionally with "hash_algorithm": "HASH_ALGORITHM_SHA256"',
                optional=True,
                group=GROUP_ADVANCED,
            ),
        ),
        examples=(("demo-signing-key", "<paste Digest sign bundle>", "", "", "", "", "", ""),),
        consumes="Signature",
    ),
)

FORMS_BY_METHOD: dict[tuple[str, str], RpcFormSpec] = {(f.service, f.method): f for f in FORMS}


class FormValidationError(ValueError):
    """Raised when a form value cannot be turned into a request field."""


def build_request(spec: RpcFormSpec, values: list[object]) -> dict[str, object]:
    """Assemble a request dict from ordered field values, dropping empties.

    Text values are stripped of surrounding whitespace. Metadata fields provided
    as JSON text are parsed to a dict so the action can rebuild the operation
    metadata for Verify/Decrypt replays; invalid JSON or non-numeric input for a
    number field raises FormValidationError so the UI can report it instead of
    sending a silently mangled request.
    """
    request: dict[str, object] = {}
    for spec_field, value in zip(spec.fields, values, strict=True):
        if isinstance(value, str):
            value = value.strip()
        if value is None or value == "":
            continue
        if spec_field.key in ("metadata", "scope_params", "scope_spec") and isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:
                raise FormValidationError(f"{spec_field.label} must be valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise FormValidationError(f"{spec_field.label} must be a JSON object")
            request[spec_field.key] = parsed
            continue
        if spec_field.kind == "number":
            try:
                request[spec_field.key] = int(float(value))  # type: ignore[arg-type]
            except (TypeError, ValueError) as exc:
                raise FormValidationError(f"{spec_field.label} must be a number") from exc
            continue
        request[spec_field.key] = value
    return request
