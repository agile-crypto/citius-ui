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


@dataclass(frozen=True, slots=True)
class FormField:
    """One request field rendered as an individual control."""

    key: str
    label: str
    kind: str = "text"  # text | area | number | bool | dropdown
    placeholder: str = ""
    choices: tuple[str, ...] = ()
    optional: bool = False


@dataclass(frozen=True, slots=True)
class RpcFormSpec:
    """The form for one implemented RPC: fields, examples, and output shape."""

    service: str
    method: str
    action_label: str
    fields: tuple[FormField, ...]
    examples: tuple[tuple[object, ...], ...] = ()
    produces: str = ""  # "" | Signature | Ciphertext
    advanced_hint: str = ""


_POLICY_FORMATS = ("json", "rego", "cedar", "yaml")
_KEY_SCOPES = ("signature", "signature_prehashed", "aead")

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
            FormField(
                "scope_spec",
                "Scope specification (JSON, overrides scope)",
                kind="area",
                placeholder='{"signature": {"scope": "SIGNATURE_SCOPE_STANDARD"}}',
                optional=True,
            ),
        ),
        examples=(
            ("demo-signing-key", "demo-signing-policy", "ecdsa-p256-sha256-der", "software", "signature", ""),
            ("demo-encryption-key", "demo-encryption-policy", "aes-256-gcm-128-96", "software", "aead", ""),
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
        examples=(("demo-signing-key", "ml-dsa-65", False, "signature", ""),),
    ),
    RpcFormSpec(
        "CryptoService",
        "Sign",
        "Sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("message", "Message", kind="area", placeholder="Hello from Citius"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"no_context": {}} or {"domain_context": {"context": "<base64>"}}',
                optional=True,
            ),
        ),
        examples=(("demo-signing-key", "Hello from Citius", ""),),
        produces="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "Verify",
        "Verify",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("message", "Message", kind="area", placeholder="Hello from Citius"),
            FormField("signature", "Signature (base64)", kind="area"),
            FormField("metadata", "Operation metadata (JSON)", kind="area"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"no_context": {}} or {"domain_context": {"context": "<base64>"}}',
                optional=True,
            ),
        ),
        examples=(("demo-signing-key", "Hello from Citius", "<paste signature>", '{"key_version": 1}', ""),),
    ),
    RpcFormSpec(
        "CryptoService",
        "Encrypt",
        "Encrypt",
        (
            FormField("key_name", "Key name", placeholder="demo-encryption-key"),
            FormField("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"aead_params": {"aad": "<base64>"}} or {"no_params": {}}',
                optional=True,
            ),
        ),
        examples=(("demo-encryption-key", "Sensitive demo payload", ""),),
        produces="Ciphertext",
    ),
    RpcFormSpec(
        "CryptoService",
        "Decrypt",
        "Decrypt",
        (
            FormField("key_name", "Key name", placeholder="demo-encryption-key"),
            FormField("ciphertext", "Ciphertext (base64)", kind="area"),
            FormField("metadata", "Operation metadata (JSON)", kind="area"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"aead_params": {"aad": "<base64>"}} or {"no_params": {}}',
                optional=True,
            ),
        ),
        examples=(("demo-encryption-key", "<paste ciphertext>", '{"key_version": 1}', ""),),
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestSign",
        "Digest sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("digest", "Digest (base64)", kind="area"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"no_context": {}}, optionally with "hash_algorithm": "HASH_ALGORITHM_SHA256"',
                optional=True,
            ),
        ),
        examples=(("demo-signing-key", "<paste digest>", ""),),
        produces="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestVerify",
        "Digest verify",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("digest", "Digest (base64)", kind="area"),
            FormField("signature", "Signature (base64)", kind="area"),
            FormField("metadata", "Operation metadata (JSON)", kind="area"),
            FormField(
                "scope_params",
                "Scope parameters (JSON, optional)",
                kind="area",
                placeholder='{"no_context": {}}, optionally with "hash_algorithm": "HASH_ALGORITHM_SHA256"',
                optional=True,
            ),
        ),
        examples=(("demo-signing-key", "<paste digest>", "<paste signature>", '{"key_version": 1}', ""),),
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
