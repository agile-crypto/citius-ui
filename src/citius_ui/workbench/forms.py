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
_SAMPLE_POLICY = "version: v1\nallowed_operations: [SIGN, VERIFY]\nallowed_templates: [ecdsa-p256-sha256]"

FORMS: tuple[RpcFormSpec, ...] = (
    RpcFormSpec(
        "CryptoPolicyService",
        "CreateCryptoPolicy",
        "Create",
        (
            FormField("name", "Policy name", placeholder="demo-signing-policy"),
            FormField("policy_document", "Policy document", kind="area", placeholder="version: v1 …"),
            FormField("format", "Format", kind="dropdown", choices=_POLICY_FORMATS, optional=True),
        ),
        examples=(
            ("demo-signing-policy", _SAMPLE_POLICY, "yaml"),
            ("demo-restricted-policy", "version: v1\nallowed_operations: [VERIFY]", "yaml"),
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
            FormField("policy_document", "Policy document", kind="area", placeholder="version: v2 …"),
            FormField("format", "Format", kind="dropdown", choices=_POLICY_FORMATS, optional=True),
            FormField("expected_version", "Expected version", kind="number", optional=True),
        ),
        examples=(("demo-signing-policy", _SAMPLE_POLICY + "\nmax_key_age_days: 90", "yaml", 1),),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "CreateKey",
        "Create",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("policy", "Policy", placeholder="demo-signing-policy"),
            FormField("template_id", "Template ID", placeholder="ecdsa-p256-sha256", optional=True),
            FormField("provider_id", "Provider ID", placeholder="software", optional=True),
        ),
        examples=(
            ("demo-signing-key", "demo-signing-policy", "ecdsa-p256-sha256", "software"),
            ("demo-encryption-key", "demo-signing-policy", "aes-256-gcm", "software"),
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
        ),
        examples=(("demo-signing-key", "ml-dsa-65", False),),
    ),
    RpcFormSpec(
        "CryptoService",
        "Sign",
        "Sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("message", "Message", kind="area", placeholder="Hello from Citius"),
        ),
        examples=(("demo-signing-key", "Hello from Citius"),),
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
        ),
        examples=(("demo-signing-key", "Hello from Citius", "<paste signature>", '{"key_version": 1}'),),
    ),
    RpcFormSpec(
        "CryptoService",
        "Encrypt",
        "Encrypt",
        (
            FormField("key_name", "Key name", placeholder="demo-encryption-key"),
            FormField("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
        ),
        examples=(("demo-encryption-key", "Sensitive demo payload"),),
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
        ),
        examples=(("demo-encryption-key", "<paste ciphertext>", '{"key_version": 1}'),),
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestSign",
        "Digest sign",
        (
            FormField("key_name", "Key name", placeholder="demo-signing-key"),
            FormField("digest", "Digest (base64)", kind="area"),
        ),
        examples=(("demo-signing-key", "<paste digest>"),),
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
        ),
        examples=(("demo-signing-key", "<paste digest>", "<paste signature>", '{"key_version": 1}'),),
    ),
)

FORMS_BY_METHOD: dict[tuple[str, str], RpcFormSpec] = {(f.service, f.method): f for f in FORMS}


def build_request(spec: RpcFormSpec, values: list[object]) -> dict[str, object]:
    """Assemble a request dict from ordered field values, dropping empties.

    Metadata fields provided as JSON text are parsed to a dict so the action can
    rebuild the operation metadata for Verify/Decrypt replays.
    """
    request: dict[str, object] = {}
    for spec_field, value in zip(spec.fields, values, strict=True):
        if value is None or value == "":
            continue
        if spec_field.key == "metadata" and isinstance(value, str):
            try:
                request[spec_field.key] = json.loads(value)
            except json.JSONDecodeError:
                request[spec_field.key] = value
            continue
        if spec_field.kind == "number":
            if isinstance(value, (int, float, str)):
                request[spec_field.key] = int(value)
            continue
        request[spec_field.key] = value
    return request
