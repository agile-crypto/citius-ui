"""Per-RPC form definitions for the implemented Workbench RPCs.

Each form declares the request fields exposed directly in the UI, aligned with
the Citius protobuf request messages in api/proto and with the request keys the
corresponding action reads. Optional properties that together make one API
message (UniversalSecurityProperties, ProviderRequirements) form a property
section: the form shows only the ones that are set. Advanced or
mutually-exclusive scope/context parameters are an optional JSON overrides
block rather than a generated widget per oneof branch.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as _field
from types import MappingProxyType

import citius_sdk as _sdk

from citius_ui.workbench.catalogue import PROVIDER_INSTANCES, PROVIDER_TYPES, SCOPES


@dataclass(frozen=True, slots=True)
class FormField:
    """One request field rendered as an individual control.

    ``group`` places the field inside a collapsible section rather than the
    always-visible core of the form. ``section`` makes it one property of a
    property section (see ``PropertySection``), shown only once it is set or
    added. A field has at most one of the two; with neither it is a core
    field shown up front.

    ``choices_from`` names a server catalogue (see ``catalogue``) whose
    entries replace ``choices`` once the page has read it.
    """

    key: str
    label: str
    kind: str = "text"  # text | area | number | bool | dropdown | radio
    placeholder: str = ""
    choices: tuple[str, ...] = ()
    optional: bool = False
    group: str = ""
    help: str = ""
    choices_from: str = ""
    section: str = ""


@dataclass(frozen=True, slots=True)
class PropertySection:
    """Optional properties that together make one message of the request.

    Every property in it is optional, and an unset one means "no
    constraint", so the form lists only the properties that are set, and
    offers the rest to add. ``message`` says where they go in the request.
    """

    key: str
    title: str
    message: str


SECTION_SECURITY = PropertySection(
    "security",
    "Security properties: which algorithms qualify",
    "UniversalSecurityProperties, inside the scope specification",
)
SECTION_REQUIREMENTS = PropertySection(
    "requirements",
    "Provider requirements: which implementations qualify",
    "ProviderRequirements",
)
SECTIONS: tuple[PropertySection, ...] = (SECTION_SECURITY, SECTION_REQUIREMENTS)


@dataclass(frozen=True, slots=True)
class Example:
    """A ready-made request: what it shows, and the fields it sets.

    Every field it does not name keeps its blank default, so an example
    stays right when a form gains a field.
    """

    text: str
    values: Mapping[str, object] = _field(default_factory=lambda: MappingProxyType({}))


# The field whose value names what an example is about (the key, policy,
# template or instance), in the order they are looked for.
_SUBJECT_FIELDS = ("name", "key_name", "instance_id")


@dataclass(frozen=True, slots=True)
class RpcFormSpec:
    """The form for one implemented RPC: fields, examples, and output shape."""

    service: str
    method: str
    action_label: str
    fields: tuple[FormField, ...]
    examples: tuple[Example, ...] = ()
    produces: str = ""  # "" | Signature | Ciphertext
    consumes: str = ""  # "" | Signature | Ciphertext: accepts a pasted producer bundle
    advanced_hint: str = ""
    # The field shown as the examples' name column; blank picks the first of
    # _SUBJECT_FIELDS the form has. A form with neither shows no name column.
    subject: str = ""
    # Per property section the form has (by key): what the server does when
    # none of its properties is set.
    when_unset: Mapping[str, str] = _field(default_factory=lambda: MappingProxyType({}))

    def subject_field(self) -> FormField | None:
        keys = (self.subject,) if self.subject else _SUBJECT_FIELDS
        by_key = {f.key: f for f in self.fields}
        return next((by_key[key] for key in keys if key in by_key), None)

    def example_values(self, example: Example) -> list[object]:
        """The example as form values in field order, blank where it sets nothing.

        Raises ValueError if the example names a field the form does not have.
        """
        unknown = set(example.values) - {f.key for f in self.fields}
        if unknown:
            raise ValueError(f"{self.method} example {example.text!r} sets unknown field(s) {sorted(unknown)}")
        return [example.values[f.key] if f.key in example.values else blank_value(f) for f in self.fields]

    def example_rows(self) -> tuple[list[str], list[list[str]]]:
        """The examples table: its headers and one row per example."""
        subject = self.subject_field()
        if subject is None:
            return ["Example"], [[example.text] for example in self.examples]
        rows = [[str(example.values.get(subject.key) or "—"), example.text] for example in self.examples]
        return [subject.label, "Example"], rows

    def core_fields(self) -> tuple[FormField, ...]:
        """Fields shown up front (no group, no section), in declaration order."""
        return tuple(field for field in self.fields if not field.group and not field.section)

    def sections(self) -> tuple[tuple[PropertySection, tuple[FormField, ...]], ...]:
        """The property sections the form has, each with its fields in declaration order."""
        return tuple(
            (section, fields)
            for section in SECTIONS
            if (fields := tuple(field for field in self.fields if field.section == section.key))
        )

    def grouped_fields(self) -> tuple[tuple[str, tuple[FormField, ...]], ...]:
        """Collapsible sections as ``(group_name, fields)`` in first-seen order."""
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


# Collapsible sections: the raw JSON escape hatches, and the consumer RPCs'
# manual entry of what a pasted bundle otherwise fills.
GROUP_ADVANCED = "Advanced — raw JSON overrides"
# Consumer RPCs (Verify/Decrypt) take a pasted bundle up front; the raw
# value + metadata fields it fills are demoted into this manual section.
GROUP_MANUAL = "Advanced — enter value and metadata manually"


_POLICY_FORMATS = ("json", "rego", "cedar", "yaml")

# What a field an example leaves out is set to: what a fresh form shows.
_BLANK: dict[str, object] = {"bool": False, "number": None, "radio": None}


def blank_value(field: FormField) -> object:
    """What a fresh form shows in a field."""
    if field.kind == "dropdown" and field.choices and not field.optional:
        return field.choices[0]
    return _BLANK.get(field.kind, "")


def is_set(field: FormField, value: object) -> bool:
    """Whether a value is sent: a ticked box, or anything but a blank."""
    if field.kind == "bool":
        return value is True
    if isinstance(value, str):
        return value.strip() != ""
    return value is not None


def value_when_added(field: FormField) -> object:
    """The value a section property takes when it is added to the form.

    A requirement is ticked and a yes/no property is true, which is why one
    adds them; a property with a range of values starts blank, to be chosen.
    """
    if field.kind == "bool":
        return True
    if field.kind == "radio":
        return field.choices[0]
    return blank_value(field)


# The message the Sign examples use, and its SHA-256 (base64) for the digest ones.
_MESSAGE = "Hello from Citius"
_MESSAGE_SHA256 = "dd37/hdyzzn7BLltwfCmNXDQt612QJj3aIVjbPLQQKA="

# The scope vocabulary, from the SDK Scope enum so the dropdown and the SDK
# stay in lock-step. The blank first entry is what a fresh form shows: a key's
# scope is required, and left for the user to choose rather than preset.
_SCOPE_CHOICES: tuple[str, ...] = ("", *(scope.name for scope in _sdk.Scope))

# Property values, aligned with the SDK enums. A property that is not set is
# not sent, so no choice stands for "unset".
_NIST_LEVELS: tuple[str, ...] = tuple(level.name for level in _sdk.NistSecurityLevel if level.value)
_NIST_STATUSES: tuple[str, ...] = tuple(status.name for status in _sdk.NistStatus if status.value)
_FIPS_LEVELS: tuple[str, ...] = tuple(level.name for level in _sdk.Fips140Level if level.value)
_TRUE_FALSE: tuple[str, ...] = ("true", "false")
_HASH_ALGORITHMS: tuple[str, ...] = ("", *(algorithm.name for algorithm in _sdk.HashAlgorithm))
# The MigrateKey strategies the server implements; the others return Unimplemented.
_MIGRATION_STRATEGIES: tuple[str, ...] = ("PROVIDER_SWITCH", "REKEY_AND_ARCHIVE")
_LIFECYCLE_STATES: tuple[str, ...] = (
    "",
    "PRE_ACTIVE",
    "ACTIVE",
    "SUSPENDED",
    "DEACTIVATED",
    "COMPROMISED",
    "DESTROYED",
    "DESTROYED_COMPROMISED",
)

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
        "allowed_templates": ["ecdsa-p256-sha256-der", "ecdsa-p256-prehashed-der", "ml-dsa-65"],
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
        "allowed_templates": [
            "ecdsa-p256-sha256-der",
            "ecdsa-p256-prehashed-der",
            "ecdsa-p384-sha384-der",
            "ml-dsa-65",
        ],
    },
    indent=2,
)
_SAMPLE_NEXTCLOUD_POLICY = json.dumps(
    {
        "version": "1",
        "allowed_operations": {
            "key_operations": ["create_key", "sign", "verify"]
        },
        "allowed_templates": ["ecdsa-p256-sha256-der", "rsa-pkcs1v15-sha256-2048", "ml-dsa-44"],
    },
    indent=2,
)
_SAMPLE_NEXTCLOUD_POLICY_QS = json.dumps(
    {
        "version": "1",
        "allowed_operations": {
            "key_operations": ["create_key", "sign", "verify"]
        },
        "allowed_templates": ["ml-dsa-44"],
    },
    indent=2,
)

# ── Shared scope, security-property and provider-requirement fields ───────────
#
# CreateKeyRequest and TransformKeyRequest carry the same ScopeSpecification
# (a scope, with UniversalSecurityProperties) beside an optional template_id;
# ListTemplates filters by the same specification. ProviderRequirements is on
# CreateKey and on the provider RPCs. Building the fields in one place keeps
# every form that carries a message in lock-step with it.


def _scope_field() -> FormField:
    """The scope of CreateKey and TransformKey: required, even when a template is named."""
    return FormField(
        "scope",
        "Scope",
        kind="dropdown",
        choices=_SCOPE_CHOICES,
        choices_from=SCOPES,
        help=(
            "What the key is for. Always given: a template can serve more than one scope "
            "(ml-dsa-65 serves SIGNATURE_STANDARD and SIGNATURE_WITH_CONTEXT)."
        ),
    )


def _security_property_fields() -> tuple[FormField, ...]:
    """The UniversalSecurityProperties a request can ask for; each one narrows the templates."""
    security = SECTION_SECURITY.key
    return (
        FormField(
            "quantum_safe",
            "Quantum-safe",
            kind="radio",
            choices=_TRUE_FALSE,
            optional=True,
            section=security,
            help="Whether the algorithm must resist attacks by a quantum computer.",
        ),
        FormField(
            "security_strength_bits",
            "Minimum security strength (bits)",
            kind="number",
            optional=True,
            section=security,
            help="At least this classical security strength, e.g. 128, 192 or 256.",
        ),
        FormField(
            "nist_security_level",
            "NIST security level",
            kind="dropdown",
            choices=_NIST_LEVELS,
            optional=True,
            section=security,
            help="At least this NIST post-quantum security level (1 to 5).",
        ),
        FormField(
            "nist_status",
            "NIST status",
            kind="dropdown",
            choices=_NIST_STATUSES,
            optional=True,
            section=security,
            help="The NIST standardisation status the algorithm must have.",
        ),
        FormField(
            "fips_approved",
            "FIPS-approved algorithm",
            kind="radio",
            choices=_TRUE_FALSE,
            optional=True,
            section=security,
            help="Whether the algorithm must be FIPS-approved. A certified module is a provider requirement.",
        ),
    )


def _scope_spec_field() -> FormField:
    """The advanced full-ScopeSpecification JSON override shared by both forms."""
    return FormField(
        "scope_spec",
        "Scope specification (JSON, overrides the scope and security properties)",
        kind="area",
        placeholder='{"signature": {"scope": "SIGNATURE_SCOPE_STANDARD"}}',
        optional=True,
        group=GROUP_ADVANCED,
    )


def _requirement(key: str, label: str, help_text: str) -> FormField:
    return FormField(key, label, kind="bool", optional=True, section=SECTION_REQUIREMENTS.key, help=help_text)


def _provider_requirement_fields() -> tuple[FormField, ...]:
    """The ProviderRequirements a request can set; each one narrows the instances."""
    return (
        _requirement("require_fips_140", "FIPS 140 certified", "The module is FIPS 140-2 or 140-3 certified."),
        FormField(
            "min_fips_level",
            "Minimum FIPS 140 level",
            kind="dropdown",
            choices=_FIPS_LEVELS,
            optional=True,
            section=SECTION_REQUIREMENTS.key,
            help="At least this FIPS 140 level; applies with FIPS 140 certified.",
        ),
        _requirement(
            "require_common_criteria", "Common Criteria certified", "The module is Common Criteria certified."
        ),
        _requirement("require_formally_verified", "Formally verified", "The implementation is formally verified."),
        _requirement("require_memory_safe", "Memory-safe", "Written in a memory-safe language."),
        _requirement("require_constant_time", "Constant-time", "Runs in constant time."),
        _requirement("require_side_channel_hardened", "Side-channel hardened", "Hardened against side channels."),
        _requirement("require_no_known_cve", "No known CVEs", "No known unpatched vulnerabilities."),
        _requirement(
            "prefer_hardware_accelerated",
            "Prefer hardware acceleration",
            "A preference, not a requirement: it reorders the instances that qualify.",
        ),
    )


def _provider_requirements_field() -> FormField:
    """The advanced ProviderRequirements JSON override — CreateKey only."""
    return FormField(
        "provider_requirements",
        "Provider requirements (JSON, overrides the provider requirements above)",
        kind="area",
        placeholder='{"fips_140_certified": true, "min_fips_level": "FIPS_140_LEVEL_3"}',
        optional=True,
        group=GROUP_ADVANCED,
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
            Example(
                "Signing policy: ECDSA and ML-DSA",
                {"name": "demo-signing-policy", "policy_document": _SAMPLE_SIGNING_POLICY, "format": "json"},
            ),
            Example(
                "Encryption policy: AES-256-GCM",
                {"name": "demo-encryption-policy", "policy_document": _SAMPLE_ENCRYPTION_POLICY, "format": "json"},
            ),
            Example(
                "Verify-only policy",
                {"name": "demo-restricted-policy", "policy_document": _SAMPLE_RESTRICTED_POLICY, "format": "json"},
            ),
            Example(
                "FIDO2 Nextcloud authentication policy",
                {"name": "nextcloud-webauthn", "policy_document": _SAMPLE_NEXTCLOUD_POLICY, "format": "json"},
            ),
        ),
    ),
    RpcFormSpec(
        "CryptoPolicyService",
        "ReadCryptoPolicy",
        "Read",
        (FormField("name", "Policy name", placeholder="demo-signing-policy"),),
        examples=(Example("The signing policy", {"name": "demo-signing-policy"}),),
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
        examples=(
            Example(
                "Add ECDSA P-384 to the signing policy",
                {
                    "name": "demo-signing-policy",
                    "policy_document": _SAMPLE_SIGNING_POLICY_V2,
                    "format": "json",
                    "expected_version": 1,
                },
            ),
            Example(
                "Remove ECDSA and RSA",
                {
                    "name": "nextcloud-webauthn",
                    "policy_document": _SAMPLE_NEXTCLOUD_POLICY_QS,
                    "format": "json",
                    "expected_version": 1,
                },
            ),
        ),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "CreateKey",
        "Create",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("policy", "Policy", placeholder="demo-signing-policy"),
            # The scope, security properties and JSON override are shared with TransformKey.
            _scope_field(),
            FormField(
                "template_id",
                "Template ID",
                placeholder="ecdsa-p256-sha256-der",
                optional=True,
                help="Names the exact template, which the policy must allow; blank lets the policy choose.",
            ),
            FormField(
                "provider_id",
                "Provider instance",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_INSTANCES,
                help="Pins the key to this instance; blank lets the server choose.",
            ),
            *_security_property_fields(),
            # Provider requirements — CreateKey only (TransformKeyRequest has none).
            *_provider_requirement_fields(),
            # Advanced escape hatches: a full ScopeSpecification / ProviderRequirements JSON wins.
            _scope_spec_field(),
            _provider_requirements_field(),
        ),
        # From intent, as the API means it: the platform picks the first
        # template in the policy's list that meets the requirements. The last
        # example names everything, to show that works too. The names are the
        # keys the Sign, Encrypt and Digest examples use.
        examples=(
            Example(
                "Signature key",
                {"name": "demo-signing-key", "policy": "demo-signing-policy", "scope": "SIGNATURE_STANDARD"},
            ),
            Example(
                "Signature key, quantum-safe",
                {
                    "name": "demo-pqc-signing-key",
                    "policy": "demo-signing-policy",
                    "scope": "SIGNATURE_STANDARD",
                    "quantum_safe": "true",
                },
            ),
            # DigestSign/DigestVerify need a prehashed-scope key.
            Example(
                "Signature key for digests (prehashed)",
                {"name": "demo-digest-key", "policy": "demo-signing-policy", "scope": "SIGNATURE_PREHASHED"},
            ),
            Example(
                "Encryption key (AEAD)",
                {"name": "demo-encryption-key", "policy": "demo-encryption-policy", "scope": "AEAD_STANDARD"},
            ),
            # fips_approved would filter the algorithm; FIPS 140 custody is a
            # provider requirement, which only openssl-fips meets.
            Example(
                "Quantum-safe key in a FIPS 140 module",
                {
                    "name": "demo-fips-signing-key",
                    "policy": "demo-signing-policy",
                    "scope": "SIGNATURE_STANDARD",
                    "quantum_safe": "true",
                    "require_fips_140": True,
                },
            ),
            Example(
                "Exact template, pinned to software",
                {
                    "name": "demo-pinned-key",
                    "policy": "demo-signing-policy",
                    "scope": "SIGNATURE_STANDARD",
                    "template_id": "ecdsa-p256-sha256-der",
                    "provider_id": "software",
                },
            ),
        ),
        when_unset={
            SECTION_SECURITY.key: "None set: the first template in the policy's list that offers the scope, "
            "unless a template is named.",
            SECTION_REQUIREMENTS.key: "None set: the first instance that implements the template, "
            "within the policy's own provider requirements.",
        },
    ),
    RpcFormSpec(
        "KeyManagementService",
        "ReadKey",
        "Read",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField("version", "Version", kind="number", optional=True),
            FormField(
                "all_versions",
                "Show every version",
                kind="bool",
                help=(
                    "A timeline, oldest first, of each version's template, provider and extractability, "
                    "and what changed. Policy and lifecycle state are the key's, shown once."
                ),
            ),
        ),
        examples=(
            Example("Current version", {"name": "demo-signing-key"}),
            Example("Every version (timeline)", {"name": "demo-signing-key", "all_versions": True}),
        ),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "TransformKey",
        "Transform",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            # The key's scope: a transform may change the algorithm, never the scope.
            _scope_field(),
            FormField(
                "template_id",
                "Template ID",
                placeholder="ml-dsa-65",
                optional=True,
                help="Required when retaining key bytes.",
            ),
            FormField(
                "retain_key_bytes",
                "Retain key bytes",
                kind="bool",
                help=(
                    "Reuse the current key material in a new version instead of generating a new key. "
                    "Requires an explicit template with the same key-material family and shape "
                    "(e.g. ECDSA P-256, RSA-2048, AES-256)."
                ),
            ),
            # The same ScopeSpecification surface as CreateKey (shared builders).
            # TransformKeyRequest has no provider requirements.
            *_security_property_fields(),
            _scope_spec_field(),
        ),
        examples=(
            Example(
                "To a quantum-safe algorithm, by intent",
                {"name": "demo-signing-key", "scope": "SIGNATURE_STANDARD", "quantum_safe": "true"},
            ),
            Example(
                "Rotate: new key material, same template",
                {"name": "demo-pinned-key", "scope": "SIGNATURE_STANDARD", "template_id": "ecdsa-p256-sha256-der"},
            ),
        ),
        when_unset={
            SECTION_SECURITY.key: "None set: the first template in the key's policy that offers the scope, "
            "unless a template is named.",
        },
    ),
    RpcFormSpec(
        "KeyManagementService",
        "MigrateKey",
        "Migrate",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField(
                "strategy",
                "Strategy",
                kind="dropdown",
                choices=_MIGRATION_STRATEGIES,
                help=(
                    "PROVIDER_SWITCH copies the key bytes to the target provider, so data "
                    "protected before the move keeps working unchanged. REKEY_AND_ARCHIVE "
                    "generates a new key on the target; the previous version stays on the "
                    "source provider to decrypt or verify older data."
                ),
            ),
            FormField(
                "target_instance_id",
                "Target provider instance",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_INSTANCES,
                help="A registered instance, e.g. software, openssl, openssl-fips.",
            ),
            FormField(
                "target_provider_id",
                "Target provider type",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_TYPES,
                help=(
                    "Alternative to an instance: the first other instance of this type "
                    "that supports the key's template. Set exactly one target."
                ),
            ),
        ),
        examples=(
            Example(
                "Copy the key to openssl (provider switch)",
                {"name": "demo-encryption-key", "strategy": "PROVIDER_SWITCH", "target_instance_id": "openssl"},
            ),
            Example(
                "New key in the FIPS module, old version archived (rekey)",
                {"name": "demo-signing-key", "strategy": "REKEY_AND_ARCHIVE", "target_instance_id": "openssl-fips"},
            ),
        ),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "ValidateKeyOperation",
        "Check migration",
        (
            FormField("name", "Key name", placeholder="demo-signing-key"),
            FormField(
                "target_instance_id",
                "Target provider instance",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_INSTANCES,
                help="A registered instance, e.g. software, openssl, openssl-fips.",
            ),
            FormField(
                "target_provider_id",
                "Target provider type",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_TYPES,
                help="Alternative to an instance. Set exactly one target.",
            ),
            FormField(
                "preferred_strategy",
                "Preferred strategy",
                kind="dropdown",
                choices=("", *_MIGRATION_STRATEGIES),
                optional=True,
                help="Nothing changes: every strategy is assessed, with why each would or would not work.",
            ),
        ),
        examples=(
            Example("Can it move to openssl?", {"name": "demo-signing-key", "target_instance_id": "openssl"}),
            Example(
                "Can it be copied into the FIPS module?",
                {
                    "name": "demo-signing-key",
                    "target_instance_id": "openssl-fips",
                    "preferred_strategy": "PROVIDER_SWITCH",
                },
            ),
        ),
    ),
    RpcFormSpec(
        "KeyManagementService",
        "ListKeys",
        "List keys",
        (
            FormField(
                "provider_id",
                "Provider instance",
                kind="dropdown",
                optional=True,
                choices_from=PROVIDER_INSTANCES,
            ),
            FormField("policy", "Policy", placeholder="demo-signing-policy", optional=True),
            FormField(
                "lifecycle_state",
                "Lifecycle state",
                kind="dropdown",
                choices=_LIFECYCLE_STATES,
                optional=True,
            ),
            FormField("page_size", "Page size", kind="number", optional=True, help="0 or blank lists every key."),
            FormField("page_token", "Page token", optional=True, help="The next_page_token of the previous page."),
        ),
        examples=(
            Example("Every key"),
            Example("Active keys on openssl", {"provider_id": "openssl", "lifecycle_state": "ACTIVE"}),
        ),
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
            Example("Sign a message", {"key_name": "demo-signing-key", "message": _MESSAGE}),
            Example("Sign with the quantum-safe key", {"key_name": "demo-pqc-signing-key", "message": _MESSAGE}),
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
        # The key only: the bundle comes from the Sign response, and choosing
        # an example leaves a pasted bundle in place.
        examples=(Example("Verify a signature", {"key_name": "demo-signing-key"}),),
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
            Example("Encrypt a message", {"key_name": "demo-encryption-key", "plaintext": "Sensitive demo payload"}),
            Example(
                "Encrypt with additional authenticated data",
                {"key_name": "demo-encryption-key", "plaintext": "Sensitive demo payload", "aad": "context-v1"},
            ),
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
        examples=(
            Example("Decrypt a ciphertext", {"key_name": "demo-encryption-key"}),
            # AAD is not in the bundle: it must be given again, as at Encrypt.
            Example(
                "Decrypt with additional authenticated data", {"key_name": "demo-encryption-key", "aad": "context-v1"}
            ),
        ),
        consumes="Ciphertext",
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestSign",
        "Digest sign",
        (
            FormField("key_name", "Key name (prehashed-scope key)", placeholder="demo-digest-key"),
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
            Example(
                "Sign a SHA-256 digest",
                {"key_name": "demo-digest-key", "digest": _MESSAGE_SHA256, "hash_algorithm": "SHA256"},
            ),
        ),
        produces="Signature",
    ),
    RpcFormSpec(
        "CryptoService",
        "DigestVerify",
        "Digest verify",
        (
            FormField("key_name", "Key name (prehashed-scope key)", placeholder="demo-digest-key"),
            FormField(
                "bundle",
                "Signature bundle (paste from a Digest sign response)",
                kind="area",
                placeholder='{"key_name": "...", "signature": "...", "metadata": {...}, "digest": "..."}',
                optional=True,
            ),
            FormField("digest", "Digest (base64)", kind="area"),
            FormField(
                "domain_context",
                "Domain context (text, must match sign)",
                placeholder="e.g. prehash domain separation",
                optional=True,
            ),
            FormField("signature", "Signature (base64)", kind="area", group=GROUP_MANUAL),
            # The metadata carries the digest hash recorded by Digest sign.
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
        examples=(Example("Verify a digest signature", {"key_name": "demo-digest-key", "digest": _MESSAGE_SHA256}),),
        consumes="Signature",
    ),
    # ── Catalogue: templates, scopes, providers ──────────────────────────────
    RpcFormSpec(
        "AlgorithmDiscoveryService",
        "ListTemplates",
        "List templates",
        (
            FormField(
                "scope",
                "Scope",
                kind="dropdown",
                choices=_SCOPE_CHOICES,
                optional=True,
                choices_from=SCOPES,
                help=(
                    "Keeps the templates that offer this scope: the same match CreateKey applies. "
                    "Security properties need a scope."
                ),
            ),
            FormField(
                "allowed_statuses",
                "Statuses",
                placeholder="ACTIVE, EXPERIMENTAL",
                optional=True,
                help="Comma-separated; blank lists every status.",
            ),
            FormField("required_standard", "Required standard", placeholder="FIPS 204", optional=True),
            FormField("page_size", "Page size", kind="number", optional=True, help="0 or blank lists every template."),
            FormField("page_token", "Page token", optional=True, help="The next_page_token of the previous page."),
            *_security_property_fields(),
        ),
        examples=(
            Example("Every template"),
            Example("Quantum-safe signature templates", {"scope": "SIGNATURE_STANDARD", "quantum_safe": "true"}),
            Example(
                "FIPS-approved AEAD templates",
                {"scope": "AEAD_STANDARD", "allowed_statuses": "ACTIVE", "fips_approved": "true"},
            ),
        ),
        when_unset={SECTION_SECURITY.key: "None set: every template of the scope."},
    ),
    RpcFormSpec(
        "AlgorithmDiscoveryService",
        "GetTemplate",
        "Get template",
        (FormField("template_id", "Template ID", placeholder="ml-dsa-65"),),
        examples=(
            Example("ML-DSA-65", {"template_id": "ml-dsa-65"}),
            Example("AES-256-GCM", {"template_id": "aes-256-gcm-128-96"}),
        ),
        subject="template_id",
    ),
    RpcFormSpec(
        "AlgorithmDiscoveryService",
        "ListScopes",
        "List scopes",
        (),
    ),
    RpcFormSpec(
        "ProviderService",
        "MatchProviders",
        "Match providers",
        (
            FormField(
                "template_id",
                "Template ID",
                placeholder="aes-256-gcm-128-96",
                help=(
                    "Required. The first match is the instance CreateKey would choose for this template, "
                    "unless the key's policy adds provider requirements (MatchProviders does not apply policy)."
                ),
            ),
            *_provider_requirement_fields(),
        ),
        examples=(
            Example("Who can hold an AES-256-GCM key", {"template_id": "aes-256-gcm-128-96"}),
            Example(
                "AES-256-GCM key in a FIPS 140 module",
                {"template_id": "aes-256-gcm-128-96", "require_fips_140": True},
            ),
            Example(
                "AES-256-GCM key, preferring hardware acceleration",
                {"template_id": "aes-256-gcm-128-96", "prefer_hardware_accelerated": True},
            ),
        ),
        subject="template_id",
        when_unset={SECTION_REQUIREMENTS.key: "None set: every instance that implements the template, best first."},
    ),
    RpcFormSpec(
        "ProviderService",
        "ListProviderInstances",
        "List instances",
        (
            FormField("provider_id", "Provider", kind="dropdown", optional=True, choices_from=PROVIDER_TYPES),
            FormField("page_size", "Page size", kind="number", optional=True),
            FormField("page_token", "Page token", optional=True),
            *_provider_requirement_fields(),
        ),
        examples=(
            Example("Every instance"),
            Example("Memory-safe instances", {"require_memory_safe": True}),
            Example("FIPS 140 instances", {"require_fips_140": True}),
        ),
        when_unset={SECTION_REQUIREMENTS.key: "None set: every instance."},
    ),
    RpcFormSpec(
        "ProviderService",
        "GetProviderInstance",
        "Get instance",
        (FormField("instance_id", "Instance ID", kind="dropdown", choices_from=PROVIDER_INSTANCES),),
        examples=(
            Example("The pure-Go software provider", {"instance_id": "software"}),
            Example("OpenSSL", {"instance_id": "openssl"}),
            Example("OpenSSL with the FIPS module", {"instance_id": "openssl-fips"}),
        ),
    ),
    RpcFormSpec(
        "ProviderService",
        "ListProviders",
        "List providers",
        (
            FormField("template_id", "Template ID", placeholder="ml-dsa-65", optional=True),
            FormField("page_size", "Page size", kind="number", optional=True),
            FormField("page_token", "Page token", optional=True),
            *_provider_requirement_fields(),
        ),
        examples=(
            Example("Every provider"),
            Example("Providers that implement ML-DSA-65", {"template_id": "ml-dsa-65"}),
        ),
        subject="template_id",
        when_unset={SECTION_REQUIREMENTS.key: "None set: every provider."},
    ),
    RpcFormSpec(
        "ProviderService",
        "GetProvider",
        "Get provider",
        (FormField("provider_id", "Provider ID", kind="dropdown", choices_from=PROVIDER_TYPES),),
        examples=(
            Example("OpenSSL", {"provider_id": "openssl"}),
            Example("The pure-Go software provider", {"provider_id": "software"}),
        ),
        subject="provider_id",
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
