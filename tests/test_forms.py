from __future__ import annotations

import pytest

from citius_ui.workbench.forms import FORMS_BY_METHOD, FormValidationError, build_request


def test_build_request_drops_empty_and_none() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    values: list[object] = ["demo-key", "demo-policy", *([""] * (len(spec.fields) - 2))]
    request = build_request(spec, values)
    assert request == {"name": "demo-key", "policy": "demo-policy"}


def _values_for(spec: object, **by_key: object) -> list[object]:
    """Build a positional value list for a form, setting named fields by key."""
    return [by_key.get(field.key, "") for field in spec.fields]  # type: ignore[attr-defined]


def test_build_request_parses_metadata_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Verify")]
    values = _values_for(spec, key_name="demo-key", message="msg", signature="c2ln", metadata='{"key_version": 3}')
    request = build_request(spec, values)
    assert request["metadata"] == {"key_version": 3}
    assert request["signature"] == "c2ln"


def test_build_request_rejects_invalid_metadata_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Decrypt")]
    values = _values_for(spec, key_name="demo-key", ciphertext="ct", metadata="not json")
    with pytest.raises(FormValidationError, match="must be valid JSON"):
        build_request(spec, values)


def test_build_request_rejects_non_object_metadata() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Decrypt")]
    values = _values_for(spec, key_name="demo-key", ciphertext="ct", metadata="[1, 2]")
    with pytest.raises(FormValidationError, match="JSON object"):
        build_request(spec, values)


def test_build_request_strips_surrounding_whitespace() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    values: list[object] = ["  demo-key  ", "demo-policy", *(["  "] * (len(spec.fields) - 2))]
    request = build_request(spec, values)
    assert request == {"name": "demo-key", "policy": "demo-policy"}


def test_build_request_rejects_non_numeric_number_field() -> None:
    spec = FORMS_BY_METHOD[("CryptoPolicyService", "UpdateCryptoPolicy")]
    with pytest.raises(FormValidationError, match="must be a number"):
        build_request(spec, ["demo-policy", "doc", "yaml", "two"])


def test_build_request_coerces_number_fields() -> None:
    spec = FORMS_BY_METHOD[("CryptoPolicyService", "UpdateCryptoPolicy")]
    request = build_request(spec, ["demo-policy", "doc", "yaml", 2.0])
    assert request["expected_version"] == 2
    assert isinstance(request["expected_version"], int)


def test_forms_field_keys_align_with_action_request_keys() -> None:
    # Field keys must match the request keys the actions read.
    expected = {
        ("CryptoService", "Sign"): {"key_name", "message", "domain_context", "scope_params"},
        ("CryptoService", "Encrypt"): {"key_name", "plaintext", "aad", "scope_params"},
        ("CryptoPolicyService", "CreateCryptoPolicy"): {"name", "policy_document", "format"},
    }
    for key, keys in expected.items():
        spec = FORMS_BY_METHOD[key]
        assert {field.key for field in spec.fields} == keys


def test_create_key_form_exposes_friendly_scope_and_filter_fields() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    keys = {field.key for field in spec.fields}
    # Scope + security-property filters + provider-requirement toggles.
    assert {"scope", "nist_security_level", "quantum_safe", "fips_approved"} <= keys
    assert {"require_fips_140", "min_fips_level", "require_memory_safe"} <= keys
    # Advanced JSON escape hatches remain.
    assert {"scope_spec", "provider_requirements"} <= keys


def test_digest_sign_form_exposes_hash_algorithm() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "DigestSign")]
    assert "hash_algorithm" in {field.key for field in spec.fields}


def test_digest_verify_form_takes_the_hash_from_metadata() -> None:
    # The server reads the digest hash from the signature's operation
    # metadata, so DigestVerify offers no hash field of its own.
    spec = FORMS_BY_METHOD[("CryptoService", "DigestVerify")]
    keys = {field.key for field in spec.fields}
    assert "hash_algorithm" not in keys
    assert "metadata" in keys


def test_create_and_transform_key_share_the_scope_selection_fields() -> None:
    # The proto puts the same ScopeSpecification surface on both requests, so
    # the UI shares those fields from one builder. This guards that they stay
    # in lock-step: any scope/security field added to the shared builders must
    # appear in BOTH forms.
    shared = {"scope", "security_strength_bits", "nist_security_level", "nist_status", "quantum_safe", "fips_approved"}
    create = {field.key for field in FORMS_BY_METHOD[("KeyManagementService", "CreateKey")].fields}
    transform = {field.key for field in FORMS_BY_METHOD[("KeyManagementService", "TransformKey")].fields}
    assert shared <= create
    assert shared <= transform
    # Both expose the advanced scope_spec JSON escape hatch.
    assert "scope_spec" in create
    assert "scope_spec" in transform
    # provider_requirements is CreateKey-only (no arm on TransformKeyRequest).
    assert "provider_requirements" in create
    assert "provider_requirements" not in transform


def test_create_key_groups_filters_into_intuitive_sections() -> None:
    from citius_ui.workbench.forms import GROUP_ADVANCED, GROUP_PROVIDER, GROUP_UNIVERSAL

    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    # Core fields stay ungrouped and up front.
    core = {field.key for field in spec.core_fields()}
    assert core == {"name", "policy", "template_id", "provider_id", "scope"}
    groups = dict(spec.grouped_fields())
    assert {group for group, _ in spec.grouped_fields()} == {GROUP_UNIVERSAL, GROUP_PROVIDER, GROUP_ADVANCED}
    assert {f.key for f in groups[GROUP_UNIVERSAL]} == {
        "security_strength_bits",
        "nist_security_level",
        "nist_status",
        "quantum_safe",
        "fips_approved",
    }
    assert {f.key for f in groups[GROUP_PROVIDER]} == {
        "require_fips_140",
        "min_fips_level",
        "require_memory_safe",
        "require_constant_time",
        "require_side_channel_hardened",
        "require_no_known_cve",
        "prefer_hardware_accelerated",
    }
    assert {f.key for f in groups[GROUP_ADVANCED]} == {"scope_spec", "provider_requirements"}


def test_grouped_fields_preserve_full_field_set_and_order() -> None:
    # Every field is either core or grouped exactly once, and concatenating
    # core + grouped covers all fields (order within each is preserved).
    for spec in FORMS_BY_METHOD.values():
        grouped = [field for _, fields in spec.grouped_fields() for field in fields]
        combined = {field.key for field in spec.core_fields()} | {field.key for field in grouped}
        assert combined == {field.key for field in spec.fields}
        assert len(spec.core_fields()) + len(grouped) == len(spec.fields)


def test_crypto_scope_params_are_grouped_as_advanced() -> None:
    from citius_ui.workbench.forms import GROUP_ADVANCED

    for method in ("Sign", "Verify", "Encrypt", "Decrypt", "DigestSign", "DigestVerify"):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        scope_params = next(field for field in spec.fields if field.key == "scope_params")
        assert scope_params.group == GROUP_ADVANCED


def test_consumer_value_and_metadata_are_demoted_to_manual_section() -> None:
    from citius_ui.workbench.forms import GROUP_MANUAL

    # Verify/Decrypt/DigestVerify take a pasted bundle up front; their opaque
    # value + metadata fields are demoted to the manual advanced section.
    for method, value_key in (("Verify", "signature"), ("Decrypt", "ciphertext"), ("DigestVerify", "signature")):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        by_key = {field.key: field for field in spec.fields}
        assert by_key[value_key].group == GROUP_MANUAL
        assert by_key["metadata"].group == GROUP_MANUAL
        # The user-supplied inputs stay core (up front, not grouped).
        assert by_key["key_name"].group == ""


def test_consumers_expose_a_core_bundle_paste_field() -> None:
    # Verify/Decrypt/DigestVerify accept the producer's copyable bundle as a
    # single core input; the server merges it into the split fields.
    for method in ("Verify", "Decrypt", "DigestVerify"):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        by_key = {field.key: field for field in spec.fields}
        assert "bundle" in by_key, method
        assert by_key["bundle"].group == "", method
        assert by_key["bundle"].optional is True, method


def test_transform_key_explains_and_exemplifies_retain_key_bytes() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "TransformKey")]
    fields = {field.key: field for field in spec.fields}
    assert "template" in fields["retain_key_bytes"].help
    assert fields["template_id"].help
    keys = [field.key for field in spec.fields]
    retain_examples = [example for example in spec.examples if example[keys.index("retain_key_bytes")] is True]
    assert retain_examples, "a retain-mode example is expected"
    for example in retain_examples:
        assert example[keys.index("template_id")], "retain examples must name a target template"
        assert len(example) == len(keys)


def test_digest_forms_use_a_prehashed_key_created_by_an_example() -> None:
    # The catalog declares DigestSign/DigestVerify only on prehashed scopes, so
    # the digest examples must target a key created with a prehashed template.
    create = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    keys = [field.key for field in create.fields]
    created = {
        example[keys.index("name")]: (example[keys.index("template_id")], example[keys.index("scope")])
        for example in create.examples
    }
    for method in ("DigestSign", "DigestVerify"):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        key_index = [field.key for field in spec.fields].index("key_name")
        for example in spec.examples:
            template_id, scope = created[example[key_index]]
            assert "prehashed" in template_id
            assert scope == "SIGNATURE_PREHASHED"
