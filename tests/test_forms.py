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


def test_digest_forms_expose_hash_algorithm() -> None:
    for method in ("DigestSign", "DigestVerify"):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        assert "hash_algorithm" in {field.key for field in spec.fields}


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
