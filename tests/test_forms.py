from __future__ import annotations

import pytest

from citius_ui.workbench.forms import FORMS_BY_METHOD, FormValidationError, build_request


def test_build_request_drops_empty_and_none() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    values: list[object] = ["demo-key", "demo-policy", *([""] * (len(spec.fields) - 2))]
    request = build_request(spec, values)
    assert request == {"name": "demo-key", "policy": "demo-policy"}


def test_build_request_parses_metadata_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Verify")]
    values: list[object] = ["demo-key", "msg", "c2ln", '{"key_version": 3}', *([""] * (len(spec.fields) - 4))]
    request = build_request(spec, values)
    assert request["metadata"] == {"key_version": 3}
    assert request["signature"] == "c2ln"


def test_build_request_rejects_invalid_metadata_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Decrypt")]
    values: list[object] = ["demo-key", "ct", "not json", *([""] * (len(spec.fields) - 3))]
    with pytest.raises(FormValidationError, match="must be valid JSON"):
        build_request(spec, values)


def test_build_request_rejects_non_object_metadata() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Decrypt")]
    values: list[object] = ["demo-key", "ct", "[1, 2]", *([""] * (len(spec.fields) - 3))]
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
