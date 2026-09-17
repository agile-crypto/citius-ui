from __future__ import annotations

from citius_ui.workbench.forms import FORMS_BY_METHOD, build_request


def test_build_request_drops_empty_and_none() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    request = build_request(spec, ["demo-key", "demo-policy", "", None])
    assert request == {"name": "demo-key", "policy": "demo-policy"}


def test_build_request_parses_metadata_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Verify")]
    request = build_request(spec, ["demo-key", "msg", "c2ln", '{"key_version": 3}'])
    assert request["metadata"] == {"key_version": 3}
    assert request["signature"] == "c2ln"


def test_build_request_keeps_metadata_text_when_invalid_json() -> None:
    spec = FORMS_BY_METHOD[("CryptoService", "Decrypt")]
    request = build_request(spec, ["demo-key", "ct", "not json"])
    assert request["metadata"] == "not json"


def test_build_request_coerces_number_fields() -> None:
    spec = FORMS_BY_METHOD[("CryptoPolicyService", "UpdateCryptoPolicy")]
    request = build_request(spec, ["demo-policy", "doc", "yaml", 2.0])
    assert request["expected_version"] == 2
    assert isinstance(request["expected_version"], int)


def test_forms_field_keys_align_with_action_request_keys() -> None:
    # Field keys must match the request keys the actions read.
    expected = {
        ("CryptoService", "Sign"): {"key_name", "message"},
        ("CryptoService", "Encrypt"): {"key_name", "plaintext"},
        ("KeyManagementService", "CreateKey"): {"name", "policy", "template_id", "provider_id"},
        ("CryptoPolicyService", "CreateCryptoPolicy"): {"name", "policy_document", "format"},
    }
    for key, keys in expected.items():
        spec = FORMS_BY_METHOD[key]
        assert {field.key for field in spec.fields} == keys
