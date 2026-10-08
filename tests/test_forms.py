from __future__ import annotations

import pytest

from citius_ui.workbench.forms import FORMS_BY_METHOD, Example, FormField, FormValidationError, build_request


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


def test_create_key_puts_properties_in_sections_and_json_overrides_in_advanced() -> None:
    from citius_ui.workbench.forms import GROUP_ADVANCED, SECTION_REQUIREMENTS, SECTION_SECURITY

    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    # The key's identity, its required scope, and the optional pins stay up front.
    assert [field.key for field in spec.core_fields()] == ["name", "policy", "scope", "template_id", "provider_id"]
    sections = {section.key: {f.key for f in fields} for section, fields in spec.sections()}
    assert sections == {
        SECTION_SECURITY.key: {
            "quantum_safe",
            "security_strength_bits",
            "nist_security_level",
            "nist_status",
            "fips_approved",
        },
        SECTION_REQUIREMENTS.key: {
            "require_fips_140",
            "min_fips_level",
            "require_common_criteria",
            "require_formally_verified",
            "require_memory_safe",
            "require_constant_time",
            "require_side_channel_hardened",
            "require_no_known_cve",
            "prefer_hardware_accelerated",
        },
    }
    groups = dict(spec.grouped_fields())
    assert set(groups) == {GROUP_ADVANCED}
    assert {f.key for f in groups[GROUP_ADVANCED]} == {"scope_spec", "provider_requirements"}


def test_every_field_is_core_grouped_or_in_one_section_exactly_once() -> None:
    for spec in FORMS_BY_METHOD.values():
        grouped = [field for _, fields in spec.grouped_fields() for field in fields]
        sectioned = [field for _, fields in spec.sections() for field in fields]
        parts = [*spec.core_fields(), *grouped, *sectioned]
        assert sorted(f.key for f in parts) == sorted(f.key for f in spec.fields), spec.method
        assert not any(field.group and field.section for field in spec.fields), spec.method


def test_section_properties_are_optional_and_each_section_says_what_none_set_means() -> None:
    for spec in FORMS_BY_METHOD.values():
        keys = {section.key for section, _ in spec.sections()}
        # Every section the form has explains its empty state, and only those.
        assert set(spec.when_unset) == keys, spec.method
        assert all(text.startswith("None set: ") for text in spec.when_unset.values()), spec.method
        for _, fields in spec.sections():
            for field in fields:
                assert field.optional and field.help, (spec.method, field.key)
                # A property is set or not; no choice stands for "unset".
                assert "" not in field.choices, (spec.method, field.key)


def test_the_property_sections_are_on_the_rpcs_that_carry_those_messages() -> None:
    from citius_ui.workbench.forms import SECTION_REQUIREMENTS, SECTION_SECURITY

    def has(service: str, method: str) -> set[str]:
        return {section.key for section, _ in FORMS_BY_METHOD[(service, method)].sections()}

    both = {SECTION_SECURITY.key, SECTION_REQUIREMENTS.key}
    assert has("KeyManagementService", "CreateKey") == both
    assert has("KeyManagementService", "TransformKey") == {SECTION_SECURITY.key}
    assert has("AlgorithmDiscoveryService", "ListTemplates") == {SECTION_SECURITY.key}
    for method in ("MatchProviders", "ListProviderInstances", "ListProviders"):
        assert has("ProviderService", method) == {SECTION_REQUIREMENTS.key}, method


def test_key_scope_is_required_and_not_preset() -> None:
    for method in ("CreateKey", "TransformKey"):
        scope = next(f for f in FORMS_BY_METHOD[("KeyManagementService", method)].fields if f.key == "scope")
        assert not scope.optional, method
        assert "infer" not in scope.label.lower() and "infer" not in scope.help.lower(), method
        # A fresh form leaves the scope for the user to choose.
        assert scope.choices[0] == ""
        assert "SIGNATURE_WITH_CONTEXT" in scope.choices


def test_is_set_and_value_when_added() -> None:
    from citius_ui.workbench.forms import FormField, is_set, value_when_added

    box = FormField("require_fips_140", "FIPS", kind="bool", optional=True)
    yes_no = FormField("quantum_safe", "QS", kind="radio", choices=("true", "false"), optional=True)
    number = FormField("security_strength_bits", "Bits", kind="number", optional=True)
    level = FormField("nist_security_level", "Level", kind="dropdown", choices=("LEVEL_1",), optional=True)
    assert (is_set(box, True), is_set(box, False), is_set(box, None)) == (True, False, False)
    assert (is_set(yes_no, "false"), is_set(yes_no, None), is_set(yes_no, " ")) == (True, False, False)
    assert (is_set(number, 0), is_set(number, None)) == (True, False)
    # Adding a requirement ticks it and a yes/no property says yes; a range starts blank.
    assert value_when_added(box) is True
    assert value_when_added(yes_no) == "true"
    assert value_when_added(number) is None
    assert value_when_added(level) == ""


def test_every_section_property_reaches_its_api_message() -> None:
    # Each property field sets exactly the API field it stands for, so none is
    # shown in the form and then lost on the way to the request.
    from citius_ui.workbench.actions import _provider_requirements, _security_properties
    from citius_ui.workbench.forms import SECTION_REQUIREMENTS, SECTION_SECURITY

    def sample(field: FormField) -> object:
        if field.kind == "bool":
            return True
        if field.kind == "number":
            return 256
        # The last choice: "false" for a yes/no property, so a lone false is sent too.
        return field.choices[-1]

    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    for section, fields in spec.sections():
        for field in fields:
            value = sample(field)
            if section is SECTION_REQUIREMENTS:
                built = _provider_requirements({field.key: value})
                assert built is not None, field.key
                assert built.ListFields(), field.key
            else:
                assert section is SECTION_SECURITY
                assert _security_properties({field.key: value}) is not None, field.key


def test_grouped_fields_keep_the_advanced_and_manual_sections() -> None:
    from citius_ui.workbench.forms import GROUP_ADVANCED

    for method in ("CreateKey", "TransformKey"):
        groups = dict(FORMS_BY_METHOD[("KeyManagementService", method)].grouped_fields())
        assert "scope_spec" in {f.key for f in groups[GROUP_ADVANCED]}


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
    for example in spec.examples:
        if example.values.get("retain_key_bytes"):
            assert example.values.get("template_id"), "retain examples must name a target template"


def test_digest_forms_use_a_prehashed_key_created_by_an_example() -> None:
    # The catalog declares DigestSign/DigestVerify only on prehashed scopes, so
    # the digest examples must target a key created with a prehashed scope.
    create = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    scopes = {example.values["name"]: example.values.get("scope") for example in create.examples}
    for method in ("DigestSign", "DigestVerify"):
        spec = FORMS_BY_METHOD[("CryptoService", method)]
        for example in spec.examples:
            assert scopes[example.values["key_name"]] == "SIGNATURE_PREHASHED"


def test_migrate_key_offers_the_implemented_strategies_with_one_target_per_example() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "MigrateKey")]
    fields = {field.key: field for field in spec.fields}
    assert fields["strategy"].choices == ("PROVIDER_SWITCH", "REKEY_AND_ARCHIVE")
    assert {example.values["strategy"] for example in spec.examples} == set(fields["strategy"].choices)
    for example in spec.examples:
        targets = [example.values.get("target_instance_id"), example.values.get("target_provider_id")]
        assert sum(bool(t) for t in targets) == 1, example


def test_every_implemented_rpc_has_a_form_whose_examples_fit() -> None:
    from citius_ui.workbench.actions import IMPLEMENTED

    for service, methods in IMPLEMENTED.items():
        for method in methods:
            spec = FORMS_BY_METHOD.get((service, method))
            assert spec is not None, f"{service}.{method} has no form"
            for example in spec.examples:
                assert example.text, method
                # Raises on a key the form does not have.
                assert len(spec.example_values(example)) == len(spec.fields), method


def test_example_values_fill_unset_fields_like_a_fresh_form() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "MigrateKey")]
    values = dict(zip([f.key for f in spec.fields], spec.example_values(Example("x")), strict=True))
    assert values == {
        "name": "",
        "strategy": "PROVIDER_SWITCH",  # a required dropdown shows its first choice
        "target_instance_id": "",
        "target_provider_id": "",
    }
    read = FORMS_BY_METHOD[("KeyManagementService", "ReadKey")]
    assert read.example_values(Example("x", {"name": "k"})) == ["k", None, False]


def test_example_values_reject_a_field_the_form_does_not_have() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "ReadKey")]
    with pytest.raises(ValueError, match="nme"):
        spec.example_values(Example("typo", {"nme": "k"}))


def test_example_rows_name_the_subject_of_each_example() -> None:
    create = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    headers, rows = create.example_rows()
    assert headers == ["Key name", "Example"]
    assert ["demo-signing-key", "Signature key"] in rows

    providers = FORMS_BY_METHOD[("ProviderService", "ListProviders")]
    headers, rows = providers.example_rows()
    assert headers == ["Template ID", "Example"]
    assert rows[0] == ["—", "Every provider"]

    keys = FORMS_BY_METHOD[("KeyManagementService", "ListKeys")]
    headers, rows = keys.example_rows()
    assert headers == ["Example"]
    assert rows == [["Every key"], ["Active keys on openssl"]]


def test_choosing_a_consumer_example_keeps_a_pasted_bundle() -> None:
    from citius_ui.workbench.app import _example_loader

    spec = FORMS_BY_METHOD[("CryptoService", "Verify")]
    values = dict(zip([f.key for f in spec.fields], _example_loader(spec)(0), strict=True))
    assert values["key_name"] == "demo-signing-key"
    assert values["bundle"] == {"__type__": "update"}  # left as it is
    assert values["message"] == ""


def test_a_one_field_example_fills_the_field_with_the_bare_value() -> None:
    from citius_ui.workbench.app import _example_loader

    spec = FORMS_BY_METHOD[("CryptoPolicyService", "ReadCryptoPolicy")]
    assert len(spec.fields) == 1
    assert _example_loader(spec)(0) == "demo-signing-policy"
