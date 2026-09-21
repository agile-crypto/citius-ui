from __future__ import annotations

import base64

import grpc
import pytest
from citius_sdk.errors import AuthenticationError, FailedPreconditionError, PermissionDeniedError

from citius_ui.actions.model import Availability, ResultStatus
from citius_ui.grpc_client.serialization import encode_bytes, error_result
from citius_ui.workbench.actions import CONTRACT_ONLY, IMPLEMENTED, registry_overview


def test_registry_overview_marks_implemented_and_contract_only() -> None:
    overview = registry_overview()
    crypto = dict(overview["CryptoService"])
    assert crypto["Sign"] is Availability.AVAILABLE
    assert crypto["GenerateMAC"] is Availability.UNIMPLEMENTED
    keys = dict(overview["KeyManagementService"])
    assert keys["CreateKey"] is Availability.AVAILABLE
    assert keys["RotateKey"] is Availability.UNIMPLEMENTED


def test_implemented_and_contract_only_do_not_overlap() -> None:
    for service, methods in IMPLEMENTED.items():
        contract = set(CONTRACT_ONLY.get(service, []))
        assert contract.isdisjoint(methods)


def test_encode_bytes_renders_base64_hex_and_utf8() -> None:
    rendered = encode_bytes(b"hi")
    assert rendered["base64"] == base64.b64encode(b"hi").decode()
    assert rendered["hex"] == "6869"
    assert rendered["utf8"] == "hi"


def test_encode_bytes_omits_utf8_for_binary() -> None:
    rendered = encode_bytes(b"\xff\xfe")
    assert "utf8" not in rendered


def test_error_result_maps_authentication() -> None:
    result = error_result(AuthenticationError(grpc.StatusCode.UNAUTHENTICATED, "no token"))
    assert result.status is ResultStatus.UNAUTHENTICATED


def test_error_result_distinguishes_resource_denial() -> None:
    method_denied = error_result(PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "missing citius:crypto:sign"))
    resource_denied = error_result(
        PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "cannot access resource 'demo-x'")
    )
    assert method_denied.denial_reason == "method_permission"
    assert resource_denied.denial_reason == "resource_pattern"


def test_error_result_maps_failed_precondition() -> None:
    result = error_result(FailedPreconditionError(grpc.StatusCode.FAILED_PRECONDITION, "policy"))
    assert result.status is ResultStatus.FAILED_PRECONDITION


def test_base64_field_rejects_invalid_input_with_field_name() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _base64_field

    with pytest.raises(RequestError, match="'signature' is not valid base64"):
        _base64_field({"signature": "not base64!!"}, "signature")


def test_base64_field_tolerates_pasted_whitespace() -> None:
    from citius_ui.workbench.actions import _base64_field

    assert _base64_field({"digest": " c2ln\n "}, "digest") == b"sig"


def test_metadata_proto_rejects_invalid_json() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _metadata_proto

    with pytest.raises(RequestError, match="not valid JSON"):
        _metadata_proto("not json")


def test_normalized_maps_missing_field_to_invalid_argument() -> None:
    import asyncio

    from citius_ui.actions.model import ResultStatus, RpcResult
    from citius_ui.workbench.actions import _normalized, _require_text

    async def invoke(request: dict[str, object]) -> RpcResult:
        _require_text(request, "key_name")
        return RpcResult(status=ResultStatus.OK)

    result = asyncio.run(_normalized(invoke)({}))
    assert result.status is ResultStatus.INVALID_ARGUMENT
    assert "'key_name' is required" in result.message


def test_normalized_maps_unexpected_error_to_unavailable() -> None:
    import asyncio

    from citius_ui.actions.model import ResultStatus, RpcResult
    from citius_ui.workbench.actions import _normalized

    async def invoke(request: dict[str, object]) -> RpcResult:
        raise RuntimeError("channel closed")

    result = asyncio.run(_normalized(invoke)({}))
    assert result.status is ResultStatus.UNAVAILABLE
    assert "channel closed" in result.message


def test_policy_document_rejects_non_json_with_schema_hint() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _policy_document

    request = {"policy_document": "version: v1\nallowed_operations: [SIGN]", "format": "json"}
    with pytest.raises(RequestError, match="not valid JSON.*allowed_operations"):
        _policy_document(request)


def test_policy_document_defaults_to_json_validation() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _policy_document

    with pytest.raises(RequestError, match="not valid JSON"):
        _policy_document({"policy_document": "not json"})


def test_policy_document_passes_other_formats_through() -> None:
    from citius_ui.workbench.actions import _policy_document

    document = "package citius\nallow = true"
    assert _policy_document({"policy_document": document, "format": "rego"}) == document


def test_policy_form_examples_are_valid_server_rules_json() -> None:
    import json as jsonlib

    from citius_ui.workbench.forms import FORMS_BY_METHOD

    known_operations = {
        "create_key",
        "read_key",
        "delete_key",
        "sign",
        "verify",
        "digest_sign",
        "digest_verify",
        "encrypt",
        "decrypt",
        "wrap",
        "unwrap",
        "derive_key",
        "rotate_key",
    }
    for method in ("CreateCryptoPolicy", "UpdateCryptoPolicy"):
        spec = FORMS_BY_METHOD[("CryptoPolicyService", method)]
        for example in spec.examples:
            document = jsonlib.loads(str(example[1]))
            # Matches the server's rules_json schema and validation rules.
            assert document["version"] == "1"
            operations = document["allowed_operations"]["key_operations"]
            assert operations and set(operations) <= known_operations
            assert document["allowed_templates"]


def test_key_scope_spec_infers_from_template() -> None:
    from citius_ui.workbench.actions import _key_scope_spec

    assert _key_scope_spec({"template_id": "ecdsa-p256-sha256-der"}).WhichOneof("scope_spec") == "signature"
    assert _key_scope_spec({"template_id": "aes-256-gcm-128-96"}).WhichOneof("scope_spec") == "aead"
    assert _key_scope_spec({"template_id": "chacha20-poly1305"}).WhichOneof("scope_spec") == "aead"
    prehashed = _key_scope_spec({"template_id": "ecdsa-p256-prehashed-der"})
    assert prehashed.signature.scope == 3  # SIGNATURE_SCOPE_PREHASHED


def test_key_scope_spec_explicit_scope_wins() -> None:
    from citius_ui.workbench.actions import _key_scope_spec

    spec = _key_scope_spec({"template_id": "aes-256-gcm-128-96", "scope": "signature"})
    assert spec.WhichOneof("scope_spec") == "signature"


def test_key_scope_spec_requires_scope_when_uninferable() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _key_scope_spec

    with pytest.raises(RequestError, match="'scope' is required"):
        _key_scope_spec({})
    with pytest.raises(RequestError, match="cannot infer"):
        _key_scope_spec({"template_id": "hkdf-sha256"})
    with pytest.raises(RequestError, match="unsupported scope"):
        _key_scope_spec({"scope": "teleport"})


def _sign_request_proto() -> object:
    from citius_sdk.services.crypto import SignRequest

    return SignRequest(key_name="k", input=b"m")


def test_finalize_scope_params_defaults_to_no_context() -> None:
    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _finalize_scope_params

    built = _sign_request_proto()
    _finalize_scope_params(built, {}, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
    assert built.WhichOneof("scope_params") == "no_context"


def test_finalize_scope_params_selects_domain_context() -> None:
    import base64 as b64

    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _finalize_scope_params

    built = _sign_request_proto()
    context = b64.b64encode(b"tenant-a").decode()
    request = {"scope_params": f'{{"domain_context": {{"context": "{context}"}}}}'}
    _finalize_scope_params(built, request, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
    assert built.WhichOneof("scope_params") == "domain_context"
    assert built.domain_context.context == b"tenant-a"


def test_finalize_scope_params_sets_aead_aad() -> None:
    import base64 as b64

    from citius_sdk.services.crypto import EncryptRequest

    from citius_ui.workbench.actions import ENCRYPTION_SCOPE_PARAM_KEYS, _finalize_scope_params

    built = EncryptRequest(key_name="k", plaintext=b"p")
    aad = b64.b64encode(b"header").decode()
    request = {"scope_params": {"aead_params": {"aad": aad}}}
    _finalize_scope_params(built, request, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params")
    assert built.WhichOneof("scope_params") == "aead_params"
    assert built.aead_params.aad == b"header"


def test_finalize_scope_params_rejects_unknown_and_invalid() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _finalize_scope_params

    built = _sign_request_proto()

    def apply(scope_params: object) -> None:
        _finalize_scope_params(
            built, {"scope_params": scope_params}, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context"
        )

    with pytest.raises(RequestError, match="unknown scope parameter"):
        apply({"aead_params": {}})
    with pytest.raises(RequestError, match="not valid JSON"):
        apply("{bad")
    with pytest.raises(RequestError, match="does not match the request schema"):
        apply({"domain_context": {"nope": 1}})


def test_key_scope_spec_accepts_full_scope_spec_json() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import _key_scope_spec

    spec = _key_scope_spec({"scope_spec": '{"aead": {"scope": "AEAD_SCOPE_STANDARD"}}'})
    assert spec.WhichOneof("scope_spec") == "aead"
    # The explicit spec overrides both the shorthand and template inference.
    spec = _key_scope_spec({"scope_spec": {"signature": {}}, "scope": "aead", "template_id": "aes-256-gcm-128-96"})
    assert spec.WhichOneof("scope_spec") == "signature"
    with pytest.raises(RequestError, match="must set one scope arm"):
        _key_scope_spec({"scope_spec": "{}"})


# ── Phase B: friendly scope / security / provider / crypto-param fields ────────


def test_key_scope_spec_accepts_full_sdk_scope_name() -> None:
    from citius_ui.workbench.actions import _key_scope_spec

    spec = _key_scope_spec({"scope": "AEAD_STANDARD"})
    assert spec.WhichOneof("scope_spec") == "aead"


def test_key_scope_spec_carries_security_filters() -> None:
    from citius_ui.workbench.actions import _key_scope_spec

    spec = _key_scope_spec(
        {
            "scope": "SIGNATURE_STANDARD",
            "security_strength_bits": 128,
            "nist_security_level": "LEVEL_3",
            "quantum_safe": "true",
            "nist_status": "APPROVED",
            "fips_approved": "false",
        }
    )
    security = spec.signature.security
    assert security.security_strength_bits == 128
    assert security.quantum_safe is True
    assert security.fips_approved is False


def test_security_properties_returns_none_when_unset() -> None:
    from citius_ui.workbench.actions import _security_properties

    assert _security_properties({"scope": "SIGNATURE_STANDARD"}) is None


def test_provider_requirements_from_toggles() -> None:
    from citius_ui.workbench.actions import _provider_requirements

    reqs = _provider_requirements({"require_fips_140": True, "min_fips_level": "LEVEL_3", "require_memory_safe": True})
    assert reqs is not None
    proto = reqs.to_proto()
    assert proto.fips_140_certified is True
    assert proto.memory_safe is True
    assert proto.min_fips_level == 3  # FIPS_140_LEVEL_3


def test_provider_requirements_none_when_no_toggles() -> None:
    from citius_ui.workbench.actions import _provider_requirements

    assert _provider_requirements({}) is None


def test_provider_requirements_json_override_wins() -> None:
    from citius_ui.workbench.actions import _provider_requirements

    reqs = _provider_requirements({"require_fips_140": False, "provider_requirements": {"constant_time": True}})
    assert reqs is not None
    proto = reqs.to_proto()
    assert proto.constant_time is True


def test_encryption_params_from_friendly_aad() -> None:
    from citius_ui.workbench.actions import _encryption_params

    # AAD is plain text, UTF-8 encoded to bytes for the API.
    params = _encryption_params({"aad": "context-v1"})
    assert params is not None
    assert params.aad == b"context-v1"
    assert _encryption_params({}) is None
    assert _encryption_params({"aad": "   "}) is None


def test_signature_context_from_friendly_domain_context() -> None:
    from citius_ui.workbench.actions import _signature_context

    # Domain context is plain text, UTF-8 encoded to bytes for the API.
    context = _signature_context({"domain_context": "citius-demo"})
    assert context is not None
    assert context.context == b"citius-demo"
    assert _signature_context({}) is None


def test_hash_algorithm_from_friendly_field() -> None:
    import citius_sdk as sdk

    from citius_ui.workbench.actions import _hash_algorithm

    assert _hash_algorithm({"hash_algorithm": "SHA256"}) is sdk.HashAlgorithm.SHA256
    assert _hash_algorithm({}) is None


def test_finalize_scope_params_override_beats_friendly_params() -> None:
    from citius_sdk import AeadParams
    from citius_sdk.services.crypto import encrypt_request

    from citius_ui.workbench.actions import ENCRYPTION_SCOPE_PARAM_KEYS, _finalize_scope_params

    # Friendly params set aead_params; an override to no_params must win.
    built = encrypt_request("k", b"p", params=AeadParams(aad=b"friendly"))
    _finalize_scope_params(
        built, {"scope_params": {"no_params": {}}}, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params"
    )
    assert built.WhichOneof("scope_params") == "no_params"


def test_finalize_scope_params_keeps_friendly_params_without_override() -> None:
    from citius_sdk import AeadParams
    from citius_sdk.services.crypto import encrypt_request

    from citius_ui.workbench.actions import ENCRYPTION_SCOPE_PARAM_KEYS, _finalize_scope_params

    built = encrypt_request("k", b"p", params=AeadParams(aad=b"friendly"))
    _finalize_scope_params(built, {}, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params")
    assert built.WhichOneof("scope_params") == "aead_params"
    assert built.aead_params.aad == b"friendly"


# ── Full response rendering ────────────────────────────────────────────────────


def test_full_response_includes_every_field() -> None:
    from citius_api.messages.key_management_pb2 import ReadKeyResponse

    from citius_ui.workbench.actions import _full_response

    response = ReadKeyResponse()
    response.key_metadata.name = "demo-signing-key"
    response.key_metadata.version = 2
    response.key_metadata.key_id = "kid-9"
    response.key_metadata.template_id = "ecdsa-p256-sha256-der"
    rendered = _full_response(response)
    meta = rendered["key_metadata"]
    # Populated and default-valued fields are both present, with proto names.
    assert meta["name"] == "demo-signing-key"
    assert meta["version"] == 2
    assert meta["key_id"] == "kid-9"
    assert meta["template_id"] == "ecdsa-p256-sha256-der"
    assert {"provider", "policy", "extractable", "lifecycle_state", "origin"} <= set(meta)


def test_full_response_uses_proto_field_names_not_camelcase() -> None:
    from citius_api.messages.key_management_pb2 import CreateKeyResponse

    from citius_ui.workbench.actions import _full_response

    response = CreateKeyResponse(success=True, message="created")
    response.key_metadata.key_id = "kid-1"
    rendered = _full_response(response)
    assert rendered["success"] is True
    assert rendered["message"] == "created"
    assert "key_metadata" in rendered
    assert rendered["key_metadata"]["key_id"] == "kid-1"  # snake_case, not keyId
