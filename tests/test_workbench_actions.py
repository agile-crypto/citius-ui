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


def test_apply_scope_params_defaults_to_no_context() -> None:
    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _apply_scope_params

    built = _sign_request_proto()
    _apply_scope_params(built, {}, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
    assert built.WhichOneof("scope_params") == "no_context"


def test_apply_scope_params_selects_domain_context() -> None:
    import base64 as b64

    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _apply_scope_params

    built = _sign_request_proto()
    context = b64.b64encode(b"tenant-a").decode()
    request = {"scope_params": f'{{"domain_context": {{"context": "{context}"}}}}'}
    _apply_scope_params(built, request, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
    assert built.WhichOneof("scope_params") == "domain_context"
    assert built.domain_context.context == b"tenant-a"


def test_apply_scope_params_sets_aead_aad() -> None:
    import base64 as b64

    from citius_sdk.services.crypto import EncryptRequest

    from citius_ui.workbench.actions import ENCRYPTION_SCOPE_PARAM_KEYS, _apply_scope_params

    built = EncryptRequest(key_name="k", plaintext=b"p")
    aad = b64.b64encode(b"header").decode()
    request = {"scope_params": {"aead_params": {"aad": aad}}}
    _apply_scope_params(built, request, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params")
    assert built.WhichOneof("scope_params") == "aead_params"
    assert built.aead_params.aad == b"header"


def test_apply_scope_params_rejects_unknown_and_invalid() -> None:
    from citius_ui.grpc_client.serialization import RequestError
    from citius_ui.workbench.actions import SIGNATURE_SCOPE_PARAM_KEYS, _apply_scope_params

    built = _sign_request_proto()

    def apply(scope_params: object) -> None:
        _apply_scope_params(
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
