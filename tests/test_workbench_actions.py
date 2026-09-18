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
