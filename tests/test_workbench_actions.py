from __future__ import annotations

import base64

import grpc
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
