"""SDK-backed RpcAction definitions for the currently implemented RPCs.

Implemented RPCs invoke the Python SDK and normalize the outcome. Every RPC that
exists in the protobuf contract but is not yet implemented by the server is
registered as visibly unavailable rather than hidden or emulated.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
from collections.abc import Awaitable, Callable
from typing import Any

from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto
from citius_sdk.errors import CitiusError
from citius_sdk.services import crypto as sdk_crypto
from citius_sdk.services import crypto_policy as sdk_policy
from citius_sdk.services import key_management as sdk_keys
from google.protobuf.json_format import ParseDict, ParseError

from citius_ui.actions.artifacts import Artifact, ArtifactKind
from citius_ui.actions.model import Availability, ResultStatus, RpcAction, RpcResult
from citius_ui.actions.registry import ActionRegistry
from citius_ui.grpc_client.client import CitiusClients
from citius_ui.grpc_client.serialization import (
    RequestError,
    encode_bytes,
    error_result,
    invalid_result,
    unexpected_result,
)

CONTRACT_ONLY: dict[str, list[str]] = {
    "KeyManagementService": [
        "ListKeys",
        "DeleteKey",
        "RotateKey",
        "UpdateKeyPolicy",
        "UpdateKeyState",
        "MigrateKey",
        "ValidateKeyOperation",
        "ExportKey",
        "ImportKey",
    ],
    "CryptoPolicyService": [
        "DeleteCryptoPolicy",
        "ListCryptoPolicies",
        "EvaluatePolicy",
        "BatchEvaluatePolicy",
    ],
    "CryptoService": [
        "GenerateMAC",
        "VerifyMAC",
        "Digest",
        "Xof",
        "GenerateRandom",
        "SeedRandom",
    ],
    "AlgorithmDiscoveryService": ["GetTemplate", "ListScopes"],
    "ProviderService": [
        "ListProviders",
        "GetProvider",
        "MatchProviders",
        "ListProviderInstances",
        "GetProviderInstance",
        "RegisterProviderInstance",
        "UpdateProviderInstance",
        "DeleteProviderInstance",
    ],
    "KeyEstablishmentService": [
        "WrapKey",
        "UnwrapKey",
        "DeriveKey",
        "KeyAgreement",
        "EncapsulateKey",
        "DecapsulateKey",
    ],
    "StreamingCryptoService": [
        "EncryptInit",
        "DecryptInit",
        "SignInit",
        "VerifyInit",
    ],
}

PERMISSION_BY_METHOD: dict[str, str] = {
    "CreateCryptoPolicy": "citius:policy:write",
    "ReadCryptoPolicy": "citius:policy:read",
    "UpdateCryptoPolicy": "citius:policy:write",
    "CreateKey": "citius:keys:create",
    "ReadKey": "citius:keys:read",
    "TransformKey": "citius:keys:rotate",
    "Encrypt": "citius:crypto:encrypt",
    "Decrypt": "citius:crypto:decrypt",
    "Sign": "citius:crypto:sign",
    "Verify": "citius:crypto:verify",
    "DigestSign": "citius:crypto:sign",
    "DigestVerify": "citius:crypto:verify",
}


IMPLEMENTED: dict[str, list[str]] = {
    "CryptoPolicyService": ["CreateCryptoPolicy", "ReadCryptoPolicy", "UpdateCryptoPolicy"],
    "KeyManagementService": ["CreateKey", "ReadKey", "TransformKey"],
    "CryptoService": ["Encrypt", "Decrypt", "Sign", "Verify", "DigestSign", "DigestVerify"],
}


def registry_overview() -> dict[str, list[tuple[str, Availability]]]:
    """Return the static service/method availability map without live clients."""
    grouped: dict[str, list[tuple[str, Availability]]] = {}
    for service, implemented in IMPLEMENTED.items():
        for method in implemented:
            grouped.setdefault(service, []).append((method, Availability.AVAILABLE))
    for service, contract in CONTRACT_ONLY.items():
        for method in contract:
            grouped.setdefault(service, []).append((method, Availability.UNIMPLEMENTED))
    for entries in grouped.values():
        entries.sort()
    return dict(sorted(grouped.items()))


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _require(request: dict[str, Any], key: str) -> Any:
    """Return a required request field, or raise a displayable RequestError."""
    value = request.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RequestError(f"'{key}' is required")
    return value


def _require_text(request: dict[str, Any], key: str) -> str:
    return str(_require(request, key)).strip()


def _base64_field(request: dict[str, Any], key: str) -> bytes:
    """Decode a required base64 field, tolerating pasted whitespace."""
    raw = "".join(_require_text(request, key).split())
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RequestError(f"'{key}' is not valid base64: {exc}") from exc


def _metadata_proto(value: Any) -> OperationMetadataProto:
    """Build operation metadata, rejecting malformed input instead of dropping it."""
    if value is None or value == "":
        return OperationMetadataProto()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RequestError(f"'metadata' is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RequestError("'metadata' must be a JSON object")
    try:
        parsed: OperationMetadataProto = ParseDict(value, OperationMetadataProto(), ignore_unknown_fields=True)
    except ParseError as exc:
        raise RequestError(f"'metadata' is not valid operation metadata: {exc}") from exc
    return parsed


def _normalized(
    invoke: Callable[[dict[str, Any]], Awaitable[RpcResult]],
) -> Callable[[dict[str, Any]], Awaitable[RpcResult]]:
    """Turn every failure of an action into a normalized RpcResult.

    SDK errors map to their gRPC status, malformed requests to INVALID_ARGUMENT,
    and anything unexpected (transport teardown, protobuf edge cases) to
    UNAVAILABLE — so an error is always rendered in the response panel instead
    of crashing the UI callback.
    """

    @functools.wraps(invoke)
    async def run(request: dict[str, Any]) -> RpcResult:
        if not isinstance(request, dict):
            return invalid_result(RequestError("request must be a JSON object"))
        try:
            return await invoke(request)
        except CitiusError as error:
            return error_result(error)
        except (RequestError, KeyError, TypeError) as error:
            message = str(error) if isinstance(error, RequestError) else f"invalid request: {error}"
            return invalid_result(RequestError(message))
        except Exception as error:  # noqa: BLE001 - last-resort UI stability net
            return unexpected_result(error)

    return run


def build_registry(clients: CitiusClients) -> ActionRegistry:
    """Register implemented and contract-only actions for one session."""
    registry = ActionRegistry()
    _register_crypto(registry, clients)
    _register_keys(registry, clients)
    _register_policy(registry, clients)
    _register_contract_only(registry)
    return registry


def _register_crypto(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def encrypt(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.encrypt_request(
                _require_text(request, "key_name"), _as_bytes(_require(request, "plaintext"))
            )
            result = await clients.crypto.encrypt(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={"ciphertext": encode_bytes(result.ciphertext), "metadata": metadata},
        )

    def encrypt_artifacts(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        response = result.response
        return [
            Artifact(
                id="",
                kind=ArtifactKind.CIPHERTEXT,
                key_name=str(request["key_name"]),
                key_version=response["metadata"].get("key_version"),
                value=response["ciphertext"]["base64"],
                metadata=response["metadata"],
            )
        ]

    async def sign(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.sign_request(_require_text(request, "key_name"), _as_bytes(_require(request, "message")))
            result = await clients.crypto.sign(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={"signature": encode_bytes(result.signature), "metadata": metadata},
        )

    def sign_artifacts(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        response = result.response
        return [
            Artifact(
                id="",
                kind=ArtifactKind.SIGNATURE,
                key_name=str(request["key_name"]),
                key_version=response["metadata"].get("key_version"),
                value=response["signature"]["base64"],
                metadata=response["metadata"],
                context={"message": request.get("message", "")},
            )
        ]

    async def decrypt(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.decrypt_request(
                _require_text(request, "key_name"),
                _base64_field(request, "ciphertext"),
                _metadata_proto(request.get("metadata")),
            )
            result = await clients.crypto.decrypt(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={"plaintext": encode_bytes(result.plaintext)},
        )

    async def verify(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.verify_request(
                _require_text(request, "key_name"),
                _as_bytes(_require(request, "message")),
                _base64_field(request, "signature"),
                _metadata_proto(request.get("metadata")),
            )
            result = await clients.crypto.verify(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(status=ResultStatus.OK, response={"valid": result.valid})

    async def digest_sign(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.digest_sign_request(_require_text(request, "key_name"), _base64_field(request, "digest"))
            result = await clients.crypto.digest_sign(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={"signature": encode_bytes(result.signature), "metadata": metadata},
        )

    async def digest_verify(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.digest_verify_request(
                _require_text(request, "key_name"),
                _base64_field(request, "digest"),
                _base64_field(request, "signature"),
                _metadata_proto(request.get("metadata")),
            )
            result = await clients.crypto.digest_verify(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(status=ResultStatus.OK, response={"valid": result.valid})

    registry.register(
        RpcAction(
            service="CryptoService",
            method="Encrypt",
            permission=PERMISSION_BY_METHOD["Encrypt"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(encrypt),
            extract_artifacts=encrypt_artifacts,
        )
    )
    registry.register(
        RpcAction(
            service="CryptoService",
            method="Sign",
            permission=PERMISSION_BY_METHOD["Sign"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(sign),
            extract_artifacts=sign_artifacts,
        )
    )
    registry.register(
        RpcAction(
            service="CryptoService",
            method="Decrypt",
            permission=PERMISSION_BY_METHOD["Decrypt"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(decrypt),
        )
    )
    registry.register(
        RpcAction(
            service="CryptoService",
            method="Verify",
            permission=PERMISSION_BY_METHOD["Verify"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(verify),
        )
    )
    registry.register(
        RpcAction(
            service="CryptoService",
            method="DigestSign",
            permission=PERMISSION_BY_METHOD["DigestSign"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(digest_sign),
            extract_artifacts=sign_artifacts,
        )
    )
    registry.register(
        RpcAction(
            service="CryptoService",
            method="DigestVerify",
            permission=PERMISSION_BY_METHOD["DigestVerify"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(digest_verify),
        )
    )


def _register_keys(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def create_key(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.create_key_request(
                _require_text(request, "name"),
                policy=request.get("policy", ""),
                template_id=request.get("template_id", ""),
                provider_id=request.get("provider_id", ""),
            )
            result = await clients.key_management.create_key(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response={"success": result.success})

    async def read_key(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.read_key_request(_require_text(request, "name"))
            result = await clients.key_management.read_key(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.key_metadata
        response = {"name": metadata.name, "version": metadata.version} if metadata else {}
        return RpcResult(status=ResultStatus.OK, response=response)

    async def transform_key(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.transform_key_request(
                _require_text(request, "name"),
                retain_key_bytes=bool(request.get("retain_key_bytes", False)),
                template_id=request.get("template_id", ""),
            )
            result = await clients.key_management.transform_key(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.key_metadata
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        response: dict[str, Any] = {"success": result.success}
        if metadata:
            response["version"] = metadata.version
        return RpcResult(status=status, message=result.message, response=response)

    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="CreateKey",
            permission=PERMISSION_BY_METHOD["CreateKey"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(create_key),
        )
    )
    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="ReadKey",
            permission=PERMISSION_BY_METHOD["ReadKey"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(read_key),
        )
    )
    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="TransformKey",
            permission=PERMISSION_BY_METHOD["TransformKey"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(transform_key),
        )
    )


def _register_policy(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def create_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.create_policy_request(
                _require_text(request, "name"),
                str(_require(request, "policy_document")),
                request.get("format") or "yaml",
            )
            result = await clients.crypto_policy.create_policy(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(
            status=status,
            message=result.message,
            response={"success": result.success, "version": result.version},
        )

    async def read_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.read_policy_request(_require_text(request, "name"))
            result = await clients.crypto_policy.read_policy(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "name": result.name,
                "policy_document": result.policy_document,
                "format": result.format,
                "version": result.version,
            },
        )

    async def update_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.update_policy_request(
                _require_text(request, "name"),
                str(_require(request, "policy_document")),
                request.get("format") or "yaml",
                expected_version=request.get("expected_version"),
            )
            result = await clients.crypto_policy.update_policy(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(
            status=status,
            message=result.message,
            response={"success": result.success, "version": result.version},
        )

    registry.register(
        RpcAction(
            service="CryptoPolicyService",
            method="CreateCryptoPolicy",
            permission=PERMISSION_BY_METHOD["CreateCryptoPolicy"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(create_policy),
        )
    )
    registry.register(
        RpcAction(
            service="CryptoPolicyService",
            method="ReadCryptoPolicy",
            permission=PERMISSION_BY_METHOD["ReadCryptoPolicy"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(read_policy),
        )
    )
    registry.register(
        RpcAction(
            service="CryptoPolicyService",
            method="UpdateCryptoPolicy",
            permission=PERMISSION_BY_METHOD["UpdateCryptoPolicy"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(update_policy),
        )
    )


def _register_contract_only(registry: ActionRegistry) -> None:
    for service, methods in CONTRACT_ONLY.items():
        for method in methods:
            registry.register(
                RpcAction(
                    service=service,
                    method=method,
                    permission=PERMISSION_BY_METHOD.get(method, ""),
                    availability=Availability.UNIMPLEMENTED,
                )
            )
