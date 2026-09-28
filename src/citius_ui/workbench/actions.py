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

import citius_sdk as sdk
from citius_api.messages.key_management_pb2 import MigrationStrategy
from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto
from citius_api.services.discovery_service_pb2 import ListTemplatesRequest
from citius_api.types import common_pb2 as common_types
from citius_api.types import implementation_pb2 as common_impl
from citius_api.types import templates_pb2 as templates_types
from citius_sdk.errors import CitiusError
from citius_sdk.services import crypto as sdk_crypto
from citius_sdk.services import crypto_policy as sdk_policy
from citius_sdk.services import key_management as sdk_keys
from google.protobuf.json_format import MessageToDict, ParseDict, ParseError

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
        "DeleteKey",
        "RotateKey",
        "UpdateKeyPolicy",
        "UpdateKeyState",
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
    "ProviderService": [
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
    "ListKeys": "citius:keys:read",
    "ValidateKeyOperation": "citius:keys:read",
    "TransformKey": "citius:keys:rotate",
    "MigrateKey": "citius:keys:rotate",
    "Encrypt": "citius:crypto:encrypt",
    "Decrypt": "citius:crypto:decrypt",
    "Sign": "citius:crypto:sign",
    "Verify": "citius:crypto:verify",
    "DigestSign": "citius:crypto:sign",
    "DigestVerify": "citius:crypto:verify",
    "ListTemplates": "citius:discovery:read",
    "GetTemplate": "citius:discovery:read",
    "ListScopes": "citius:discovery:read",
    "ListProviders": "citius:provider:read",
    "GetProvider": "citius:provider:read",
    "ListProviderInstances": "citius:provider:read",
    "GetProviderInstance": "citius:provider:read",
    "MatchProviders": "citius:provider:read",
}


IMPLEMENTED: dict[str, list[str]] = {
    "CryptoPolicyService": ["CreateCryptoPolicy", "ReadCryptoPolicy", "UpdateCryptoPolicy"],
    "KeyManagementService": [
        "CreateKey",
        "ReadKey",
        "ListKeys",
        "TransformKey",
        "MigrateKey",
        "ValidateKeyOperation",
    ],
    "CryptoService": ["Encrypt", "Decrypt", "Sign", "Verify", "DigestSign", "DigestVerify"],
    "AlgorithmDiscoveryService": ["ListTemplates", "GetTemplate", "ListScopes"],
    "ProviderService": [
        "ListProviders",
        "GetProvider",
        "ListProviderInstances",
        "GetProviderInstance",
        "MatchProviders",
    ],
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


def _full_response(message: Any) -> dict[str, Any]:
    """Render a full response proto as a dict, preserving every populated field.

    Uses proto field names (not camelCase) and includes fields left at their
    default so the Response panel shows the complete server reply rather than a
    hand-picked subset. Bytes fields are base64-encoded by MessageToDict, which
    is the faithful JSON representation of protobuf ``bytes``.
    """
    rendered: dict[str, Any] = MessageToDict(
        message,
        preserving_proto_field_name=True,
        always_print_fields_with_no_presence=True,
    )
    return rendered


def _require(request: dict[str, Any], key: str) -> Any:
    """Return a required request field, or raise a displayable RequestError."""
    value = request.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RequestError(f"'{key}' is required")
    return value


def _require_text(request: dict[str, Any], key: str) -> str:
    return str(_require(request, key)).strip()


def _merge_bundle(request: dict[str, Any]) -> dict[str, Any]:
    """Expand a pasted producer 'bundle' into the request's individual fields.

    Verify/Decrypt take the producer's copyable bundle (value + metadata as one
    JSON object) as the primary input. This parses that bundle and fills any
    field the caller did not set directly, so ``{"ciphertext": ..., "metadata":
    ...}`` from an Encrypt response drives Decrypt with a single paste. Fields
    the caller set explicitly (the advanced split inputs) win over the bundle.
    """
    raw = request.get("bundle")
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return request
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RequestError(f"'bundle' is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise RequestError("'bundle' must be a JSON object")
    merged = dict(request)
    for key, value in raw.items():
        current = merged.get(key)
        if current is None or (isinstance(current, str) and not current.strip()):
            merged[key] = value
    return merged


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


_SIGNATURE_TEMPLATE_PREFIXES = (
    "ecdsa-",
    "ed25519",
    "ed448",
    "ml-dsa-",
    "slh-dsa-",
    "hash-ml-dsa-",
    "hash-slh-dsa-",
    "rsa-",
)
_AEAD_TEMPLATE_MARKERS = ("gcm", "chacha20-poly1305")


_LEGACY_SCOPE_ALIASES = {
    "signature": "SIGNATURE_STANDARD",
    "signature_prehashed": "SIGNATURE_PREHASHED",
    "aead": "AEAD_STANDARD",
}


def _resolve_scope(scope: str) -> sdk.Scope:
    """Map a scope string (SDK name or legacy shorthand) to an SDK Scope."""
    name = _LEGACY_SCOPE_ALIASES.get(scope.strip().lower(), scope.strip().upper())
    try:
        return sdk.Scope[name]
    except KeyError as exc:
        supported = ", ".join(member.name for member in sdk.Scope)
        raise RequestError(f"unsupported scope {scope!r} (supported: {supported})") from exc


def _tristate(request: dict[str, Any], key: str) -> bool | None:
    """Read an optional tri-state ('true'/'false'/unset) filter field."""
    value = request.get(key)
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    raise RequestError(f"'{key}' must be true, false, or blank")


def _enum_member(enum_cls: Any, request: dict[str, Any], key: str) -> Any | None:
    """Read an optional enum-name field into the given SDK enum, or None."""
    value = request.get(key)
    if value is None or value == "":
        return None
    try:
        return enum_cls[str(value).strip().upper()]
    except KeyError as exc:
        supported = ", ".join(member.name for member in enum_cls)
        raise RequestError(f"'{key}' must be one of: {supported}") from exc


def _security_properties(request: dict[str, Any]) -> sdk.SecurityProperties | None:
    """Build SecurityProperties from the friendly filter fields, or None."""
    strength = request.get("security_strength_bits")
    level = _enum_member(sdk.NistSecurityLevel, request, "nist_security_level")
    status = _enum_member(sdk.NistStatus, request, "nist_status")
    quantum_safe = _tristate(request, "quantum_safe")
    fips_approved = _tristate(request, "fips_approved")
    if all(v in (None, "", 0) for v in (strength, level, status, quantum_safe, fips_approved)):
        return None
    return sdk.SecurityProperties(
        security_strength_bits=int(strength) if strength else 0,
        nist_security_level=level or sdk.NistSecurityLevel.UNSPECIFIED,
        quantum_safe=quantum_safe,
        nist_status=status or sdk.NistStatus.UNSPECIFIED,
        fips_approved=fips_approved,
    )


def _provider_requirements(request: dict[str, Any]) -> sdk.ProviderRequirements | None:
    """Build ProviderRequirements from the friendly toggle fields, or None.

    An explicit 'provider_requirements' JSON object wins over the toggles.
    """
    override = request.get("provider_requirements")
    if override not in (None, ""):
        if isinstance(override, str):
            try:
                override = json.loads(override)
            except json.JSONDecodeError as exc:
                raise RequestError(f"'provider_requirements' is not valid JSON: {exc}") from exc
        if not isinstance(override, dict):
            raise RequestError("'provider_requirements' must be a JSON object")
        try:
            proto: Any = ParseDict(override, common_impl.ProviderRequirements(), ignore_unknown_fields=False)
        except ParseError as exc:
            raise RequestError(f"'provider_requirements' does not match the schema: {exc}") from exc
        return _ProtoProviderRequirements(proto)
    min_fips = _enum_member(sdk.Fips140Level, request, "min_fips_level")
    toggles = {
        "fips_140_certified": bool(request.get("require_fips_140", False)),
        "common_criteria_certified": bool(request.get("require_common_criteria", False)),
        "memory_safe": bool(request.get("require_memory_safe", False)),
        "constant_time": bool(request.get("require_constant_time", False)),
        "side_channel_hardened": bool(request.get("require_side_channel_hardened", False)),
        "no_known_cve": bool(request.get("require_no_known_cve", False)),
        "prefer_hardware_accelerated": bool(request.get("prefer_hardware_accelerated", False)),
    }
    if min_fips is None and not any(toggles.values()):
        return None
    return sdk.ProviderRequirements(min_fips_level=min_fips or sdk.Fips140Level.UNSPECIFIED, **toggles)


class _ProtoProviderRequirements:
    """Adapter that lets a raw ProviderRequirements proto flow through the SDK builder path."""

    def __init__(self, proto: Any) -> None:
        self._proto = proto

    def to_proto(self) -> Any:
        return self._proto


def _key_scope_spec(request: dict[str, Any]) -> common_types.ScopeSpecification:
    """Resolve the key scope the server requires on Create/TransformKey.

    The server rejects key creation without a scope specification even when a
    template is given, and the template must match the scope. An explicit
    'scope_spec' JSON object wins (full ScopeSpecification control), then an
    explicit 'scope' name/shorthand combined with the friendly security
    filters; otherwise the scope is inferred from the template id.
    """
    spec_json = request.get("scope_spec")
    if spec_json not in (None, ""):
        if isinstance(spec_json, str):
            try:
                spec_json = json.loads(spec_json)
            except json.JSONDecodeError as exc:
                raise RequestError(f"'scope_spec' is not valid JSON: {exc}") from exc
        if not isinstance(spec_json, dict):
            raise RequestError("'scope_spec' must be a JSON object")
        try:
            spec: common_types.ScopeSpecification = ParseDict(
                spec_json, common_types.ScopeSpecification(), ignore_unknown_fields=False
            )
        except ParseError as exc:
            raise RequestError(f"'scope_spec' does not match the ScopeSpecification schema: {exc}") from exc
        if spec.WhichOneof("scope_spec") is None:
            raise RequestError(
                "'scope_spec' must set one scope arm, e.g. "
                '{"signature": {"scope": "SIGNATURE_SCOPE_STANDARD"}} or {"aead": {"scope": "AEAD_SCOPE_STANDARD"}}'
            )
        return spec
    scope_name = str(request.get("scope") or "").strip()
    if not scope_name:
        scope_name = _infer_scope_from_template(request)
    try:
        built_spec: common_types.ScopeSpecification = sdk.build_scope_spec(
            _resolve_scope(scope_name), security=_security_properties(request)
        )
    except ValueError as exc:
        raise RequestError(str(exc)) from exc
    return built_spec


def _infer_scope_from_template(request: dict[str, Any]) -> str:
    """Infer an SDK scope name from a template id, matching legacy behaviour."""
    template_id = str(request.get("template_id") or "").strip().lower()
    if not template_id:
        supported = ", ".join(member.name for member in sdk.Scope)
        raise RequestError(f"'scope' is required when no template_id is given (supported: {supported})")
    if "prehashed" in template_id:
        return "SIGNATURE_PREHASHED"
    if template_id.startswith(_SIGNATURE_TEMPLATE_PREFIXES):
        return "SIGNATURE_STANDARD"
    if any(marker in template_id for marker in _AEAD_TEMPLATE_MARKERS):
        return "AEAD_STANDARD"
    raise RequestError(f"cannot infer a key scope from template {template_id!r}; set 'scope' explicitly")


# ── Crypto operation parameters / signature contexts ──────────────────────────
#
# Friendly fields (aad, domain_context, hash_algorithm) build the SDK params/
# context objects. An advanced 'scope_params' JSON object overrides them for
# full oneof control (e.g. xts_params, vendor_params, user_context).

SIGNATURE_SCOPE_PARAM_KEYS = frozenset({"no_context", "domain_context", "vendor_context", "user_context"})
# DigestSign also declares the digest's hash; DigestVerify reads it from the
# signature's operation metadata (digest_hash), so it takes the plain set.
DIGEST_SIGN_SCOPE_PARAM_KEYS = SIGNATURE_SCOPE_PARAM_KEYS | {"hash_algorithm"}
ENCRYPTION_SCOPE_PARAM_KEYS = frozenset(
    {"no_params", "aead_params", "xts_params", "asymmetric_params", "vendor_params", "user_context"}
)


def _scope_params_override(request: dict[str, Any], allowed: frozenset[str]) -> dict[str, Any] | None:
    """Parse and validate the optional advanced 'scope_params' JSON override."""
    raw = request.get("scope_params")
    if raw is None or raw == "":
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RequestError(f"'scope_params' is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise RequestError("'scope_params' must be a JSON object")
    unknown = set(raw) - allowed
    if unknown:
        raise RequestError(f"unknown scope parameter(s) {sorted(unknown)}; supported for this RPC: {sorted(allowed)}")
    return raw


def _apply_scope_params_override(built: Any, override: dict[str, Any]) -> None:
    """Merge an advanced scope_params JSON override onto a crypto request proto."""
    try:
        ParseDict(override, built, ignore_unknown_fields=False)
    except ParseError as exc:
        raise RequestError(f"'scope_params' does not match the request schema: {exc}") from exc


def _finalize_scope_params(built: Any, request: dict[str, Any], *, allowed: frozenset[str], default_arm: str) -> None:
    """Reconcile friendly params, an advanced JSON override, and the required arm.

    The friendly fields (already applied by the SDK builder) set an arm when
    present. An advanced 'scope_params' JSON override wins over them. If no arm
    ends up set, ``default_arm`` is selected because the server requires one.
    """
    override = _scope_params_override(request, allowed)
    if override is not None:
        built.ClearField("scope_params")
        _apply_scope_params_override(built, override)
    if built.WhichOneof("scope_params") is None:
        getattr(built, default_arm).SetInParent()


def _optional_text_bytes(request: dict[str, Any], key: str) -> bytes | None:
    """Encode an optional plain-text field as UTF-8 bytes, or None if blank.

    The API's ``aad`` / ``context`` fields are protobuf ``bytes`` but are almost
    always human-meaningful strings (a tenant id, a domain-separation tag), so
    the Workbench takes them as plain text — matching how the message/plaintext
    fields work — rather than forcing the caller to base64-encode them.
    """
    value = request.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return str(value).encode("utf-8")


def _encryption_params(request: dict[str, Any]) -> sdk.AeadParams | None:
    """Build encryption params from the friendly plain-text 'aad' field, or None."""
    aad = _optional_text_bytes(request, "aad")
    if aad is None:
        return None
    return sdk.AeadParams(aad=aad)


def _signature_context(request: dict[str, Any]) -> sdk.DomainContext | None:
    """Build a signature context from the friendly plain-text 'domain_context' field, or None."""
    context = _optional_text_bytes(request, "domain_context")
    if context is None:
        return None
    return sdk.DomainContext(context=context)


def _hash_algorithm(request: dict[str, Any]) -> sdk.HashAlgorithm | None:
    """Read the friendly 'hash_algorithm' field into the SDK enum, or None."""
    return _enum_member(sdk.HashAlgorithm, request, "hash_algorithm")


def _policy_document(request: dict[str, Any]) -> str:
    """Return the policy document, pre-validating JSON-format documents.

    The server parses every policy document as rules JSON, so catching invalid
    JSON here turns a cryptic server-side parse failure into an immediate,
    actionable INVALID_ARGUMENT.
    """
    document = str(_require(request, "policy_document"))
    if str(request.get("format") or "json").lower() == "json":
        try:
            json.loads(document)
        except json.JSONDecodeError as exc:
            raise RequestError(
                f"'policy_document' is not valid JSON: {exc}. The server stores policy rules as JSON, "
                'e.g. {"version": "1", "allowed_operations": {"key_operations": ["sign", "verify"]}, '
                '"allowed_templates": ["ecdsa-p256-sha256-der"]}'
            ) from exc
    return document


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
    _register_discovery(registry, clients)
    _register_providers(registry, clients)
    _register_contract_only(registry)
    return registry


def _register_crypto(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def encrypt(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.encrypt_request(
                _require_text(request, "key_name"),
                _as_bytes(_require(request, "plaintext")),
                params=_encryption_params(request),
            )
            # The server requires the scope_params oneof; an advanced override
            # wins, else default to standard AEAD parameters.
            _finalize_scope_params(built, request, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params")
            result = await clients.crypto.encrypt(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "ciphertext": encode_bytes(result.ciphertext),
                "metadata": metadata,
                "full_response": _full_response(result.proto),
            },
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
            built = sdk_crypto.sign_request(
                _require_text(request, "key_name"),
                _as_bytes(_require(request, "message")),
                context=_signature_context(request),
            )
            # The server requires the scope_params oneof; an override wins, else
            # no_context selects the standard signature scope.
            _finalize_scope_params(built, request, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
            result = await clients.crypto.sign(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "signature": encode_bytes(result.signature),
                "metadata": metadata,
                "full_response": _full_response(result.proto),
            },
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

    def digest_sign_artifacts(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        response = result.response
        return [
            Artifact(
                id="",
                kind=ArtifactKind.SIGNATURE,
                key_name=str(request["key_name"]),
                key_version=response["metadata"].get("key_version"),
                value=response["signature"]["base64"],
                metadata=response["metadata"],
                context={"digest": request.get("digest", "")},
            )
        ]

    async def decrypt(request: dict[str, Any]) -> RpcResult:
        try:
            request = _merge_bundle(request)
            built = sdk_crypto.decrypt_request(
                _require_text(request, "key_name"),
                _base64_field(request, "ciphertext"),
                _metadata_proto(request.get("metadata")),
                params=_encryption_params(request),
            )
            _finalize_scope_params(built, request, allowed=ENCRYPTION_SCOPE_PARAM_KEYS, default_arm="aead_params")
            result = await clients.crypto.decrypt(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "plaintext": encode_bytes(result.plaintext),
                "full_response": _full_response(result.proto),
            },
        )

    async def verify(request: dict[str, Any]) -> RpcResult:
        try:
            request = _merge_bundle(request)
            built = sdk_crypto.verify_request(
                _require_text(request, "key_name"),
                _as_bytes(_require(request, "message")),
                _base64_field(request, "signature"),
                _metadata_proto(request.get("metadata")),
                context=_signature_context(request),
            )
            _finalize_scope_params(built, request, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
            result = await clients.crypto.verify(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={"valid": result.valid, "full_response": _full_response(result.proto)},
        )

    async def digest_sign(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.digest_sign_request(
                _require_text(request, "key_name"),
                _base64_field(request, "digest"),
                context=_signature_context(request),
                hash_algorithm=_hash_algorithm(request),
            )
            _finalize_scope_params(built, request, allowed=DIGEST_SIGN_SCOPE_PARAM_KEYS, default_arm="no_context")
            result = await clients.crypto.digest_sign(built)
        except CitiusError as error:
            return error_result(error)
        metadata = result.metadata.to_dict() if result.metadata else {}
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "signature": encode_bytes(result.signature),
                "metadata": metadata,
                "full_response": _full_response(result.proto),
            },
        )

    async def digest_verify(request: dict[str, Any]) -> RpcResult:
        try:
            request = _merge_bundle(request)
            built = sdk_crypto.digest_verify_request(
                _require_text(request, "key_name"),
                _base64_field(request, "digest"),
                _base64_field(request, "signature"),
                _metadata_proto(request.get("metadata")),
                context=_signature_context(request),
            )
            _finalize_scope_params(built, request, allowed=SIGNATURE_SCOPE_PARAM_KEYS, default_arm="no_context")
            result = await clients.crypto.digest_verify(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={"valid": result.valid, "full_response": _full_response(result.proto)},
        )

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
            extract_artifacts=digest_sign_artifacts,
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


def _migration_strategy(request: dict[str, Any], key: str, *, required: bool) -> Any:
    """Read a migration strategy name (with or without its prefix) into the enum."""
    name = str(request.get(key) or "").strip().upper()
    if not name:
        if required:
            raise RequestError(f"'{key}' is required")
        return MigrationStrategy.MIGRATION_STRATEGY_UNSPECIFIED
    full_name = f"MIGRATION_STRATEGY_{name.removeprefix('MIGRATION_STRATEGY_')}"
    try:
        return MigrationStrategy.Value(full_name)
    except ValueError as exc:
        raise RequestError(f"unknown migration strategy {name!r}") from exc


def _lifecycle_state(request: dict[str, Any]) -> Any:
    """Read an optional lifecycle state name (with or without its prefix)."""
    name = str(request.get("lifecycle_state") or "").strip().upper()
    if not name:
        return common_types.KeyLifecycleState.KEY_LIFECYCLE_STATE_UNSPECIFIED
    full_name = f"KEY_LIFECYCLE_STATE_{name.removeprefix('KEY_LIFECYCLE_STATE_')}"
    try:
        return common_types.KeyLifecycleState.Value(full_name)
    except ValueError as exc:
        raise RequestError(f"unknown lifecycle state {name!r}") from exc


def _page_size(request: dict[str, Any]) -> int:
    value = request.get("page_size")
    if value is None or value == "":
        return 0
    try:
        size = int(value)
    except (TypeError, ValueError) as exc:
        raise RequestError("'page_size' must be a whole number") from exc
    if size < 0:
        raise RequestError("'page_size' must not be negative")
    return size


def _key_summary(view: sdk_keys.KeyMetadataView) -> dict[str, Any]:
    """One inventory row: where a key lives and what it is."""
    return {
        "name": view.name,
        "version": view.version,
        "template_id": view.template_id,
        "provider": view.provider,
        "policy": view.policy,
        "extractable": view.extractable,
        "lifecycle_state": common_types.KeyLifecycleState.Name(view.lifecycle_state),
        "origin": common_types.KeyOrigin.Name(view.origin),
    }


def _register_keys(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def create_key(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.create_key_request(
                _require_text(request, "name"),
                policy=request.get("policy", ""),
                template_id=request.get("template_id") or "scope-spec-carrier",
                provider_id=request.get("provider_id", ""),
                provider_requirements=_provider_requirements(request),
            )
            if not request.get("template_id"):
                built.ClearField("template_id")
            # The server requires a scope even when a template is given; the
            # scope spec carries the friendly security-property filters and is
            # built through the SDK vocabulary (sdk.build_scope_spec).
            built.scope_spec.CopyFrom(_key_scope_spec(request))
            result = await clients.key_management.create_key(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response=_full_response(result.proto))

    async def read_key(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.read_key_request(_require_text(request, "name"))
            result = await clients.key_management.read_key(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(status=ResultStatus.OK, response=_full_response(result.proto))

    async def transform_key(request: dict[str, Any]) -> RpcResult:
        retain_key_bytes = bool(request.get("retain_key_bytes", False))
        template_id = str(request.get("template_id") or "").strip()
        if retain_key_bytes and not template_id:
            # The server requires an explicit, material-compatible target
            # template to retain key bytes; fail fast with the same meaning.
            raise RequestError("'template_id' is required when 'retain_key_bytes' is set")
        try:
            built = sdk_keys.transform_key_request(
                _require_text(request, "name"),
                retain_key_bytes=retain_key_bytes,
                template_id=template_id,
            )
            built.scope_spec.CopyFrom(_key_scope_spec(request))
            result = await clients.key_management.transform_key(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response=_full_response(result.proto))

    async def migrate_key(request: dict[str, Any]) -> RpcResult:
        strategy = _migration_strategy(request, "strategy", required=True)
        try:
            built = sdk_keys.migrate_key_request(
                _require_text(request, "name"),
                strategy=strategy,
                target_instance_id=str(request.get("target_instance_id") or "").strip(),
                target_provider_id=str(request.get("target_provider_id") or "").strip(),
            )
            result = await clients.key_management.migrate_key(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response=_full_response(result.proto))

    async def list_keys(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.list_keys_request(
                provider_id=str(request.get("provider_id") or "").strip(),
                policy=str(request.get("policy") or "").strip(),
                lifecycle_state=_lifecycle_state(request),
                page_size=_page_size(request),
                page_token=str(request.get("page_token") or "").strip(),
            )
            result = await clients.key_management.list_keys(built)
        except CitiusError as error:
            return error_result(error)
        keys = [_key_summary(view) for view in result.keys]
        return RpcResult(
            status=ResultStatus.OK,
            message=f"{len(keys)} key(s)" + ("; more on the next page" if result.next_page_token else ""),
            response={
                "keys": keys,
                "next_page_token": result.next_page_token,
                "full_response": _full_response(result.proto),
            },
        )

    async def validate_key_operation(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_keys.validate_migration_request(
                _require_text(request, "name"),
                target_instance_id=str(request.get("target_instance_id") or "").strip(),
                target_provider_id=str(request.get("target_provider_id") or "").strip(),
                preferred_strategy=_migration_strategy(request, "preferred_strategy", required=False),
            )
            result = await clients.key_management.validate_key_operation(built)
        except CitiusError as error:
            return error_result(error)
        recommended = result.recommended_strategy
        feasible = recommended != MigrationStrategy.MIGRATION_STRATEGY_UNSPECIFIED
        return RpcResult(
            status=ResultStatus.OK,
            message=(f"recommended: {MigrationStrategy.Name(recommended)}" if feasible else "no strategy is feasible"),
            response={
                "current": {
                    "instance_id": result.current_instance_id,
                    "template_id": result.current_template_id,
                    "extractable": result.current_extractable,
                },
                "recommended_strategy": MigrationStrategy.Name(recommended),
                "recommendation_reason": result.recommendation_reason,
                "options": [
                    {
                        "strategy": option.strategy_name,
                        "feasible": option.feasible,
                        "why_not": option.infeasibility_reason,
                        "security_notes": option.security_notes,
                    }
                    for option in result.options
                ],
                "full_response": _full_response(result.proto),
            },
        )

    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="ListKeys",
            permission=PERMISSION_BY_METHOD["ListKeys"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(list_keys),
        )
    )
    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="ValidateKeyOperation",
            permission=PERMISSION_BY_METHOD["ValidateKeyOperation"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(validate_key_operation),
        )
    )
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
    registry.register(
        RpcAction(
            service="KeyManagementService",
            method="MigrateKey",
            permission=PERMISSION_BY_METHOD["MigrateKey"],
            availability=Availability.AVAILABLE,
            invoke=_normalized(migrate_key),
        )
    )


def _register_policy(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def create_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.create_policy_request(
                _require_text(request, "name"),
                _policy_document(request),
                request.get("format") or "json",
            )
            result = await clients.crypto_policy.create_policy(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response=_full_response(result.proto))

    async def read_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.read_policy_request(_require_text(request, "name"))
            result = await clients.crypto_policy.read_policy(built)
        except CitiusError as error:
            return error_result(error)
        return RpcResult(status=ResultStatus.OK, response=_full_response(result.proto))

    async def update_policy(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_policy.update_policy_request(
                _require_text(request, "name"),
                _policy_document(request),
                request.get("format") or "json",
                expected_version=request.get("expected_version"),
            )
            result = await clients.crypto_policy.update_policy(built)
        except CitiusError as error:
            return error_result(error)
        status = ResultStatus.OK if result.success else ResultStatus.FAILED_PRECONDITION
        return RpcResult(status=status, message=result.message, response=_full_response(result.proto))

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


def _template_summary(info: Any) -> dict[str, Any]:
    """One catalogue row: what a template is and how quantum-safe it is."""
    quantum_level = info.cyclonedx.nist_quantum_security_level
    return {
        "template_id": info.template_id,
        "display_name": info.display_name,
        "status": templates_types.TemplateStatus.Name(info.status),
        "standards": list(info.standards),
        "classical_security_bits": info.cyclonedx.classical_security_level,
        "nist_quantum_security_level": quantum_level,
        "quantum_safe": quantum_level > 0,
    }


def _template_statuses(request: dict[str, Any]) -> list[Any]:
    raw = request.get("allowed_statuses")
    if raw is None or raw == "":
        return []
    names = raw if isinstance(raw, list) else str(raw).split(",")
    statuses = []
    for name in names:
        text = str(name).strip().upper()
        if not text:
            continue
        try:
            statuses.append(
                templates_types.TemplateStatus.Value(f"TEMPLATE_STATUS_{text.removeprefix('TEMPLATE_STATUS_')}")
            )
        except ValueError as exc:
            raise RequestError(f"unknown template status {text!r}") from exc
    return statuses


def _register_discovery(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def list_templates(request: dict[str, Any]) -> RpcResult:
        built = ListTemplatesRequest(
            allowed_statuses=_template_statuses(request),
            page_size=_page_size(request),
            page_token=str(request.get("page_token") or "").strip(),
        )
        standard = str(request.get("required_standard") or "").strip()
        if standard:
            built.required_standards.append(standard)
        scope = str(request.get("scope") or "").strip()
        if scope:
            try:
                built.scope_spec.CopyFrom(
                    sdk.build_scope_spec(_resolve_scope(scope), security=_security_properties(request))
                )
            except ValueError as exc:
                raise RequestError(str(exc)) from exc
        try:
            result = await clients.discovery.list_templates(built)
        except CitiusError as error:
            return error_result(error)
        rows = [_template_summary(t) for t in result.templates]
        return RpcResult(
            status=ResultStatus.OK,
            message=f"{len(rows)} template(s)" + ("; more on the next page" if result.next_page_token else ""),
            response={
                "templates": rows,
                "next_page_token": result.next_page_token,
                "full_response": _full_response(result),
            },
        )

    async def get_template(request: dict[str, Any]) -> RpcResult:
        try:
            info = await clients.discovery.get_template(_require_text(request, "template_id"))
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={"summary": _template_summary(info), "full_response": _full_response(info)},
        )

    async def list_scopes(_request: dict[str, Any]) -> RpcResult:
        try:
            result = await clients.discovery.list_scopes()
        except CitiusError as error:
            return error_result(error)
        scopes = [
            {
                "scope": s.name,
                "operations": [common_types.CryptoOperation.Name(o) for o in s.supported_operations],
            }
            for s in result.scopes
        ]
        return RpcResult(
            status=ResultStatus.OK,
            message=f"{len(scopes)} scope(s) offered by the catalogue",
            response={"scopes": scopes, "full_response": _full_response(result)},
        )

    for method, invoke in (
        ("ListTemplates", list_templates),
        ("GetTemplate", get_template),
        ("ListScopes", list_scopes),
    ):
        registry.register(
            RpcAction(
                service="AlgorithmDiscoveryService",
                method=method,
                permission=PERMISSION_BY_METHOD[method],
                availability=Availability.AVAILABLE,
                invoke=_normalized(invoke),
            )
        )


def _implementation_summary(props: Any) -> dict[str, Any]:
    fips = props.fips_140
    return {
        "fips_140": common_impl.Fips140Level.Name(fips.level) if fips.certified else "not certified",
        "language": props.implementation_language,
        "memory_safe": props.memory_safe_language,
        "hardware_accelerated": props.hardware_accelerated,
        "constant_time": props.constant_time,
    }


def unmet_requirements(requirements: Any, props: Any) -> list[str]:
    """Name each hard requirement ``props`` fails, mirroring the server's check.

    ``requirements`` is a ProviderRequirements proto and ``props`` an
    ImplementationProperties proto. An empty list means every hard
    requirement is met.
    """
    fips = props.fips_140
    checks = (
        (requirements.fips_140_certified, fips.certified, "not FIPS 140 certified"),
        (
            requirements.min_fips_level > 0,
            fips.certified and fips.level >= requirements.min_fips_level,
            f"below {common_impl.Fips140Level.Name(requirements.min_fips_level)}",
        ),
        (requirements.common_criteria_certified, props.common_criteria_certified, "not Common Criteria certified"),
        (requirements.formally_verified, props.formally_verified, "not formally verified"),
        (requirements.memory_safe, props.memory_safe_language, "not written in a memory-safe language"),
        (requirements.constant_time, props.constant_time, "not constant-time"),
        (requirements.side_channel_hardened, props.side_channel_hardened, "not side-channel hardened"),
        (
            requirements.no_known_cve,
            props.no_known_cve and not props.unpatched_cves,
            "has known CVEs",
        ),
    )
    return [reason for required, met, reason in checks if required and not met]


def _register_providers(registry: ActionRegistry, clients: CitiusClients) -> None:
    async def list_instances(request: dict[str, Any]) -> RpcResult:
        try:
            result = await clients.providers.list_provider_instances(
                provider_id=str(request.get("provider_id") or "").strip(),
                requirements=_provider_requirements(request),
                page_size=_page_size(request),
                page_token=str(request.get("page_token") or "").strip(),
            )
        except CitiusError as error:
            return error_result(error)
        rows = [
            {
                "instance_id": i.instance_id,
                "provider": i.provider_id,
                **_implementation_summary(i.implementation_override),
            }
            for i in result.instances
        ]
        return RpcResult(
            status=ResultStatus.OK,
            message=f"{len(rows)} instance(s)",
            response={
                "instances": rows,
                "next_page_token": result.next_page_token,
                "full_response": _full_response(result),
            },
        )

    async def get_instance(request: dict[str, Any]) -> RpcResult:
        try:
            instance = await clients.providers.get_provider_instance(_require_text(request, "instance_id"))
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "instance_id": instance.instance_id,
                "provider": instance.provider_id,
                "implementation": _implementation_summary(instance.implementation_override),
                "full_response": _full_response(instance),
            },
        )

    async def list_providers(request: dict[str, Any]) -> RpcResult:
        try:
            result = await clients.providers.list_providers(
                template_id=str(request.get("template_id") or "").strip(),
                requirements=_provider_requirements(request),
                page_size=_page_size(request),
                page_token=str(request.get("page_token") or "").strip(),
            )
        except CitiusError as error:
            return error_result(error)
        rows = [{"provider": p.provider_id, "templates": len(p.template_support)} for p in result.providers]
        return RpcResult(
            status=ResultStatus.OK,
            message=f"{len(rows)} provider(s)",
            response={
                "providers": rows,
                "next_page_token": result.next_page_token,
                "full_response": _full_response(result),
            },
        )

    async def get_provider(request: dict[str, Any]) -> RpcResult:
        try:
            info = await clients.providers.get_provider(_require_text(request, "provider_id"))
        except CitiusError as error:
            return error_result(error)
        return RpcResult(
            status=ResultStatus.OK,
            response={
                "provider": info.provider_id,
                "templates": {s.template_id: s.notes for s in info.template_support},
                "full_response": _full_response(info),
            },
        )

    async def match_providers(request: dict[str, Any]) -> RpcResult:
        """Rank the instances for a template, and say why every other one lost."""
        requirements = _provider_requirements(request)
        template_id = str(request.get("template_id") or "").strip()
        try:
            matches = await clients.providers.match_providers(
                template_id=template_id,
                requirements=requirements,
            )
            everyone = await clients.providers.list_provider_instances()
        except CitiusError as error:
            return error_result(error)
        required = requirements.to_proto() if requirements is not None else common_impl.ProviderRequirements()
        ranked = [
            {
                "rank": n,
                "instance_id": m.instance.instance_id,
                "score": m.match_score,
                **_implementation_summary(m.resolved_implementation),
            }
            for n, m in enumerate(matches.matches, start=1)
        ]
        chosen = {row["instance_id"] for row in ranked}
        excluded = []
        for instance in everyone.instances:
            if instance.instance_id in chosen:
                continue
            reasons = unmet_requirements(required, instance.implementation_override)
            if not reasons:
                reasons = [f"does not support template {template_id}" if template_id else "not selectable"]
            excluded.append({"instance_id": instance.instance_id, "why_not": reasons})
        message = f"CreateKey would choose {ranked[0]['instance_id']}" if ranked else "no instance can hold this key"
        return RpcResult(
            status=ResultStatus.OK,
            message=message,
            response={"ranked": ranked, "excluded": excluded, "full_response": _full_response(matches)},
        )

    for method, invoke in (
        ("ListProviders", list_providers),
        ("GetProvider", get_provider),
        ("ListProviderInstances", list_instances),
        ("GetProviderInstance", get_instance),
        ("MatchProviders", match_providers),
    ):
        registry.register(
            RpcAction(
                service="ProviderService",
                method=method,
                permission=PERMISSION_BY_METHOD[method],
                availability=Availability.AVAILABLE,
                invoke=_normalized(invoke),
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
