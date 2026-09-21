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
from citius_api.messages.metadata_pb2 import OperationMetadata as OperationMetadataProto
from citius_api.types import common_pb2 as common_types
from citius_api.types import implementation_pb2 as common_impl
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
DIGEST_SCOPE_PARAM_KEYS = SIGNATURE_SCOPE_PARAM_KEYS | {"hash_algorithm", "hash_algorithm_oid"}
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
            response={"plaintext": encode_bytes(result.plaintext)},
        )

    async def verify(request: dict[str, Any]) -> RpcResult:
        try:
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
        return RpcResult(status=ResultStatus.OK, response={"valid": result.valid})

    async def digest_sign(request: dict[str, Any]) -> RpcResult:
        try:
            built = sdk_crypto.digest_sign_request(
                _require_text(request, "key_name"),
                _base64_field(request, "digest"),
                context=_signature_context(request),
                hash_algorithm=_hash_algorithm(request),
            )
            _finalize_scope_params(built, request, allowed=DIGEST_SCOPE_PARAM_KEYS, default_arm="no_context")
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
                context=_signature_context(request),
                hash_algorithm=_hash_algorithm(request),
            )
            _finalize_scope_params(built, request, allowed=DIGEST_SCOPE_PARAM_KEYS, default_arm="no_context")
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
            built.scope_spec.CopyFrom(_key_scope_spec(request))
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
                _policy_document(request),
                request.get("format") or "json",
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
                _policy_document(request),
                request.get("format") or "json",
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
