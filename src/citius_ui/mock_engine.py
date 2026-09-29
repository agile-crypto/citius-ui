"""Pure mock execution engine used to validate the proposed UI flows.

Nothing in this module performs cryptography or authenticates a user. It models
the product interaction contract so the UI can be reviewed before real gRPC and
OIDC integrations are implemented.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any

PERSONAS: dict[str, dict[str, Any]] = {
    "CISO": {
        "username": "citius-ciso",
        "description": "Govern policies and key lifecycle without using cryptographic operations.",
        "permissions": {
            "citius:policy:read",
            "citius:policy:write",
            "citius:keys:create",
            "citius:keys:read",
            "citius:keys:rotate",
            "citius:keys:update-policy",
            "citius:discovery:read",
            "citius:provider:read",
        },
        "allow": ["demo-*"],
        "deny": [],
    },
    "Producer": {
        "username": "citius-producer",
        "description": "Create/read keys, encrypt data, and sign messages.",
        "permissions": {
            "citius:policy:read",
            "citius:keys:create",
            "citius:keys:read",
            "citius:discovery:read",
            "citius:provider:read",
            "citius:crypto:sign",
            "citius:crypto:encrypt",
        },
        "allow": ["demo-*"],
        "deny": ["demo-restricted-*"],
    },
    "Consumer": {
        "username": "citius-consumer",
        "description": "Read keys, decrypt ciphertext, and verify signatures.",
        "permissions": {
            "citius:policy:read",
            "citius:keys:read",
            "citius:discovery:read",
            "citius:crypto:verify",
            "citius:crypto:decrypt",
        },
        "allow": ["demo-*"],
        "deny": ["demo-restricted-*"],
    },
}


SERVICES: dict[str, list[str]] = {
    "KeyManagementService": [
        "CreateKey",
        "ReadKey",
        "ListKeys",
        "DeleteKey",
        "RotateKey",
        "TransformKey",
        "UpdateKeyPolicy",
        "MigrateKey",
        "ValidateKeyOperation",
        "ExportKey",
        "ImportKey",
    ],
    "CryptoPolicyService": [
        "CreateCryptoPolicy",
        "ReadCryptoPolicy",
        "UpdateCryptoPolicy",
        "DeleteCryptoPolicy",
        "ListCryptoPolicies",
        "EvaluatePolicy",
        "BatchEvaluatePolicy",
    ],
    "CryptoService": [
        "Encrypt",
        "Decrypt",
        "Sign",
        "Verify",
        "DigestSign",
        "DigestVerify",
        "GenerateMAC",
        "VerifyMAC",
        "Digest",
        "Xof",
        "GenerateRandom",
        "SeedRandom",
    ],
    "AlgorithmDiscoveryService": ["ListTemplates", "GetTemplate", "ListScopes"],
    "ProviderService": [
        "ListProviders",
        "GetProvider",
        "RegisterProviderInstance",
        "ListProviderInstances",
        "GetProviderInstance",
        "UpdateProviderInstance",
        "DeleteProviderInstance",
        "MatchProviders",
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
        "EncryptUpdate",
        "EncryptFinal",
        "DecryptInit",
        "DecryptUpdate",
        "DecryptFinal",
        "SignInit",
        "SignUpdate",
        "SignFinal",
        "VerifyInit",
        "VerifyUpdate",
        "VerifyFinal",
    ],
}


IMPLEMENTED = {
    ("CryptoPolicyService", "CreateCryptoPolicy"),
    ("CryptoPolicyService", "ReadCryptoPolicy"),
    ("CryptoPolicyService", "UpdateCryptoPolicy"),
    ("KeyManagementService", "CreateKey"),
    ("KeyManagementService", "ReadKey"),
    ("KeyManagementService", "TransformKey"),
    ("KeyManagementService", "MigrateKey"),
    ("KeyManagementService", "ValidateKeyOperation"),
    ("KeyManagementService", "ListKeys"),
    ("CryptoService", "Encrypt"),
    ("CryptoService", "Decrypt"),
    ("CryptoService", "Sign"),
    ("CryptoService", "Verify"),
    ("CryptoService", "DigestSign"),
    ("CryptoService", "DigestVerify"),
}


PERMISSION_BY_METHOD = {
    "CreateCryptoPolicy": "citius:policy:write",
    "ReadCryptoPolicy": "citius:policy:read",
    "UpdateCryptoPolicy": "citius:policy:write",
    "DeleteCryptoPolicy": "citius:policy:write",
    "ListCryptoPolicies": "citius:policy:read",
    "EvaluatePolicy": "citius:policy:read",
    "BatchEvaluatePolicy": "citius:policy:read",
    "CreateKey": "citius:keys:create",
    "ReadKey": "citius:keys:read",
    "ListKeys": "citius:keys:read",
    "DeleteKey": "citius:keys:create",
    "RotateKey": "citius:keys:rotate",
    "TransformKey": "citius:keys:rotate",
    "UpdateKeyPolicy": "citius:keys:update-policy",
    "MigrateKey": "citius:keys:rotate",
    "ValidateKeyOperation": "citius:keys:read",
    "ExportKey": "citius:keys:read",
    "ImportKey": "citius:keys:create",
    "Encrypt": "citius:crypto:encrypt",
    "Decrypt": "citius:crypto:decrypt",
    "Sign": "citius:crypto:sign",
    "DigestSign": "citius:crypto:sign",
    "Verify": "citius:crypto:verify",
    "DigestVerify": "citius:crypto:verify",
    "ListTemplates": "citius:discovery:read",
    "GetTemplate": "citius:discovery:read",
    "ListScopes": "citius:discovery:read",
    "ListProviders": "citius:provider:read",
    "GetProvider": "citius:provider:read",
    "ListProviderInstances": "citius:provider:read",
    "GetProviderInstance": "citius:provider:read",
    "MatchProviders": "citius:provider:read",
    "RegisterProviderInstance": "citius:provider:write",
    "UpdateProviderInstance": "citius:provider:write",
    "DeleteProviderInstance": "citius:provider:write",
}


REQUEST_EXAMPLES: dict[tuple[str, str], dict[str, Any]] = {
    ("CryptoPolicyService", "CreateCryptoPolicy"): {
        "name": "demo-signing-policy",
        "policy_document": {
            "version": "v1",
            "allowed_operations": ["SIGN", "VERIFY"],
            "allowed_templates": ["ecdsa-p256-sha256"],
            "allowed_providers": ["software"],
        },
    },
    ("CryptoPolicyService", "ReadCryptoPolicy"): {"name": "demo-signing-policy"},
    ("CryptoPolicyService", "UpdateCryptoPolicy"): {
        "name": "demo-signing-policy",
        "policy_document": {"version": "v2", "allowed_operations": ["SIGN", "VERIFY"]},
    },
    ("KeyManagementService", "CreateKey"): {
        "name": "demo-signing-key",
        "policy": "demo-signing-policy",
        "template_id": "ecdsa-p256-sha256",
        "provider_id": "software",
        "provider_requirements": {"constant_time": True, "memory_safe": True},
    },
    ("KeyManagementService", "ReadKey"): {"name": "demo-signing-key"},
    ("KeyManagementService", "TransformKey"): {
        "name": "demo-signing-key",
        "retain_key_bytes": False,
        "template_id": "ml-dsa-65",
    },
    ("KeyManagementService", "MigrateKey"): {
        "name": "demo-signing-key",
        "strategy": "PROVIDER_SWITCH",
        "target_instance_id": "openssl",
    },
    ("KeyManagementService", "ValidateKeyOperation"): {
        "name": "demo-signing-key",
        "target_instance_id": "openssl",
    },
    ("KeyManagementService", "ListKeys"): {},
    ("CryptoService", "Sign"): {"key_name": "demo-signing-key", "message": "Hello from Citius"},
    ("CryptoService", "Verify"): {
        "key_name": "demo-signing-key",
        "message": "Hello from Citius",
        "signature": "use-latest-signature",
        "metadata": "use-latest-metadata",
    },
    ("CryptoService", "Encrypt"): {
        "key_name": "demo-encryption-key",
        "plaintext": "Sensitive demo payload",
        "additional_authenticated_data": "tenant=demo",
    },
    ("CryptoService", "Decrypt"): {
        "key_name": "demo-encryption-key",
        "ciphertext": "use-latest-ciphertext",
        "metadata": "use-latest-metadata",
        "additional_authenticated_data": "tenant=demo",
    },
}


SCENARIO_STEPS = [
    ("CISO", "Create a restrictive signing policy", "CryptoPolicyService", "CreateCryptoPolicy"),
    ("Producer", "Create a governed signing key", "KeyManagementService", "CreateKey"),
    ("Producer", "Sign a message", "CryptoService", "Sign"),
    ("Producer", "Attempt Verify and observe method denial", "CryptoService", "Verify"),
    ("Consumer", "Verify the producer's signature", "CryptoService", "Verify"),
    ("Consumer", "Attempt Sign and observe method denial", "CryptoService", "Sign"),
    ("Producer", "Attempt an allowed method on a denied key", "CryptoService", "Sign"),
    ("CISO", "Transform the key to a post-quantum template", "KeyManagementService", "TransformKey"),
    ("Consumer", "Verify the pre-transform signature using its recorded key version", "CryptoService", "Verify"),
]


def initial_state() -> dict[str, Any]:
    return {
        "authenticated_persona": None,
        "policies": {},
        "keys": {},
        "key_versions": {},
        "history": [],
        "artifacts": {"signatures": [], "ciphertexts": []},
        "scenario_step": 0,
    }


def producer_response_rows(state: dict[str, Any] | None) -> list[list[Any]]:
    """Return copyable producer responses in the reference UI's append-only style."""
    artifacts = (state or {}).get("artifacts", {})
    records = [*artifacts.get("signatures", []), *artifacts.get("ciphertexts", [])]
    rows: list[list[Any]] = []
    for artifact in records:
        value_field = "signature" if artifact["kind"] == "Signature" else "ciphertext"
        bundle: dict[str, Any] = {
            "key_name": artifact["key_name"],
            value_field: artifact["value"],
            "metadata": artifact["metadata"],
        }
        if artifact["kind"] == "Signature":
            bundle["message"] = artifact["input"]
        else:
            bundle["additional_authenticated_data"] = artifact.get("additional_authenticated_data", "")
        rows.append(
            [
                artifact["created_at"],
                artifact["source_operation"],
                artifact["kind"],
                artifact["key_name"],
                artifact["key_version"],
                json.dumps(bundle, sort_keys=True),
            ]
        )
    return rows


def request_example(service: str, method: str) -> dict[str, Any]:
    return copy.deepcopy(
        REQUEST_EXAMPLES.get(
            (service, method),
            {"note": f"Mock request for {service}.{method}"},
        )
    )


def execute(
    state: dict[str, Any] | None,
    persona_name: str,
    service: str,
    method: str,
    request: dict[str, Any],
    *,
    scenario_run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    state = copy.deepcopy(state or initial_state())
    persona = PERSONAS[persona_name]
    permission = PERMISSION_BY_METHOD.get(method, "citius:crypto:misc")
    key_name = str(request.get("key_name") or request.get("name") or "")
    policy_name = str(request.get("policy_name") or request.get("policy") or request.get("name") or "")

    if permission not in persona["permissions"]:
        result = _error(
            "PERMISSION_DENIED",
            f"{persona['username']} is missing {permission}",
            "method_permission",
        )
    elif _resource_denied(persona_name, service, key_name, policy_name):
        resource = key_name if service != "CryptoPolicyService" else policy_name
        result = _error(
            "PERMISSION_DENIED",
            f"{persona['username']} cannot access resource {resource!r}",
            "resource_pattern",
        )
    elif (service, method) not in IMPLEMENTED:
        result = _error("UNIMPLEMENTED", f"{service}.{method} is defined but not implemented", "server")
    else:
        result = _dispatch(state, service, method, request)
        if method == "ListKeys" and result["status"] == "OK":
            # Like the server: keys the persona may not read are left out.
            result["response"]["keys"] = [
                k for k in result["response"]["keys"] if not _resource_denied(persona_name, service, k["name"], "")
            ]

    _record(state, persona_name, service, method, request, result, scenario_run_id)
    return state, result


def run_scenario_step(state: dict[str, Any] | None, persona_name: str) -> tuple[dict[str, Any], dict[str, Any], bool]:
    state = copy.deepcopy(state or initial_state())
    index = int(state.get("scenario_step", 0))
    if index >= len(SCENARIO_STEPS):
        return state, {"status": "COMPLETE", "message": "Scenario complete."}, True

    expected_persona, title, service, method = SCENARIO_STEPS[index]
    if persona_name != expected_persona:
        return (
            state,
            {
                "status": "IDENTITY_SWITCH_REQUIRED",
                "message": f"Switch to {expected_persona} to continue: {title}",
            },
            False,
        )

    request = request_example(service, method)
    if index == 3:
        request["signature"] = state["artifacts"].get("latest_signature", "missing")
    elif index == 4:
        request["signature"] = state["artifacts"].get("latest_signature", "missing")
    elif index == 5:
        request = {"key_name": "demo-signing-key", "message": "Consumer must not sign"}
    elif index == 6:
        request = {"key_name": "demo-restricted-key", "message": "Resource denial"}
    elif index == 8:
        signature = state["artifacts"]["signatures"][0]
        request = {
            "key_name": signature["key_name"],
            "message": signature["input"],
            "signature": signature["value"],
            "metadata": signature["metadata"],
        }

    state, result = execute(
        state,
        persona_name,
        service,
        method,
        request,
        scenario_run_id="identity-showcase",
    )
    expected_denial = index in {3, 5, 6} and result["status"] == "PERMISSION_DENIED"
    if result["status"] == "OK" or expected_denial:
        state["scenario_step"] = index + 1
    return state, result, state["scenario_step"] >= len(SCENARIO_STEPS)


def history_rows(state: dict[str, Any] | None, service_filter: str = "All services") -> list[list[Any]]:
    records = (state or {}).get("history", [])
    if service_filter != "All services":
        records = [record for record in records if record["service"] == service_filter]
    return [
        [
            record["id"],
            record["time"],
            record["persona"],
            record["service"],
            record["method"],
            record["status"],
            record["resource"],
        ]
        for record in reversed(records)
    ]


def history_record(state: dict[str, Any] | None, record_id: str) -> dict[str, Any]:
    for record in (state or {}).get("history", []):
        if record["id"] == record_id:
            return copy.deepcopy(record)
    return {"status": "NOT_FOUND", "message": f"No history record {record_id!r}"}


def artifact_rows(state: dict[str, Any] | None) -> list[list[Any]]:
    artifacts = (state or {}).get("artifacts", {})
    records = [*artifacts.get("signatures", []), *artifacts.get("ciphertexts", [])]
    return [
        [
            artifact["id"],
            artifact["created_at"],
            artifact["kind"],
            artifact["producer"],
            artifact["key_name"],
            artifact["key_version"],
            artifact["source_operation"],
        ]
        for artifact in reversed(records)
    ]


def artifact_ids(state: dict[str, Any] | None) -> list[str]:
    return [row[0] for row in artifact_rows(state)]


def artifact_record(state: dict[str, Any] | None, artifact_id: str) -> dict[str, Any]:
    artifacts = (state or {}).get("artifacts", {})
    for artifact in [*artifacts.get("signatures", []), *artifacts.get("ciphertexts", [])]:
        if artifact["id"] == artifact_id:
            return copy.deepcopy(artifact)
    return {"status": "NOT_FOUND", "message": f"No artifact {artifact_id!r}"}


def consumer_request_for_artifact(state: dict[str, Any] | None, artifact_id: str) -> tuple[str, dict[str, Any]]:
    artifact = artifact_record(state, artifact_id)
    if artifact.get("status") == "NOT_FOUND":
        raise ValueError(artifact["message"])
    if artifact["kind"] == "Signature":
        return "Verify", {
            "key_name": artifact["key_name"],
            "message": artifact["input"],
            "signature": artifact["value"],
            "metadata": artifact["metadata"],
        }
    return "Decrypt", {
        "key_name": artifact["key_name"],
        "ciphertext": artifact["value"],
        "metadata": artifact["metadata"],
        "additional_authenticated_data": artifact.get("additional_authenticated_data", ""),
    }


def scenario_progress(state: dict[str, Any] | None) -> str:
    index = int((state or {}).get("scenario_step", 0))
    completed = min(index, len(SCENARIO_STEPS))
    lines = [f"### Identity showcase · {completed}/{len(SCENARIO_STEPS)} steps"]
    for step_index, (persona, title, _, _) in enumerate(SCENARIO_STEPS):
        if step_index < index:
            marker = "✅"
        elif step_index == index:
            marker = "▶️"
        else:
            marker = "○"
        lines.append(f"{marker} **{persona}** — {title}")
    if index >= len(SCENARIO_STEPS):
        lines.append(
            "\n**Complete:** method and resource authorization were exercised using one shared operation history."
        )
    return "\n\n".join(lines)


def persona_summary(persona_name: str) -> str:
    persona = PERSONAS[persona_name]
    permissions = " · ".join(sorted(persona["permissions"]))
    deny = ", ".join(persona["deny"]) or "none"
    return (
        f"### {persona['username']}\n"
        f"{persona['description']}\n\n"
        f"**Key/policy scope:** `demo-*` · **Explicit deny:** `{deny}`\n\n"
        f"<small>{permissions}</small>"
    )


def _resource_denied(persona_name: str, service: str, key_name: str, policy_name: str) -> bool:
    candidate = policy_name if service == "CryptoPolicyService" else key_name
    if not candidate:
        return False
    persona = PERSONAS[persona_name]
    if any(fnmatchcase(candidate, pattern) for pattern in persona["deny"]):
        return True
    return not any(fnmatchcase(candidate, pattern) for pattern in persona["allow"])


_MOCK_INSTANCES = ("software", "openssl")
# Every strategy the API defines, in core's order, and the ones it carries out.
_ALL_STRATEGIES = (
    "PROVIDER_SWITCH",
    "EXTRACT_AND_IMPORT",
    "WRAPPED_TRANSFER",
    "REKEY_AND_ARCHIVE",
    "REKEY_AND_DESTROY",
)
_MOCK_STRATEGIES = ("PROVIDER_SWITCH", "REKEY_AND_ARCHIVE")


def _strategy(value: Any) -> str:
    return str(value or "").upper().removeprefix("MIGRATION_STRATEGY_").removesuffix("UNSPECIFIED")


def _recommend(options: list[dict[str, Any]]) -> tuple[str, str]:
    """Core's recommendation: provider switch if it can, else rekey and archive."""
    feasible = {o["strategy"] for o in options if o["feasible"]}
    if "MIGRATION_STRATEGY_PROVIDER_SWITCH" in feasible:
        return "MIGRATION_STRATEGY_PROVIDER_SWITCH", "the key's material moves unchanged"
    if "MIGRATION_STRATEGY_REKEY_AND_ARCHIVE" in feasible:
        return "MIGRATION_STRATEGY_REKEY_AND_ARCHIVE", "new material is generated on the target"
    return "MIGRATION_STRATEGY_UNSPECIFIED", "none of the assessed strategies can migrate the key to the target"


def _mock_migration(state: dict[str, Any], method: str, request: dict[str, Any]) -> dict[str, Any]:
    """Mock MigrateKey and its side-effect-free check, over the two in-process instances.

    It follows core's order: the request's shape is checked first
    (INVALID_ARGUMENT, or UNIMPLEMENTED for a strategy MigrateKey does not
    carry out), then the key is read, then the target judged. MigrateKey
    fails on a refused target; ValidateKeyOperation reports the refusal as
    each strategy's reason and still answers OK. Each mock instance is the
    only instance of its provider type.
    """
    name = str(request.get("name", ""))
    instance = str(request.get("target_instance_id") or "")
    provider = str(request.get("target_provider_id") or "")
    if not name:
        return _error("INVALID_ARGUMENT", "key name is required", "validation")
    if bool(instance) == bool(provider):
        return _error(
            "INVALID_ARGUMENT", "exactly one of target instance ID or target provider ID is required", "validation"
        )
    if method == "MigrateKey":
        strategy = _strategy(request.get("strategy"))
        if not strategy:
            return _error("INVALID_ARGUMENT", "migration strategy is required", "validation")
        if strategy not in _ALL_STRATEGIES:
            return _error("INVALID_ARGUMENT", f"unknown migration strategy {strategy}", "validation")
        if strategy not in _MOCK_STRATEGIES:
            return _error(
                "UNIMPLEMENTED", f"migration strategy MIGRATION_STRATEGY_{strategy} is not implemented", "server"
            )
    else:
        preferred = _strategy(request.get("preferred_strategy"))
        if preferred and preferred not in _ALL_STRATEGIES:
            return _error("INVALID_ARGUMENT", f"unknown migration strategy {preferred}", "validation")
    if name not in state["keys"]:
        return _error("NOT_FOUND", f"key {name!r} not found", "storage")
    source = state["keys"][name]["provider"]
    target = instance or provider
    refusal: tuple[str, str] | None = None
    if target not in _MOCK_INSTANCES:
        refusal = ("NOT_FOUND", f"no provider instance {target!r}")
    elif target == source:
        refusal = ("FAILED_PRECONDITION", f"key is already on provider instance {source!r}")
    if method == "ValidateKeyOperation":
        options = []
        for s in [preferred] if preferred else list(_ALL_STRATEGIES):
            option: dict[str, Any] = {"strategy": f"MIGRATION_STRATEGY_{s}", "feasible": False}
            if refusal is not None:
                option["infeasibility_reason"] = refusal[1]
            elif s not in _MOCK_STRATEGIES:
                option["infeasibility_reason"] = f"MIGRATION_STRATEGY_{s} is not implemented"
            else:
                option["feasible"] = True
            options.append(option)
        recommended, reason = _recommend(options)
        return _ok(
            {
                "current_state": {
                    "instance_id": source,
                    "template_id": state["keys"][name]["template_id"],
                    "extractable": bool(state["keys"][name].get("extractable", False)),
                },
                "options": options,
                "recommended_strategy": recommended,
                "recommendation_reason": reason,
            }
        )
    if refusal is not None:
        return _error(refusal[0], refusal[1], "provider")
    state["keys"][name]["version"] += 1
    state["keys"][name]["provider"] = target
    after = copy.deepcopy(state["keys"][name])
    state["key_versions"].setdefault(name, {})[str(after["version"])] = copy.deepcopy(after)
    response: dict[str, Any] = {
        "success": True,
        "key_metadata": after,
        "result": {
            "strategy_used": f"MIGRATION_STRATEGY_{strategy}",
            "key_bytes_preserved": strategy == "PROVIDER_SWITCH",
            "source_instance_id": source,
            "target_instance_id": target,
            # Each mock instance is the only instance of its provider type.
            "source_provider_id": source,
            "target_provider_id": target,
        },
    }
    if strategy == "REKEY_AND_ARCHIVE":
        # Like core: the archived version keeps the key's name and is
        # addressed by version on its old provider.
        response["archived_key_info"] = {"archived_key_name": name, "provider_id": source}
    return _ok(response)


def _dispatch(state: dict[str, Any], service: str, method: str, request: dict[str, Any]) -> dict[str, Any]:
    if method in {"CreateCryptoPolicy", "UpdateCryptoPolicy"}:
        name = str(request.get("name", ""))
        if not name:
            return _error("INVALID_ARGUMENT", "name is required", "validation")
        state["policies"][name] = copy.deepcopy(request.get("policy_document", {}))
        return _ok({"success": True, "name": name, "message": "Policy stored by mock service"})

    if method == "ReadCryptoPolicy":
        name = str(request.get("name", ""))
        if name not in state["policies"]:
            return _error("NOT_FOUND", f"policy {name!r} not found", "storage")
        return _ok({"name": name, "policy_document": state["policies"][name]})

    if method == "CreateKey":
        name = str(request.get("name", ""))
        policy = str(request.get("policy", ""))
        if not name or not policy:
            return _error("INVALID_ARGUMENT", "name and policy are required", "validation")
        if policy not in state["policies"]:
            return _error("NOT_FOUND", f"policy {policy!r} not found", "storage")
        metadata = {
            "name": name,
            "version": 1,
            "key_id": f"mock-{hashlib.sha256(name.encode()).hexdigest()[:12]}",
            "template_id": request.get("template_id", "auto-selected-template"),
            "provider": request.get("provider_id", "software"),
            "policy": policy,
            "implementation_properties": {
                "constant_time": True,
                "memory_safe_language": True,
                "implementation_language": "Go",
            },
            "security_guarantees": {"security_strength_bits": 128},
        }
        state["keys"][name] = metadata
        state["key_versions"][name] = {"1": copy.deepcopy(metadata)}
        state["artifacts"]["latest_key"] = name
        return _ok({"success": True, "key_metadata": metadata})

    if method == "ReadKey":
        name = str(request.get("name", ""))
        if name not in state["keys"]:
            return _error("NOT_FOUND", f"key {name!r} not found", "storage")
        try:
            version = int(request.get("version") or 0)
        except (TypeError, ValueError):
            return _error("INVALID_ARGUMENT", "version must be a whole number", "validation")
        if version < 0:
            return _error("INVALID_ARGUMENT", "version must not be negative", "validation")
        if version:
            recorded = state["key_versions"].get(name, {}).get(str(version))
            if recorded is None:
                return _error("NOT_FOUND", f"key {name!r} has no version {version}", "storage")
            return _ok({"key_metadata": recorded})
        return _ok({"key_metadata": state["keys"][name]})

    if method == "TransformKey":
        name = str(request.get("name", ""))
        if name not in state["keys"]:
            return _error("NOT_FOUND", f"key {name!r} not found", "storage")
        before = copy.deepcopy(state["keys"][name])
        state["keys"][name]["version"] += 1
        state["keys"][name]["template_id"] = request.get("template_id", "auto-selected-template")
        after = copy.deepcopy(state["keys"][name])
        state["key_versions"].setdefault(name, {})[str(after["version"])] = copy.deepcopy(after)
        return _ok({"success": True, "before": before, "after": after})

    if method == "ListKeys":
        keys = [copy.deepcopy(state["keys"][name]) for name in sorted(state["keys"])]
        return _ok({"keys": keys, "next_page_token": ""})

    if method in {"MigrateKey", "ValidateKeyOperation"}:
        return _mock_migration(state, method, request)

    if method in {"Sign", "DigestSign"}:
        key = str(request.get("key_name", ""))
        if key not in state["keys"] and not key.startswith("demo-restricted-"):
            return _error("NOT_FOUND", f"key {key!r} not found", "storage")
        message = str(request.get("message") or request.get("digest") or "")
        key_version = int(state["keys"].get(key, {}).get("version", 1))
        signature = "mock-sig:" + hashlib.sha256(f"{key}:{key_version}:{message}".encode()).hexdigest()
        metadata = _operation_metadata(key_version, "raw")
        state["artifacts"]["latest_signature"] = signature
        state["artifacts"]["latest_signed_message"] = message
        state["artifacts"]["latest_signature_metadata"] = metadata
        return _ok({"signature": signature, "metadata": metadata})

    if method in {"Verify", "DigestVerify"}:
        key = str(request.get("key_name", ""))
        message = str(request.get("message") or request.get("digest") or "")
        signature = str(request.get("signature", ""))
        metadata = request.get("metadata")
        if signature == "use-latest-signature":
            signature = state["artifacts"].get("latest_signature", "")
        if metadata == "use-latest-metadata":
            metadata = state["artifacts"].get("latest_signature_metadata", {})
        key_version = _requested_key_version(state, key, metadata)
        expected = "mock-sig:" + hashlib.sha256(f"{key}:{key_version}:{message}".encode()).hexdigest()
        return _ok(
            {
                "valid": signature == expected,
                "metadata": _operation_metadata(key_version, "raw"),
                "compatibility": _compatibility_label(state, key, key_version),
            }
        )

    if method == "Encrypt":
        key = str(request.get("key_name", ""))
        if key not in state["keys"]:
            return _error("NOT_FOUND", f"key {key!r} not found", "storage")
        plaintext = str(request.get("plaintext", ""))
        key_version = int(state["keys"][key]["version"])
        ciphertext = f"mock-ct:v{key_version}:" + base64.urlsafe_b64encode(plaintext[::-1].encode()).decode()
        metadata = _operation_metadata(key_version, "raw", aead=True)
        state["artifacts"]["latest_ciphertext"] = ciphertext
        state["artifacts"]["latest_ciphertext_metadata"] = metadata
        state["artifacts"]["latest_aad"] = request.get("additional_authenticated_data", "")
        return _ok({"ciphertext": ciphertext, "metadata": metadata})

    if method == "Decrypt":
        ciphertext = str(request.get("ciphertext", ""))
        metadata = request.get("metadata")
        if ciphertext == "use-latest-ciphertext":
            ciphertext = state["artifacts"].get("latest_ciphertext", "")
        if metadata == "use-latest-metadata":
            metadata = state["artifacts"].get("latest_ciphertext_metadata", {})
        if not ciphertext.startswith("mock-ct:v"):
            return _error("INVALID_ARGUMENT", "not a mock ciphertext", "validation")
        try:
            prefix, encoded = ciphertext.rsplit(":", 1)
            embedded_version = int(prefix.removeprefix("mock-ct:v"))
            key = str(request.get("key_name", ""))
            key_version = _requested_key_version(state, key, metadata)
            if key_version != embedded_version:
                return _error(
                    "FAILED_PRECONDITION",
                    "ciphertext metadata selects the wrong key version",
                    "key_version",
                )
            plaintext = base64.urlsafe_b64decode(encoded).decode()[::-1]
        except Exception:
            return _error("INVALID_ARGUMENT", "malformed mock ciphertext", "validation")
        return _ok(
            {
                "plaintext": plaintext,
                "metadata": _operation_metadata(key_version, "raw", aead=True),
                "compatibility": _compatibility_label(state, key, key_version),
            }
        )

    return _error("UNIMPLEMENTED", f"No mock implementation for {service}.{method}", "mock")


def _ok(response: dict[str, Any]) -> dict[str, Any]:
    return {"status": "OK", "response": response, "mock": True}


def _error(code: str, message: str, category: str) -> dict[str, Any]:
    return {"status": code, "error": {"message": message, "category": category}, "mock": True}


def _operation_metadata(key_version: int, encoding: str, *, aead: bool = False) -> dict[str, Any]:
    algorithm_output: dict[str, Any]
    if aead:
        algorithm_output = {"aead_output": {"nonce": "mock-nonce-12b", "tag_length_bytes": 16}}
    else:
        algorithm_output = {"no_output": {}}
    return {
        "key_version": key_version,
        "provider_output": {
            "algorithm_output": algorithm_output,
            "encoding": encoding,
        },
        "api_version": "1.0",
    }


def _requested_key_version(state: dict[str, Any], key_name: str, metadata: Any) -> int:
    if isinstance(metadata, dict) and metadata.get("key_version"):
        return int(metadata["key_version"])
    return int(state.get("keys", {}).get(key_name, {}).get("version", 1))


def _compatibility_label(state: dict[str, Any], key_name: str, key_version: int) -> str:
    current = int(state.get("keys", {}).get(key_name, {}).get("version", key_version))
    if key_version < current:
        return f"historical key version {key_version} resolved; current version is {current}"
    return f"current key version {key_version}"


def _record(
    state: dict[str, Any],
    persona: str,
    service: str,
    method: str,
    request: dict[str, Any],
    result: dict[str, Any],
    scenario_run_id: str | None,
) -> None:
    number = len(state["history"]) + 1
    resource = str(request.get("key_name") or request.get("name") or request.get("policy_name") or "—")
    operation_id = f"op-{number:03d}"
    state["history"].append(
        {
            "id": operation_id,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "persona": persona,
            "service": service,
            "method": method,
            "status": result["status"],
            "duration_ms": 12 + number * 3,
            "resource": resource,
            "request": copy.deepcopy(request),
            "result": copy.deepcopy(result),
            "scenario_run_id": scenario_run_id,
        }
    )
    if result["status"] == "OK" and method in {"Sign", "DigestSign", "Encrypt"}:
        response = result["response"]
        is_signature = method in {"Sign", "DigestSign"}
        collection = "signatures" if is_signature else "ciphertexts"
        value_field = "signature" if is_signature else "ciphertext"
        artifact_number = sum(len(state["artifacts"].get(name, [])) for name in ("signatures", "ciphertexts")) + 1
        artifact = {
            "id": f"artifact-{artifact_number:03d}",
            "created_at": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "kind": "Signature" if is_signature else "Ciphertext",
            "producer": persona,
            "source_operation": operation_id,
            "key_name": str(request.get("key_name", "")),
            "key_version": response["metadata"]["key_version"],
            "value": response[value_field],
            "metadata": copy.deepcopy(response["metadata"]),
            "input": str(request.get("message") or request.get("digest") or request.get("plaintext") or ""),
        }
        if not is_signature:
            artifact["additional_authenticated_data"] = request.get("additional_authenticated_data", "")
        state["artifacts"].setdefault(collection, []).append(artifact)


def parse_json(value: str) -> dict[str, Any]:
    parsed = json.loads(value or "{}")
    if not isinstance(parsed, dict):
        raise ValueError("request must be a JSON object")
    return parsed
