"""Typed cryptographic artifacts and their compatibility hand-offs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ArtifactKind(str, Enum):
    """Kinds of artifacts extracted from RPC responses."""

    KEY = "key"
    POLICY = "policy"
    TEMPLATE = "template"
    PROVIDER = "provider"
    PLAINTEXT = "plaintext"
    CIPHERTEXT = "ciphertext"
    SIGNATURE = "signature"
    DIGEST = "digest"
    PUBLIC_KEY = "public_key"


@dataclass(frozen=True, slots=True)
class Artifact:
    """A produced value bundled with the metadata required to reuse it.

    For long-lived cryptographic outputs the value and the complete operation
    metadata are one logical bundle. metadata retains at least key_version,
    provider_output, and api_version so a later Verify or Decrypt can replay
    against the original key version.
    """

    id: str
    kind: ArtifactKind
    key_name: str
    key_version: int | None = None
    value: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)

    def bundle(self) -> dict[str, Any]:
        """Return a JSON-safe copyable bundle for reuse in a compatible RPC."""
        payload: dict[str, Any] = {"key_name": self.key_name}
        if self.value is not None:
            payload[_value_field(self.kind)] = self.value
        if self.metadata:
            payload["metadata"] = self.metadata
        payload.update(self.context)
        return payload


def _value_field(kind: ArtifactKind) -> str:
    if kind is ArtifactKind.SIGNATURE:
        return "signature"
    if kind is ArtifactKind.CIPHERTEXT:
        return "ciphertext"
    if kind is ArtifactKind.PLAINTEXT:
        return "plaintext"
    if kind is ArtifactKind.DIGEST:
        return "digest"
    return "value"


_HANDOFFS: dict[ArtifactKind, tuple[tuple[str, str], ...]] = {
    ArtifactKind.CIPHERTEXT: (("CryptoService", "Decrypt"),),
    ArtifactKind.SIGNATURE: (("CryptoService", "Verify"),),
    ArtifactKind.KEY: (
        ("KeyManagementService", "ReadKey"),
        ("KeyManagementService", "TransformKey"),
    ),
    ArtifactKind.POLICY: (("KeyManagementService", "CreateKey"),),
    ArtifactKind.TEMPLATE: (("KeyManagementService", "CreateKey"),),
    ArtifactKind.PROVIDER: (
        ("KeyManagementService", "CreateKey"),
        ("KeyManagementService", "MigrateKey"),
    ),
}


def compatible_targets(kind: ArtifactKind) -> tuple[tuple[str, str], ...]:
    """Return the (service, method) targets an artifact kind can be sent to."""
    return _HANDOFFS.get(kind, ())


def is_compatible(kind: ArtifactKind, service: str, method: str) -> bool:
    """Report whether an artifact kind can be handed off to a given RPC."""
    return (service, method) in _HANDOFFS.get(kind, ())
