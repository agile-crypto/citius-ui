from __future__ import annotations

from citius_ui.actions.artifacts import (
    Artifact,
    ArtifactKind,
    compatible_targets,
    is_compatible,
)


def test_signature_bundle_includes_metadata_and_message() -> None:
    artifact = Artifact(
        id="1",
        kind=ArtifactKind.SIGNATURE,
        key_name="demo-signing-key",
        key_version=5,
        value="sig-bytes",
        metadata={"key_version": 5, "api_version": "v1"},
        context={"message": "hello"},
    )
    bundle = artifact.bundle()
    assert bundle["key_name"] == "demo-signing-key"
    assert bundle["signature"] == "sig-bytes"
    assert bundle["metadata"]["key_version"] == 5
    assert bundle["message"] == "hello"


def test_ciphertext_bundle_uses_ciphertext_field() -> None:
    artifact = Artifact(
        id="2",
        kind=ArtifactKind.CIPHERTEXT,
        key_name="demo-encryption-key",
        value="ct-bytes",
        metadata={"key_version": 3},
    )
    assert artifact.bundle()["ciphertext"] == "ct-bytes"


def test_compatibility_handoffs() -> None:
    assert is_compatible(ArtifactKind.SIGNATURE, "CryptoService", "Verify")
    assert is_compatible(ArtifactKind.CIPHERTEXT, "CryptoService", "Decrypt")
    assert not is_compatible(ArtifactKind.SIGNATURE, "CryptoService", "Decrypt")
    assert ("KeyManagementService", "TransformKey") in compatible_targets(ArtifactKind.KEY)
    assert compatible_targets(ArtifactKind.DIGEST) == ()
