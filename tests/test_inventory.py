"""Crypto inventory: joining keys, templates and instances, and the CBOM export."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

import grpc
from citius_api.messages.key_management_pb2 import ListKeysResponse
from citius_api.services.provider_service_pb2 import ListProviderInstancesResponse
from citius_api.types import common_pb2 as common_types
from citius_api.types.templates_pb2 import TemplateInfo
from citius_sdk.errors import NotFoundError, PermissionDeniedError
from citius_sdk.services.key_management import KeyMetadataView, ListKeysResult

from citius_ui.showcases.inventory import build_inventory, collect, render_markdown, to_cyclonedx


def _template(template_id: str, *, name: str, primitive: str, quantum: bool, level: int = 0) -> TemplateInfo:
    t = TemplateInfo(template_id=template_id, display_name=name)
    t.cyclonedx.name = name
    t.cyclonedx.primitive = primitive
    t.cyclonedx.nist_quantum_security_level = level
    t.cyclonedx.classical_security_level = 128
    t.cyclonedx.oid = "1.2.3"
    t.cyclonedx.crypto_functions.extend(["sign", "verify"])
    cap = t.scoped_capabilities.add()
    if primitive == "signature":
        cap.scope.signature.security.quantum_safe = quantum
        cap.scope.signature.security.fips_approved = True
    else:
        cap.scope.aead.security.quantum_safe = quantum
        cap.scope.aead.security.fips_approved = True
    return t


TEMPLATES = {
    "ml-dsa-65": _template("ml-dsa-65", name="ML-DSA-65", primitive="signature", quantum=True, level=3),
    "ecdsa-p256-sha256-der": _template(
        "ecdsa-p256-sha256-der", name="ECDSA-P256-SHA256", primitive="signature", quantum=False
    ),
    "aes-256-gcm-128-96": _template("aes-256-gcm-128-96", name="AES-256-GCM", primitive="ae", quantum=False),
}


def _keys() -> ListKeysResponse:
    response = ListKeysResponse()
    for name, template, provider in (
        ("pq-key", "ml-dsa-65", "openssl-fips"),
        ("classic-key", "ecdsa-p256-sha256-der", "software"),
        ("data-key", "aes-256-gcm-128-96", "openssl"),
        ("orphan-key", "retired-template", "software"),
    ):
        k = response.keys.add(name=name, version=2, template_id=template, provider=provider)
        k.lifecycle_state = common_types.KeyLifecycleState.KEY_LIFECYCLE_STATE_ACTIVE
    return response


def _instances() -> ListProviderInstancesResponse:
    response = ListProviderInstancesResponse()
    for instance_id in ("software", "openssl", "openssl-fips"):
        i = response.instances.add(instance_id=instance_id)
        if instance_id == "openssl-fips":
            i.implementation_override.fips_140.certified = True
            i.implementation_override.fips_140.level = 1
    return response


def _views() -> list[KeyMetadataView]:
    return ListKeysResult(_keys()).keys


def test_rows_read_quantum_safety_and_fips_from_the_catalogue_and_instances() -> None:
    inv = build_inventory(_views(), dict(TEMPLATES), {i.instance_id: i for i in _instances().instances})
    rows = {r.name: r for r in inv.rows}
    assert rows["pq-key"].pq_ready and rows["pq-key"].fips_ready
    assert rows["pq-key"].provider_fips_140 == "FIPS_140_LEVEL_1"
    assert rows["classic-key"].quantum_safe is False and not rows["classic-key"].fips_ready
    assert rows["classic-key"].provider_fips_140 == "not certified"
    orphan = rows["orphan-key"]
    assert orphan.quantum_safe is None and orphan.algorithm is None
    assert inv.summary() == {
        "keys": 4,
        "quantum_safe": 1,
        "not_quantum_safe": 2,
        "fips_approved_algorithm": 3,
        "on_fips_provider": 1,
        "quantum_safe_and_fips": 1,
        "unknown": 1,
    }
    assert "4 key(s)" in render_markdown(inv)


def test_unreadable_catalogues_leave_columns_unknown() -> None:
    inv = build_inventory(_views(), None, None)
    assert inv.unreadable == {"templates": "not read", "providers": "not read"}
    assert all(r.quantum_safe is None and r.provider_fips_140 is None for r in inv.rows)
    assert "Could not read: templates (not read), providers (not read)." in render_markdown(inv)


def test_cbom_links_each_key_to_its_algorithm() -> None:
    inv = build_inventory(_views(), dict(TEMPLATES), {i.instance_id: i for i in _instances().instances})
    bom = to_cyclonedx(inv, timestamp=datetime(2026, 9, 28, 12, 0, tzinfo=UTC), serial="urn:uuid:x")
    assert (bom["bomFormat"], bom["specVersion"], bom["metadata"]["timestamp"]) == (
        "CycloneDX",
        "1.6",
        "2026-09-28T12:00:00Z",
    )
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    algorithm = by_ref["algorithm:ml-dsa-65"]["cryptoProperties"]
    assert algorithm["assetType"] == "algorithm"
    assert algorithm["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert algorithm["oid"] == "1.2.3"
    pq = by_ref["key:pq-key"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert pq == {"type": "private-key", "state": "active", "algorithmRef": "algorithm:ml-dsa-65"}
    data = by_ref["key:data-key"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert data["type"] == "secret-key"
    # A key whose template is unreadable has no algorithm to reference.
    assert "algorithmRef" not in by_ref["key:orphan-key"]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert {"ref": "key:pq-key", "dependsOn": ["algorithm:ml-dsa-65"]} in bom["dependencies"]
    assert not any(d["ref"] == "key:orphan-key" for d in bom["dependencies"])


class _Keys:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def list_keys(self, request: object) -> ListKeysResult:
        token = request.page_token  # type: ignore[attr-defined]
        self.tokens.append(token)
        full = _keys()
        response = ListKeysResponse()
        start = int(token or 0)
        response.keys.extend(full.keys[start : start + 2])
        if start + 2 < len(full.keys):
            response.next_page_token = str(start + 2)
        return ListKeysResult(response)


class _Discovery:
    async def get_template(self, template_id: str) -> TemplateInfo:
        if template_id not in TEMPLATES:
            raise NotFoundError(grpc.StatusCode.NOT_FOUND, "no template")
        return TEMPLATES[template_id]


class _DeniedDiscovery:
    async def get_template(self, template_id: str) -> TemplateInfo:
        raise PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "denied")


class _Providers:
    async def list_provider_instances(self) -> ListProviderInstancesResponse:
        return _instances()


def test_collect_pages_through_every_key_and_reads_each_template_once() -> None:
    keys = _Keys()
    clients = SimpleNamespace(key_management=keys, discovery=_Discovery(), providers=_Providers())
    inv = asyncio.run(collect(clients))
    assert keys.tokens == ["", "2"]
    assert len(inv.rows) == 4
    assert set(inv.templates) == set(TEMPLATES)  # the retired template is simply unknown
    assert inv.unreadable == {}


def test_collect_marks_templates_unreadable_when_discovery_is_denied() -> None:
    clients = SimpleNamespace(key_management=_Keys(), discovery=_DeniedDiscovery(), providers=_Providers())
    inv = asyncio.run(collect(clients))
    assert inv.unreadable == {"templates": "PERMISSION_DENIED"}


def test_cbom_does_not_guess_the_type_of_a_key_whose_template_is_unknown() -> None:
    inv = build_inventory(_views(), dict(TEMPLATES), None)
    bom = to_cyclonedx(inv)
    orphan = next(c for c in bom["components"] if c["bom-ref"] == "key:orphan-key")
    assert orphan["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "key"
