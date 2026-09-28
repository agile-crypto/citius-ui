from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from citius_api.services.discovery_service_pb2 import ListScopesResponse, ListTemplatesResponse
from citius_api.services.provider_service_pb2 import ListProviderInstancesResponse, MatchProvidersResponse
from citius_api.types.common_pb2 import CryptoOperation
from citius_api.types.implementation_pb2 import Fips140Level, ImplementationProperties, ProviderRequirements
from citius_api.types.templates_pb2 import TemplateInfo, TemplateStatus

from citius_ui.actions.model import Availability, ResultStatus, RpcResult
from citius_ui.actions.registry import ActionRegistry
from citius_ui.workbench.actions import (
    CONTRACT_ONLY,
    IMPLEMENTED,
    _register_discovery,
    _register_providers,
    unmet_requirements,
)


def _invoke(registry: ActionRegistry, service: str, method: str, request: dict[str, Any]) -> RpcResult:
    action = registry.get(service, method)
    assert action.availability is Availability.AVAILABLE
    assert action.invoke is not None

    async def run() -> RpcResult:
        assert action.invoke is not None
        return await action.invoke(request)

    return asyncio.run(run())


class _Discovery:
    def __init__(self) -> None:
        self.sent: list[Any] = []

    async def list_templates(self, request: Any) -> ListTemplatesResponse:
        self.sent.append(request)
        response = ListTemplatesResponse()
        pq = response.templates.add(template_id="ml-dsa-65", status=TemplateStatus.TEMPLATE_STATUS_ACTIVE)
        pq.cyclonedx.nist_quantum_security_level = 3
        response.templates.add(template_id="ecdsa-p256-sha256-der", standards=["FIPS 186-5"])
        return response

    async def get_template(self, template_id: str) -> TemplateInfo:
        return TemplateInfo(template_id=template_id)

    async def list_scopes(self) -> ListScopesResponse:
        response = ListScopesResponse()
        response.scopes.add(name="aead_standard", supported_operations=[CryptoOperation.CRYPTO_OPERATION_ENCRYPT])
        return response


def test_list_templates_reports_quantum_safety_and_sends_filters() -> None:
    discovery = _Discovery()
    registry = ActionRegistry()
    _register_discovery(registry, SimpleNamespace(discovery=discovery))  # type: ignore[arg-type]

    result = _invoke(
        registry,
        "AlgorithmDiscoveryService",
        "ListTemplates",
        {"scope": "SIGNATURE_STANDARD", "allowed_statuses": "ACTIVE, EXPERIMENTAL", "required_standard": "FIPS 204"},
    )
    assert result.status is ResultStatus.OK
    pq, classical = result.response["templates"]
    assert pq["quantum_safe"] is True and pq["status"] == "TEMPLATE_STATUS_ACTIVE"
    assert classical["quantum_safe"] is False
    (request,) = discovery.sent
    assert request.scope_spec.WhichOneof("scope_spec") == "signature"
    assert list(request.allowed_statuses) == [
        TemplateStatus.TEMPLATE_STATUS_ACTIVE,
        TemplateStatus.TEMPLATE_STATUS_EXPERIMENTAL,
    ]
    assert list(request.required_standards) == ["FIPS 204"]


def test_list_templates_rejects_an_unknown_status() -> None:
    registry = ActionRegistry()
    _register_discovery(registry, SimpleNamespace(discovery=_Discovery()))  # type: ignore[arg-type]
    result = _invoke(registry, "AlgorithmDiscoveryService", "ListTemplates", {"allowed_statuses": "SHINY"})
    assert result.status is ResultStatus.INVALID_ARGUMENT


def test_get_template_and_list_scopes() -> None:
    registry = ActionRegistry()
    _register_discovery(registry, SimpleNamespace(discovery=_Discovery()))  # type: ignore[arg-type]
    got = _invoke(registry, "AlgorithmDiscoveryService", "GetTemplate", {"template_id": "ml-dsa-65"})
    assert got.response["summary"]["template_id"] == "ml-dsa-65"
    missing = _invoke(registry, "AlgorithmDiscoveryService", "GetTemplate", {})
    assert missing.status is ResultStatus.INVALID_ARGUMENT
    scopes = _invoke(registry, "AlgorithmDiscoveryService", "ListScopes", {})
    assert scopes.response["scopes"] == [{"scope": "aead_standard", "operations": ["CRYPTO_OPERATION_ENCRYPT"]}]


class _Providers:
    """software (Go, memory safe), openssl (C), openssl-fips (C, FIPS 140 level 1)."""

    def __init__(self) -> None:
        self.match_requests: list[Any] = []

    @staticmethod
    def _instances() -> ListProviderInstancesResponse:
        response = ListProviderInstancesResponse()
        response.instances.add(instance_id="openssl", provider_id="openssl").implementation_override.CopyFrom(
            ImplementationProperties(implementation_language="c", hardware_accelerated=True)
        )
        fips = response.instances.add(instance_id="openssl-fips", provider_id="openssl")
        fips.implementation_override.fips_140.certified = True
        fips.implementation_override.fips_140.level = Fips140Level.FIPS_140_LEVEL_1
        response.instances.add(instance_id="software", provider_id="software").implementation_override.CopyFrom(
            ImplementationProperties(implementation_language="go", memory_safe_language=True)
        )
        return response

    async def list_provider_instances(self, **_: Any) -> ListProviderInstancesResponse:
        return self._instances()

    async def match_providers(self, *, template_id: str, requirements: Any) -> MatchProvidersResponse:
        self.match_requests.append((template_id, requirements))
        response = MatchProvidersResponse()
        for instance in self._instances().instances:
            props = instance.implementation_override
            wanted = requirements.to_proto() if requirements is not None else ProviderRequirements()
            if instance.instance_id == "software" and template_id == "ml-kem-768-hsm-only":
                continue
            if not unmet_requirements(wanted, props):
                match = response.matches.add(match_score=1)
                match.instance.CopyFrom(instance)
                match.resolved_implementation.CopyFrom(props)
        return response


def test_match_providers_explains_every_loser() -> None:
    registry = ActionRegistry()
    _register_providers(registry, SimpleNamespace(providers=_Providers()))  # type: ignore[arg-type]

    result = _invoke(
        registry, "ProviderService", "MatchProviders", {"template_id": "aes-256-gcm", "require_fips_140": True}
    )
    assert result.status is ResultStatus.OK
    assert result.message == "CreateKey would choose openssl-fips"
    assert [row["instance_id"] for row in result.response["ranked"]] == ["openssl-fips"]
    assert result.response["ranked"][0]["fips_140"] == "FIPS_140_LEVEL_1"
    assert {row["instance_id"]: row["why_not"] for row in result.response["excluded"]} == {
        "openssl": ["not FIPS 140 certified"],
        "software": ["not FIPS 140 certified"],
    }


def test_match_providers_names_a_template_gap_when_requirements_are_met() -> None:
    registry = ActionRegistry()
    _register_providers(registry, SimpleNamespace(providers=_Providers()))  # type: ignore[arg-type]
    result = _invoke(registry, "ProviderService", "MatchProviders", {"template_id": "ml-kem-768-hsm-only"})
    excluded = {row["instance_id"]: row["why_not"] for row in result.response["excluded"]}
    assert excluded == {"software": ["does not support template ml-kem-768-hsm-only"]}


def test_match_providers_with_no_candidate_says_so() -> None:
    registry = ActionRegistry()
    _register_providers(registry, SimpleNamespace(providers=_Providers()))  # type: ignore[arg-type]
    result = _invoke(
        registry,
        "ProviderService",
        "MatchProviders",
        {"template_id": "aes-256-gcm", "require_fips_140": True, "require_memory_safe": True},
    )
    assert result.message == "no instance can hold this key"
    assert len(result.response["excluded"]) == 3


def test_list_provider_instances_summarizes_implementation() -> None:
    registry = ActionRegistry()
    _register_providers(registry, SimpleNamespace(providers=_Providers()))  # type: ignore[arg-type]
    result = _invoke(registry, "ProviderService", "ListProviderInstances", {})
    rows = {row["instance_id"]: row for row in result.response["instances"]}
    assert rows["software"]["memory_safe"] is True
    assert rows["openssl-fips"]["fips_140"] == "FIPS_140_LEVEL_1"
    assert rows["openssl"]["fips_140"] == "not certified"


def test_unmet_requirements_mirrors_the_server_check() -> None:
    fips1 = ImplementationProperties()
    fips1.fips_140.certified = True
    fips1.fips_140.level = Fips140Level.FIPS_140_LEVEL_1
    assert unmet_requirements(ProviderRequirements(fips_140_certified=True), fips1) == []
    assert unmet_requirements(ProviderRequirements(min_fips_level=Fips140Level.FIPS_140_LEVEL_3), fips1) == [
        "below FIPS_140_LEVEL_3"
    ]
    cve = ImplementationProperties(no_known_cve=True, unpatched_cves=["CVE-2099-1"])
    assert unmet_requirements(ProviderRequirements(no_known_cve=True), cve) == ["has known CVEs"]
    # A preference never excludes.
    assert unmet_requirements(ProviderRequirements(prefer_hardware_accelerated=True), ImplementationProperties()) == []


def test_catalogue_reads_are_implemented_and_writes_are_not() -> None:
    assert set(IMPLEMENTED["ProviderService"]).isdisjoint(CONTRACT_ONLY["ProviderService"])
    assert "RegisterProviderInstance" in CONTRACT_ONLY["ProviderService"]
    assert "AlgorithmDiscoveryService" not in CONTRACT_ONLY
