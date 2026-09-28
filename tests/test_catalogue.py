"""Live dropdown choices read from the server catalogue."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import grpc
from citius_api.services.discovery_service_pb2 import ListScopesResponse
from citius_api.services.provider_service_pb2 import ListProviderInstancesResponse, ListProvidersResponse
from citius_sdk.errors import PermissionDeniedError

from citius_ui.workbench.catalogue import (
    PROVIDER_INSTANCES,
    PROVIDER_TYPES,
    SCOPES,
    choices_for,
    load_choices,
)
from citius_ui.workbench.forms import FORMS


class _Providers:
    async def list_provider_instances(self) -> ListProviderInstancesResponse:
        response = ListProviderInstancesResponse()
        for instance_id, provider_id in (("openssl-fips", "openssl"), ("software", "software"), ("openssl", "openssl")):
            response.instances.add(instance_id=instance_id, provider_id=provider_id)
        return response

    async def list_providers(self) -> ListProvidersResponse:
        response = ListProvidersResponse()
        for provider_id in ("software", "openssl"):
            response.providers.add(provider_id=provider_id)
        return response


class _Discovery:
    async def list_scopes(self) -> ListScopesResponse:
        response = ListScopesResponse()
        for name in ("aead_standard", "signature_standard", "not_a_scope"):
            response.scopes.add(name=name)
        return response


class _DeniedDiscovery:
    async def list_scopes(self) -> ListScopesResponse:
        raise PermissionDeniedError(grpc.StatusCode.PERMISSION_DENIED, "denied")


def test_load_choices_reads_each_catalogue() -> None:
    clients = SimpleNamespace(providers=_Providers(), discovery=_Discovery())
    loaded = asyncio.run(load_choices(clients, {PROVIDER_INSTANCES, PROVIDER_TYPES, SCOPES}))
    assert loaded[PROVIDER_INSTANCES] == ("openssl", "openssl-fips", "software")
    assert loaded[PROVIDER_TYPES] == ("openssl", "software")
    # SDK names, in the SDK's order; names the SDK does not know are dropped.
    assert loaded[SCOPES] == ("SIGNATURE_STANDARD", "AEAD_STANDARD")


def test_a_catalogue_the_session_cannot_read_is_left_out() -> None:
    clients = SimpleNamespace(providers=_Providers(), discovery=_DeniedDiscovery())
    loaded = asyncio.run(load_choices(clients, {PROVIDER_INSTANCES, SCOPES}))
    assert set(loaded) == {PROVIDER_INSTANCES}


def test_choices_fall_back_to_static_and_keep_a_blank_for_optional_fields() -> None:
    assert choices_for(("", "A"), True, None) == ["", "A"]
    assert choices_for(("", "A"), True, ("B",)) == ["", "B"]
    assert choices_for((), False, ("B", "C")) == ["B", "C"]


def test_catalogue_fields_are_dropdowns_naming_a_known_catalogue() -> None:
    live = [(form.method, field) for form in FORMS for field in form.fields if field.choices_from]
    assert {(method, field.key) for method, field in live} >= {
        ("MigrateKey", "target_instance_id"),
        ("MigrateKey", "target_provider_id"),
        ("ValidateKeyOperation", "target_instance_id"),
        ("CreateKey", "scope"),
        ("TransformKey", "scope"),
    }
    for _, field in live:
        assert field.kind == "dropdown"
        assert field.choices_from in {PROVIDER_INSTANCES, PROVIDER_TYPES, SCOPES}
