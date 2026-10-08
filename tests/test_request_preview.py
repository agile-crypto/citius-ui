"""The request preview shows exactly the message the action puts on the wire.

The real SDK clients run with a stub that records each request instead of
sending it, so the comparison covers the SDK's own request building too.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from citius_api.messages.key_management_pb2 import CreateKeyResponse, TransformKeyResponse
from citius_api.services.discovery_service_pb2 import ListTemplatesResponse
from citius_api.services.provider_service_pb2 import (
    ListProviderInstancesResponse,
    ListProvidersResponse,
    MatchProvidersResponse,
)
from citius_sdk.services.discovery import DiscoveryClient
from citius_sdk.services.key_management import KeyManagementClient
from citius_sdk.services.provider import ProviderClient
from google.protobuf.json_format import MessageToDict

from citius_ui.actions.model import ResultStatus
from citius_ui.grpc_client.serialization import RequestError
from citius_ui.workbench.actions import REQUEST_BUILDERS, build_registry, create_key_request
from citius_ui.workbench.app import _request_preview
from citius_ui.workbench.forms import FORMS_BY_METHOD, Example, build_request

_RESPONSES: dict[str, Any] = {
    "CreateKey": CreateKeyResponse(success=True),
    "TransformKey": TransformKeyResponse(success=True),
    "ListTemplates": ListTemplatesResponse(),
    "ListProviders": ListProvidersResponse(),
    "ListProviderInstances": ListProviderInstancesResponse(),
    "MatchProviders": MatchProvidersResponse(),
}


class _RecordingStub:
    """Answers every RPC with an empty response and keeps the request it got."""

    def __init__(self) -> None:
        self.sent: dict[str, Any] = {}

    def __getattr__(self, method: str) -> Any:
        async def call(request: Any, timeout: float | None = None) -> Any:
            self.sent[method] = request
            return _RESPONSES[method]

        return call


def _clients() -> tuple[SimpleNamespace, _RecordingStub]:
    stub = _RecordingStub()
    clients = SimpleNamespace(
        key_management=KeyManagementClient(MagicMock(), timeout=5),
        discovery=DiscoveryClient(MagicMock(), timeout=5),
        providers=ProviderClient(MagicMock(), timeout=5),
    )
    for client in vars(clients).values():
        client._stub = stub
    return clients, stub


def _cases() -> list[tuple[str, str, Example]]:
    return [
        (service, method, example)
        for (service, method) in REQUEST_BUILDERS
        for example in FORMS_BY_METHOD[(service, method)].examples
    ]


@pytest.mark.parametrize(("service", "method", "example"), _cases(), ids=lambda case: getattr(case, "text", case))
def test_the_preview_is_the_request_sent(service: str, method: str, example: Example) -> None:
    spec = FORMS_BY_METHOD[(service, method)]
    values = spec.example_values(example)
    clients, stub = _clients()
    result = asyncio.run(build_registry(clients).get(service, method).invoke(build_request(spec, values)))  # type: ignore[arg-type,misc]
    assert result.status is ResultStatus.OK, result.message
    sent = stub.sent[method]
    shown = _request_preview(spec, REQUEST_BUILDERS[(service, method)])(*values)
    assert json.loads(shown) == MessageToDict(sent, preserving_proto_field_name=True)


def test_every_form_with_property_sections_has_a_preview() -> None:
    with_sections = {key for key, spec in FORMS_BY_METHOD.items() if spec.sections()}
    assert with_sections == set(REQUEST_BUILDERS)


def test_create_key_request_carries_the_scope_properties_and_requirements_in_their_messages() -> None:
    built = create_key_request(
        {
            "name": "k",
            "policy": "p",
            "scope": "SIGNATURE_STANDARD",
            "template_id": "ml-dsa-65",
            "quantum_safe": "false",
            "require_formally_verified": True,
        }
    )
    assert MessageToDict(built, preserving_proto_field_name=True) == {
        "name": "k",
        "policy": "p",
        "template_id": "ml-dsa-65",
        "scope_spec": {"signature": {"scope": "SIGNATURE_SCOPE_STANDARD", "security": {"quantum_safe": False}}},
        "provider_requirements": {"formally_verified": True},
    }


def test_a_key_request_names_a_template_only_when_one_is_given() -> None:
    from citius_ui.workbench.actions import transform_key_request

    request = {"name": "k", "policy": "p", "scope": "SIGNATURE_STANDARD", "template_id": "  "}
    assert not create_key_request(request).HasField("template_id")
    assert not transform_key_request(request).HasField("template_id")
    assert create_key_request({**request, "template_id": "ml-dsa-65"}).template_id == "ml-dsa-65"


def test_create_key_request_refuses_a_template_without_a_scope() -> None:
    with pytest.raises(RequestError, match="'scope' is required"):
        create_key_request({"name": "k", "template_id": "ml-dsa-65"})


def test_the_preview_says_why_a_request_cannot_be_sent_yet() -> None:
    spec = FORMS_BY_METHOD[("KeyManagementService", "CreateKey")]
    preview = _request_preview(spec, REQUEST_BUILDERS[("KeyManagementService", "CreateKey")])
    fresh = spec.example_values(Example("fresh"))
    assert preview(*fresh) == "// Not ready to send: 'name' is required"
    named = [("k" if field.key == "name" else value) for field, value in zip(spec.fields, fresh, strict=True)]
    assert preview(*named).startswith("// Not ready to send: 'scope' is required")
