"""Live dropdown choices read from the server's catalogue.

Some form fields name something the server has registered: a provider
instance, a provider type, or a scope the template catalogue offers. Rather
than make the user type those names, the Workbench reads them once per page
load through the discovery and provider RPCs and offers them as choices.

A catalogue the session cannot read (no permission, server down) is left
out, and its fields keep their static choices, so the form still works with
typed values.
"""

from __future__ import annotations

from typing import Any

import citius_sdk as sdk
from citius_sdk.errors import CitiusError

# Catalogue names a FormField can draw its choices from.
PROVIDER_INSTANCES = "provider_instances"
PROVIDER_TYPES = "provider_types"
SCOPES = "scopes"


async def _instances(clients: Any) -> tuple[str, ...]:
    result = await clients.providers.list_provider_instances()
    return tuple(sorted({i.instance_id for i in result.instances if i.instance_id}))


async def _provider_types(clients: Any) -> tuple[str, ...]:
    result = await clients.providers.list_providers()
    return tuple(sorted({p.provider_id for p in result.providers if p.provider_id}))


async def _scopes(clients: Any) -> tuple[str, ...]:
    """The offered scopes, as SDK Scope names (the server reports ``signature_standard``)."""
    result = await clients.discovery.list_scopes()
    known = {member.name for member in sdk.Scope}
    names = {s.name.upper() for s in result.scopes}
    # Keep the SDK's order, so the dropdown reads the same as the static one.
    return tuple(member.name for member in sdk.Scope if member.name in names & known)


_LOADERS = {
    PROVIDER_INSTANCES: _instances,
    PROVIDER_TYPES: _provider_types,
    SCOPES: _scopes,
}


async def load_choices(clients: Any, catalogues: set[str]) -> dict[str, tuple[str, ...]]:
    """Read each named catalogue; one the session cannot read is left out."""
    loaded: dict[str, tuple[str, ...]] = {}
    for name in sorted(catalogues):
        loader = _LOADERS.get(name)
        if loader is None:
            raise ValueError(f"unknown catalogue {name!r}")
        try:
            loaded[name] = await loader(clients)
        except CitiusError:
            continue
    return loaded


def choices_for(static: tuple[str, ...], optional: bool, live: tuple[str, ...] | None) -> list[str]:
    """The choices a field offers: the live catalogue if read, else its static ones.

    An optional field keeps a blank first entry, which means "leave unset".
    """
    if live is None:
        return list(static)
    return ["", *live] if optional else list(live)
