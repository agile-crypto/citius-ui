"""Crypto inventory: every key the session can read, with a PQ-readiness report.

The inventory joins three read-only listings the server already offers:

- ListKeys: each key's current version, template, provider instance and state;
- GetTemplate: what the catalogue says about each template (its CycloneDX
  algorithm properties, and whether its scopes are quantum-safe and
  FIPS-approved);
- ListProviderInstances: the FIPS 140 level each instance reports.

Nothing here decides anything: quantum safety and FIPS approval are read from
the catalogue, the FIPS level from the instance. A template or instance that
could not be read leaves its columns unknown (None), not guessed; the report
names the status code that refused it.

The same data is exported as a CycloneDX 1.6 CBOM: one ``algorithm`` asset per
template in use and one ``related-crypto-material`` asset per key, linked by
``algorithmRef`` and ``dependencies``.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from citius_api.types import common_pb2 as common_types
from citius_api.types import implementation_pb2 as common_impl
from citius_sdk.errors import CitiusError, NotFoundError
from citius_sdk.services import key_management as sdk_keys

# Bound on the ListKeys pages one inventory reads.
_PAGE_SIZE = 200
_MAX_PAGES = 50

# CycloneDX primitives whose keys are key pairs; every other primitive uses a
# secret key. A combiner (a hybrid KEM or signature) joins key pairs.
_ASYMMETRIC_PRIMITIVES = {"signature", "kem", "key-agree", "pke", "combiner"}

# The primitives CycloneDX 1.6 defines. The catalogue uses others (key-wrap),
# which a 1.6 CBOM must report as "other", keeping the catalogue's name in a
# property.
_CYCLONEDX_PRIMITIVES = {
    "drbg",
    "mac",
    "block-cipher",
    "stream-cipher",
    "signature",
    "hash",
    "pke",
    "xof",
    "kdf",
    "key-agree",
    "kem",
    "ae",
    "combiner",
    "other",
    "unknown",
}

_CYCLONEDX_STATE = {
    "KEY_LIFECYCLE_STATE_PRE_ACTIVE": "pre-activation",
    "KEY_LIFECYCLE_STATE_ACTIVE": "active",
    "KEY_LIFECYCLE_STATE_SUSPENDED": "suspended",
    "KEY_LIFECYCLE_STATE_DEACTIVATED": "deactivated",
    "KEY_LIFECYCLE_STATE_COMPROMISED": "compromised",
    "KEY_LIFECYCLE_STATE_DESTROYED": "destroyed",
    "KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED": "destroyed",
}


@dataclass(frozen=True, slots=True)
class InventoryRow:
    """One key in the inventory. None means the session could not read it."""

    name: str
    version: int
    template_id: str
    algorithm: str | None
    quantum_safe: bool | None
    nist_quantum_security_level: int | None
    fips_approved_algorithm: bool | None
    provider: str
    provider_fips_140: str | None
    lifecycle_state: str

    @property
    def pq_ready(self) -> bool:
        return self.quantum_safe is True

    @property
    def fips_ready(self) -> bool:
        """A FIPS-approved algorithm on an instance that reports a FIPS 140 level.

        It says where the key is held, not how its material was made: a key
        generated elsewhere and migrated onto a FIPS instance counts, though
        a policy requiring approved generation would refuse it.
        """
        return self.fips_approved_algorithm is True and self.provider_fips_140 not in (None, "not certified")


@dataclass(frozen=True, slots=True)
class Inventory:
    rows: tuple[InventoryRow, ...]
    templates: dict[str, Any]  # template_id -> TemplateInfo, for those the session could read
    unreadable: dict[str, str]  # catalogue ("templates", "providers") -> the status code that refused it
    truncated: bool

    def summary(self) -> dict[str, Any]:
        total = len(self.rows)
        return {
            "keys": total,
            "quantum_safe": sum(r.pq_ready for r in self.rows),
            "not_quantum_safe": sum(r.quantum_safe is False for r in self.rows),
            "fips_approved_algorithm": sum(r.fips_approved_algorithm is True for r in self.rows),
            "on_fips_provider": sum(r.provider_fips_140 not in (None, "not certified") for r in self.rows),
            "quantum_safe_and_fips": sum(r.pq_ready and r.fips_ready for r in self.rows),
            "unknown": sum(r.quantum_safe is None for r in self.rows),
        }

    def table(self) -> list[dict[str, Any]]:
        return [{**asdict(r), "pq_ready": r.pq_ready, "fips_ready": r.fips_ready} for r in self.rows]


def _scope_security(template: Any) -> list[Any]:
    """The UniversalSecurityProperties of each scope the template offers."""
    found = []
    for capability in template.scoped_capabilities:
        spec = capability.scope
        arm = spec.WhichOneof("scope_spec")
        if arm is None:
            continue
        primitive = getattr(spec, arm)
        if primitive.HasField("security"):
            found.append(primitive.security)
    return found


def template_quantum_safe(template: Any) -> bool:
    """Whether the catalogue marks a scope of ``template`` quantum-safe.

    This is the flag the server matches when a caller asks for
    ``quantum_safe`` (ListTemplates' filter, CreateKey's selection), so it is
    the UI's one definition of "quantum-safe" for a template. The CycloneDX
    NIST quantum security level is reported beside it, not in its place.
    """
    return any(s.quantum_safe for s in _scope_security(template))


def template_fips_approved(template: Any) -> bool:
    """Whether the catalogue marks a scope of ``template`` FIPS-approved."""
    return any(s.fips_approved for s in _scope_security(template))


def _fips_label(instance: Any) -> str:
    fips = instance.implementation_override.fips_140
    return common_impl.Fips140Level.Name(fips.level) if fips.certified else "not certified"


def build_inventory(
    keys: list[sdk_keys.KeyMetadataView],
    templates: dict[str, Any] | None,
    instances: dict[str, Any] | None,
    *,
    reasons: dict[str, str] | None = None,
    truncated: bool = False,
) -> Inventory:
    """Join keys with template and instance data; None for a catalogue means it was not read.

    ``reasons`` names the status code that refused each unread catalogue.
    """
    reasons = reasons or {}
    unreadable = {
        name: reasons.get(name, "not read")
        for name, data in (("templates", templates), ("providers", instances))
        if data is None
    }
    templates = templates or {}
    instances = instances or {}
    rows = []
    for key in keys:
        template = templates.get(key.template_id)
        instance = instances.get(key.provider)
        if template is not None:
            quantum_safe: bool | None = template_quantum_safe(template)
            fips_approved: bool | None = template_fips_approved(template)
            algorithm: str | None = template.cyclonedx.name or template.display_name or key.template_id
            nist_level: int | None = template.cyclonedx.nist_quantum_security_level
        else:
            quantum_safe = fips_approved = algorithm = nist_level = None
        rows.append(
            InventoryRow(
                name=key.name,
                version=key.version,
                template_id=key.template_id,
                algorithm=algorithm,
                quantum_safe=quantum_safe,
                nist_quantum_security_level=nist_level,
                fips_approved_algorithm=fips_approved,
                provider=key.provider,
                provider_fips_140=_fips_label(instance) if instance is not None else None,
                lifecycle_state=common_types.KeyLifecycleState.Name(key.lifecycle_state),
            )
        )
    return Inventory(
        rows=tuple(sorted(rows, key=lambda r: r.name)),
        templates=templates,
        unreadable=unreadable,
        truncated=truncated,
    )


async def collect(clients: Any) -> Inventory:
    """Read the listings and build the inventory. ListKeys failing fails the call."""
    keys: list[sdk_keys.KeyMetadataView] = []
    token = ""
    truncated = False
    for _ in range(_MAX_PAGES):
        page = await clients.key_management.list_keys(
            sdk_keys.list_keys_request(page_size=_PAGE_SIZE, page_token=token)
        )
        keys.extend(page.keys)
        token = page.next_page_token
        if not token:
            break
    else:
        truncated = True

    read: dict[str, Any] = {}
    templates: dict[str, Any] | None = read
    reasons: dict[str, str] = {}
    for template_id in sorted({k.template_id for k in keys if k.template_id}):
        try:
            read[template_id] = await clients.discovery.get_template(template_id)
        except NotFoundError:
            continue  # a key on a template the catalogue no longer has: its columns stay unknown
        except CitiusError as error:
            templates = None
            reasons["templates"] = _code(error)
            break

    instances: dict[str, Any] | None
    try:
        listed = await clients.providers.list_provider_instances()
        instances = {i.instance_id: i for i in listed.instances}
    except CitiusError as error:
        instances = None
        reasons["providers"] = _code(error)
    return build_inventory(keys, templates, instances, reasons=reasons, truncated=truncated)


def _code(error: CitiusError) -> str:
    code = getattr(error, "code", None)
    return code.name if code is not None else type(error).__name__


def _algorithm_component(template_id: str, template: Any) -> dict[str, Any]:
    cdx = template.cyclonedx
    primitive = cdx.primitive or "unknown"
    properties: dict[str, Any] = {"primitive": primitive if primitive in _CYCLONEDX_PRIMITIVES else "other"}
    for field, value in (
        ("parameterSetIdentifier", cdx.parameter_set_identifier),
        ("curve", cdx.elliptic_curve),
        ("mode", cdx.mode),
        ("padding", cdx.padding),
        ("executionEnvironment", cdx.execution_environment),
        ("implementationPlatform", cdx.implementation_platform),
    ):
        if value:
            properties[field] = value
    if cdx.crypto_functions:
        properties["cryptoFunctions"] = list(cdx.crypto_functions)
    if cdx.certification_level:
        properties["certificationLevel"] = list(cdx.certification_level)
    if cdx.classical_security_level:
        properties["classicalSecurityLevel"] = cdx.classical_security_level
    properties["nistQuantumSecurityLevel"] = cdx.nist_quantum_security_level
    crypto: dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": properties}
    if cdx.oid:
        crypto["oid"] = cdx.oid
    component: dict[str, Any] = {
        "type": "cryptographic-asset",
        "bom-ref": f"algorithm:{template_id}",
        "name": cdx.name or template.display_name or template_id,
        "cryptoProperties": crypto,
        "properties": [{"name": "citius:template_id", "value": template_id}],
    }
    if cdx.algorithm_family:
        component["properties"].append({"name": "citius:algorithm_family", "value": cdx.algorithm_family})
    if primitive not in _CYCLONEDX_PRIMITIVES:
        component["properties"].append({"name": "citius:primitive", "value": primitive})
    return component


def to_cyclonedx(
    inventory: Inventory, *, timestamp: datetime | None = None, serial: str | None = None
) -> dict[str, Any]:
    """The inventory as a CycloneDX 1.6 CBOM."""
    when = (timestamp or datetime.now(UTC)).replace(microsecond=0)
    components = [
        _algorithm_component(template_id, inventory.templates[template_id])
        for template_id in sorted({r.template_id for r in inventory.rows if r.template_id in inventory.templates})
    ]
    dependencies = []
    for row in inventory.rows:
        template = inventory.templates.get(row.template_id)
        if template is None:
            key_type = "key"  # without the template, the kind of key is not known
        elif template.cyclonedx.primitive in _ASYMMETRIC_PRIMITIVES:
            key_type = "private-key"
        else:
            key_type = "secret-key"
        material: dict[str, Any] = {"type": key_type}
        state = _CYCLONEDX_STATE.get(row.lifecycle_state)
        if state:
            material["state"] = state
        if template is not None:
            material["algorithmRef"] = f"algorithm:{row.template_id}"
        properties = [
            {"name": "citius:version", "value": str(row.version)},
            {"name": "citius:template_id", "value": row.template_id},
            {"name": "citius:provider", "value": row.provider},
        ]
        if row.provider_fips_140 is not None:
            properties.append({"name": "citius:provider_fips_140", "value": row.provider_fips_140})
        ref = f"key:{row.name}"
        components.append(
            {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": row.name,
                "cryptoProperties": {
                    "assetType": "related-crypto-material",
                    "relatedCryptoMaterialProperties": material,
                },
                "properties": properties,
            }
        )
        if template is not None:
            dependencies.append({"ref": ref, "dependsOn": [f"algorithm:{row.template_id}"]})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": when.isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "citius-ui"}]},
        },
        "components": components,
        "dependencies": dependencies,
    }


def render_markdown(inventory: Inventory) -> str:
    """A short PQ-readiness report for the inventory panel."""
    s = inventory.summary()
    if not s["keys"]:
        return "No keys visible to this identity."
    lines = [
        f"**{s['keys']} key(s)** · quantum-safe **{s['quantum_safe']}** · "
        f"not quantum-safe **{s['not_quantum_safe']}** · on a FIPS 140 provider **{s['on_fips_provider']}** · "
        f"quantum-safe and FIPS **{s['quantum_safe_and_fips']}**",
    ]
    if s["unknown"]:
        lines.append(f"{s['unknown']} key(s) have a template that could not be read; their columns are unknown.")
    if inventory.unreadable:
        refused = ", ".join(f"{name} ({code})" for name, code in inventory.unreadable.items())
        lines.append(f"Could not read: {refused}.")
    if inventory.truncated:
        lines.append(f"Only the first {_PAGE_SIZE * _MAX_PAGES} keys are listed.")
    return "\n\n".join(lines)
