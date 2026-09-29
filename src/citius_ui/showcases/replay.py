"""Replay runbooks against a server through the Workbench actions.

Each step's prefilled request goes the way the UI sends it: form values in
field order, through ``build_request`` and the action registered for its RPC.
Bundles a producer step returns are kept by name and pasted into the consumer
steps that name them. Each result is checked against the step's expected
outcome and its ``look_for`` fields.

Steps whose outcome depends on the caller's identity (method and resource
denials) need an authenticated server with the demo identities; without auth
they are skipped.

    python -m citius_ui.showcases.replay [--endpoint 127.0.0.1:50051] [r1-intent ...]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from citius_ui.actions.model import ResultStatus
from citius_ui.actions.registry import ActionRegistry
from citius_ui.showcases.model import ACCEPTED_STATUS, ExpectedOutcome, Runbook, RunbookStep
from citius_ui.showcases.runbooks import RUNBOOKS, look_up
from citius_ui.workbench.forms import FORMS_BY_METHOD, build_request

_IDENTITY_OUTCOMES = {ExpectedOutcome.METHOD_DENIED, ExpectedOutcome.RESOURCE_DENIED}


def form_values(step: RunbookStep, bundles: Mapping[str, str] | None = None) -> list[object]:
    """The step's form values in the form's field order, with its bundle pasted in.

    Raises KeyError if the step's RPC has no form, and ValueError if the
    request names a field the form does not have.
    """
    spec = FORMS_BY_METHOD[(step.service, step.method)]
    request = dict(step.request or {})
    unknown = set(request) - {field.key for field in spec.fields}
    if unknown:
        raise ValueError(f"{step.method} form has no field(s) {sorted(unknown)}")
    if step.bundle and not step.copy_bundle and bundles and step.bundle in bundles:
        request.setdefault("bundle", bundles[step.bundle])
    return [request.get(field.key) for field in spec.fields]


@dataclass(frozen=True, slots=True)
class StepResult:
    index: int
    step: RunbookStep
    status: str
    passed: bool
    skipped: bool = False
    detail: str = ""


def _check(step: RunbookStep, status: str, response: Mapping[str, Any]) -> str:
    """Why the result does not match the step, or "" if it does."""
    if status not in ACCEPTED_STATUS[step.expected]:
        return f"expected {step.expected.value}, got {status}"
    for path, want in (step.look_for or {}).items():
        got = look_up(response, path)
        if got != want:
            return f"{path} = {json.dumps(got)}, expected {json.dumps(want)}"
    return ""


async def replay(runbook: Runbook, registry: ActionRegistry, *, identities: bool = False) -> list[StepResult]:
    """Run every step of a runbook in order. Stops at nothing: each step reports its own result."""
    bundles: dict[str, str] = {}
    results = []
    for index, step in enumerate(runbook.steps, start=1):
        if step.expected in _IDENTITY_OUTCOMES and not identities:
            results.append(StepResult(index, step, "", passed=True, skipped=True, detail="needs the demo identities"))
            continue
        spec = FORMS_BY_METHOD[(step.service, step.method)]
        try:
            payload = build_request(spec, form_values(step, bundles))
        except ValueError as exc:  # a step the forms refuse is that step's failure, not the replay's
            results.append(StepResult(index, step, "INVALID_ARGUMENT", passed=False, detail=f"form refused: {exc}"))
            continue
        action = registry.get(step.service, step.method)
        assert action.invoke is not None
        result = await action.invoke(payload)
        detail = _check(step, result.status.value, result.response)
        if not detail and result.status is not ResultStatus.OK:
            detail = result.message
        if step.copy_bundle and step.bundle and result.status is ResultStatus.OK and action.extract_artifacts:
            artifacts = action.extract_artifacts(payload, result)
            if artifacts:
                bundles[step.bundle] = json.dumps(artifacts[0].bundle())
        passed = not _check(step, result.status.value, result.response)
        results.append(StepResult(index, step, result.status.value, passed=passed, detail=detail or result.message))
    return results


def _clients(endpoint: str) -> Any:
    from citius_sdk import ClientConfig, TLSConfig
    from citius_sdk.services.crypto import CryptoClient
    from citius_sdk.services.crypto_policy import CryptoPolicyClient
    from citius_sdk.services.discovery import DiscoveryClient
    from citius_sdk.services.key_management import KeyManagementClient
    from citius_sdk.services.provider import ProviderClient

    config = ClientConfig(endpoint=endpoint, tls=TLSConfig(enabled=False))
    return SimpleNamespace(
        crypto=CryptoClient.connect(config),
        key_management=KeyManagementClient.connect(config),
        crypto_policy=CryptoPolicyClient.connect(config),
        discovery=DiscoveryClient.connect(config),
        providers=ProviderClient.connect(config),
    )


async def _main(endpoint: str, keys: Iterable[str]) -> int:
    from citius_ui.workbench.actions import build_registry

    wanted = set(keys)
    clients = _clients(endpoint)
    registry = build_registry(clients)
    failures = 0
    try:
        for runbook in RUNBOOKS:
            if wanted and runbook.key not in wanted:
                continue
            print(f"\n{runbook.title}")
            for r in await replay(runbook, registry):
                mark = "skip" if r.skipped else ("ok  " if r.passed else "FAIL")
                failures += not r.passed
                print(f"  {mark} {r.index:2}. {r.step.method:<22} {r.step.title} {r.status}  {r.detail}".rstrip())
    finally:
        for client in vars(clients).values():
            await client.close()
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--endpoint", default="127.0.0.1:50051", help="a Citius server without authentication")
    parser.add_argument("runbooks", nargs="*", help="runbook keys (default: all)")
    args = parser.parse_args()
    sys.exit(asyncio.run(_main(args.endpoint, args.runbooks)))
