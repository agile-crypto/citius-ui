"""Replay runbooks against a server through the Workbench actions.

Each step's prefilled request goes the way the UI sends it: form values in
field order, through ``build_request`` and the action registered for its RPC.
Bundles a producer step returns are kept by name and pasted into the consumer
steps that name them. Each result is checked against the step's expected
outcome and its ``look_for`` fields.

Steps whose outcome depends on the caller's identity (method and resource
denials) need an authenticated server with the demo identities; without auth
they are skipped.

    python -m citius_ui.showcases.replay [--endpoint 127.0.0.1:50051] [choose ...]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from citius_ui.actions.model import ResultStatus, RpcAction, RpcResult
from citius_ui.actions.registry import ActionRegistry
from citius_ui.showcases.model import ACCEPTED_STATUS, Evidence, ExpectedOutcome, Runbook, RunbookStep, StepState
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
    state: StepState
    detail: str = ""
    # What was sent and what came back, for a closer look; empty when no call was made.
    request: Mapping[str, Any] = field(default_factory=dict)
    response: Mapping[str, Any] = field(default_factory=dict)
    message: str = ""

    @property
    def passed(self) -> bool:
        return self.state in (StepState.PASSED, StepState.SKIPPED)

    @property
    def skipped(self) -> bool:
        return self.state is StepState.SKIPPED


# Runs an action with a built request. The replay calls the action directly;
# the UI goes through the ActionExecutor, so the run lands in the history.
Invoke = Callable[[RpcAction, dict[str, Any]], Awaitable[RpcResult]]


async def _invoke_directly(action: RpcAction, payload: dict[str, Any]) -> RpcResult:
    assert action.invoke is not None
    return await action.invoke(payload)


def judge(step: RunbookStep, status: str, response: Mapping[str, Any]) -> tuple[StepState, str]:
    """How a result compares with the step, and why when it does not match."""
    if status not in ACCEPTED_STATUS[step.expected]:
        return StepState.FAILED, f"expected {step.expected.value}, got {status}"
    for path, want in (step.look_for or {}).items():
        got = look_up(response, path)
        if got != want:
            return StepState.DIFFERS, f"{path} = {json.dumps(got)}, expected {json.dumps(want)}"
    return StepState.PASSED, ""


async def run_step(
    index: int,
    step: RunbookStep,
    registry: ActionRegistry,
    bundles: dict[str, str],
    *,
    invoke: Invoke = _invoke_directly,
) -> StepResult:
    """Run one step the way the UI sends it, and judge the result.

    A consumer step gets the named bundle from ``bundles`` pasted in; a
    producer step that succeeds stores its bundle there under its name. A
    consumer step whose bundle does not exist yet fails without a call.
    """
    if step.bundle and not step.copy_bundle and step.bundle not in bundles:
        return StepResult(
            index, step, "", StepState.FAILED, f"no {step.bundle} bundle yet: run the step that keeps it first"
        )
    spec = FORMS_BY_METHOD[(step.service, step.method)]
    try:
        payload = build_request(spec, form_values(step, bundles))
    except ValueError as exc:  # a step the forms refuse is that step's failure
        return StepResult(index, step, "INVALID_ARGUMENT", StepState.FAILED, f"form refused: {exc}")
    action = registry.get(step.service, step.method)
    result = await invoke(action, payload)
    if step.copy_bundle and step.bundle and result.status is ResultStatus.OK and action.extract_artifacts:
        artifacts = action.extract_artifacts(payload, result)
        if artifacts:
            bundles[step.bundle] = json.dumps(artifacts[0].bundle())
    state, why = judge(step, result.status.value, result.response)
    detail = "; ".join(part for part in (why, result.message) if part)
    return StepResult(
        index,
        step,
        result.status.value,
        state,
        detail,
        request=payload,
        response=dict(result.response or {}),
        message=result.message,
    )


def evidence(item: Evidence, results: Mapping[int, StepResult]) -> object:
    """The value an Evidence names in a run's results, or None if its step has not run or it is absent."""
    result = results.get(item.step)
    if result is None:
        return None
    if item.path == "status":
        return result.status or None
    if item.path == "request":
        return list(result.request) or None
    if item.path.startswith("request."):
        return look_up(result.request, item.path.removeprefix("request."))
    return look_up(result.response, item.path)


async def replay(
    runbook: Runbook,
    registry: ActionRegistry,
    *,
    identities: bool = False,
    bundles: dict[str, str] | None = None,
) -> list[StepResult]:
    """Run every step of a runbook in order. Stops at nothing: each step reports its own result.

    Pass the same ``bundles`` to runbooks run one after another, so a runbook
    can paste bundles an earlier one kept (see ``Runbook.after``).
    """
    bundles = {} if bundles is None else bundles
    results = []
    for index, step in enumerate(runbook.steps, start=1):
        if step.expected in _IDENTITY_OUTCOMES and not identities:
            results.append(StepResult(index, step, "", StepState.SKIPPED, "needs the demo identities"))
            continue
        results.append(await run_step(index, step, registry, bundles))
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


_MARK = {
    StepState.PASSED: "ok  ",
    StepState.SKIPPED: "skip",
    StepState.DIFFERS: "DIFF",
    StepState.FAILED: "FAIL",
    StepState.NOT_RUN: "    ",
}


async def _main(endpoint: str, keys: Iterable[str]) -> int:
    from citius_ui.workbench.actions import build_registry

    wanted = set(keys)
    clients = _clients(endpoint)
    registry = build_registry(clients)
    failures = 0
    # Shared in order, so a showcase runbook gets the bundles the one before kept.
    bundles: dict[str, str] = {}
    try:
        for runbook in RUNBOOKS:
            if wanted and runbook.key not in wanted:
                continue
            print(f"\n{runbook.title}")
            for r in await replay(runbook, registry, bundles=bundles):
                mark = _MARK[r.state]
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
