"""Shared executor that runs actions and records safe history."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from citius_ui.actions.artifacts import Artifact
from citius_ui.actions.model import ResultStatus, RpcAction, RpcResult
from citius_ui.auth.redaction import redact
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.history.model import OperationRecord


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Identity and session context for one execution."""

    session_id: str
    subject: str
    endpoint: str | None = None
    api_version: str | None = None
    scenario_run_id: str | None = None


def _resource(request: dict[str, Any]) -> str:
    for key in ("key_name", "name", "policy_name", "policy"):
        value = request.get(key)
        if value:
            return str(value)
    return ""


class ActionExecutor:
    """Runs a registered action end to end and records the outcome.

    Every callback funnels through this executor so history records are created
    with redacted request/response snapshots and extracted artifacts.
    """

    def __init__(self, history: MemoryHistoryStore) -> None:
        self._history = history

    async def execute(
        self,
        action: RpcAction,
        context: ExecutionContext,
        request: dict[str, Any],
    ) -> tuple[RpcResult, OperationRecord]:
        if action.invoke is None:
            raise ValueError(f"action {action.qualified_name} has no invoke binding")

        correlation_id = uuid.uuid4().hex
        started = time.perf_counter()
        try:
            built = action.build_request(request) if action.build_request else request
        except Exception as exc:  # noqa: BLE001 - malformed input must render, not crash
            built = request
            result = RpcResult(status=ResultStatus.INVALID_ARGUMENT, message=str(exc) or type(exc).__name__)
        else:
            try:
                result = await action.invoke(built)
            except Exception as exc:  # noqa: BLE001 - last-resort net; actions normalize their own errors
                result = RpcResult(
                    status=ResultStatus.ERROR,
                    message=f"unexpected error in {action.qualified_name}: {exc}",
                )
        duration_ms = (time.perf_counter() - started) * 1000

        artifacts: tuple[Artifact, ...] = ()
        if result.status is ResultStatus.OK and action.extract_artifacts is not None:
            artifacts = tuple(action.extract_artifacts(built, result))

        record = OperationRecord(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc),
            session_id=context.session_id,
            subject=context.subject,
            service=action.service,
            method=action.method,
            status=result.status,
            resource=_resource(built),
            request=redact(built),
            response=redact(result.response),
            message=result.message,
            denial_reason=result.denial_reason,
            duration_ms=duration_ms,
            correlation_id=correlation_id,
            artifacts=artifacts,
            scenario_run_id=context.scenario_run_id,
            endpoint=context.endpoint,
            api_version=context.api_version,
        )
        self._history.append(record)
        return result, record
