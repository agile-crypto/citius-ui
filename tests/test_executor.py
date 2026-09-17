from __future__ import annotations

import asyncio
from typing import Any

from citius_ui.actions.artifacts import Artifact, ArtifactKind
from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import ResultStatus, RpcAction, RpcResult
from citius_ui.auth.redaction import REDACTED
from citius_ui.history.memory_store import MemoryHistoryStore


def _context() -> ExecutionContext:
    return ExecutionContext(session_id="s1", subject="citius-producer", endpoint="localhost:50051")


def test_execute_records_success_with_artifacts_and_redaction() -> None:
    store = MemoryHistoryStore()
    executor = ActionExecutor(store)

    async def invoke(request: dict[str, Any]) -> RpcResult:
        return RpcResult(
            status=ResultStatus.OK,
            response={"signature": "sig", "access_token": "should-not-persist"},
        )

    def extract(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        return [
            Artifact(
                id="art-1",
                kind=ArtifactKind.SIGNATURE,
                key_name=request["key_name"],
                key_version=5,
                value=result.response["signature"],
                metadata={"key_version": 5},
            )
        ]

    action = RpcAction(
        service="CryptoService",
        method="Sign",
        permission="citius:crypto:sign",
        invoke=invoke,
        extract_artifacts=extract,
    )

    result, record = asyncio.run(
        executor.execute(action, _context(), {"key_name": "demo-signing-key", "password": "p"})
    )

    assert result.ok
    assert record.status is ResultStatus.OK
    assert record.resource == "demo-signing-key"
    assert record.request["password"] == REDACTED
    assert record.response["access_token"] == REDACTED
    assert record.artifacts[0].kind is ArtifactKind.SIGNATURE
    assert record.correlation_id
    assert store.get("s1", record.id) is record


def test_execute_records_failure_without_extracting_artifacts() -> None:
    store = MemoryHistoryStore()
    executor = ActionExecutor(store)

    async def invoke(request: dict[str, Any]) -> RpcResult:
        return RpcResult(
            status=ResultStatus.PERMISSION_DENIED,
            message="denied",
            denial_reason="method_permission",
        )

    calls: list[int] = []

    def extract(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        calls.append(1)
        return []

    action = RpcAction(
        service="CryptoService",
        method="Verify",
        permission="citius:crypto:verify",
        invoke=invoke,
        extract_artifacts=extract,
    )

    result, record = asyncio.run(executor.execute(action, _context(), {"key_name": "demo-signing-key"}))

    assert result.status is ResultStatus.PERMISSION_DENIED
    assert record.denial_reason == "method_permission"
    assert record.artifacts == ()
    assert calls == []
