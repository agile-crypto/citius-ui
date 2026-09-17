from __future__ import annotations

import asyncio
import json
from typing import Any

from citius_ui.actions.artifacts import Artifact, ArtifactKind
from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import ResultStatus, RpcAction, RpcResult
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.workbench.history_view import (
    activity_rows,
    latest_consumer_handoff,
    producer_rows,
)


def _sign_action() -> RpcAction:
    async def invoke(request: dict[str, Any]) -> RpcResult:
        return RpcResult(status=ResultStatus.OK, response={"signature": "sig"})

    def extract(request: dict[str, Any], result: RpcResult) -> list[Artifact]:
        return [
            Artifact(
                id="a",
                kind=ArtifactKind.SIGNATURE,
                key_name=request["key_name"],
                key_version=5,
                value="c2ln",
                metadata={"key_version": 5, "api_version": "v1"},
                context={"message": request["message"]},
            )
        ]

    return RpcAction(
        service="CryptoService",
        method="Sign",
        permission="citius:crypto:sign",
        invoke=invoke,
        extract_artifacts=extract,
    )


def _read_action() -> RpcAction:
    async def invoke(request: dict[str, Any]) -> RpcResult:
        return RpcResult(status=ResultStatus.OK, response={"version": 1})

    return RpcAction(
        service="KeyManagementService",
        method="ReadKey",
        permission="citius:keys:read",
        invoke=invoke,
    )


def _populate() -> MemoryHistoryStore:
    history = MemoryHistoryStore()
    executor = ActionExecutor(history)
    context = ExecutionContext(session_id="hist", subject="citius-producer")
    asyncio.run(executor.execute(_read_action(), context, {"name": "demo-signing-key"}))
    asyncio.run(executor.execute(_sign_action(), context, {"key_name": "demo-signing-key", "message": "Hi"}))
    return history


def test_activity_rows_newest_first() -> None:
    rows = activity_rows(_populate(), "hist")
    assert rows[0][1:4] == ["CryptoService", "Sign", "OK"]
    assert rows[1][1:4] == ["KeyManagementService", "ReadKey", "OK"]


def test_producer_rows_only_include_signatures_and_ciphertexts() -> None:
    rows = producer_rows(_populate(), "hist")
    assert len(rows) == 1
    row = rows[0]
    assert row[1] == "Sign"
    assert row[2] == "signature"
    assert row[3] == "demo-signing-key"
    assert row[4] == "5"
    bundle = json.loads(row[5])
    assert bundle["signature"] == "c2ln"
    assert bundle["metadata"]["key_version"] == 5
    assert bundle["message"] == "Hi"


def test_latest_consumer_handoff_targets_verify() -> None:
    handoff = latest_consumer_handoff(_populate(), "hist")
    assert handoff is not None
    service, method, request_json = handoff
    assert (service, method) == ("CryptoService", "Verify")
    payload = json.loads(request_json)
    assert payload["signature"] == "c2ln"
    assert payload["metadata"]["key_version"] == 5


def test_handoff_none_without_producer_output() -> None:
    history = MemoryHistoryStore()
    executor = ActionExecutor(history)
    context = ExecutionContext(session_id="empty", subject="s")
    asyncio.run(executor.execute(_read_action(), context, {"name": "demo-key"}))
    assert latest_consumer_handoff(history, "empty") is None


def test_views_are_session_scoped() -> None:
    history = _populate()
    assert producer_rows(history, "other-session") == []
    assert activity_rows(history, "other-session") == []
