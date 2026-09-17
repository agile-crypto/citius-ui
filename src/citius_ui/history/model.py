"""Operation history record model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from citius_ui.actions.artifacts import Artifact
from citius_ui.actions.model import ResultStatus


@dataclass(frozen=True, slots=True)
class OperationRecord:
    """One recorded RPC invocation, safe to persist and display."""

    id: str
    timestamp: datetime
    session_id: str
    subject: str
    service: str
    method: str
    status: ResultStatus
    resource: str = ""
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    denial_reason: str | None = None
    duration_ms: float | None = None
    correlation_id: str | None = None
    artifacts: tuple[Artifact, ...] = ()
    scenario_run_id: str | None = None
    endpoint: str | None = None
    api_version: str | None = None
