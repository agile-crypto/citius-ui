"""Transport-independent RPC action and result models."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Availability(str, Enum):
    """Availability of an RPC for the connected server and current identity."""

    AVAILABLE = "available"
    UNIMPLEMENTED = "unimplemented"
    UNAVAILABLE = "unavailable"
    FORBIDDEN = "forbidden"
    UNKNOWN = "unknown"


class ResultStatus(str, Enum):
    """Outcome category of an executed RPC."""

    OK = "OK"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    FAILED_PRECONDITION = "FAILED_PRECONDITION"
    NOT_FOUND = "NOT_FOUND"
    UNIMPLEMENTED = "UNIMPLEMENTED"
    UNAVAILABLE = "UNAVAILABLE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class RpcResult:
    """Normalized outcome of one RPC invocation."""

    status: ResultStatus
    message: str = ""
    response: dict[str, Any] = field(default_factory=dict)
    denial_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is ResultStatus.OK


@dataclass(frozen=True, slots=True)
class RpcAction:
    """Definition of a single callable RPC.

    invoke receives the built request payload and returns a normalized RpcResult.
    Binding to a concrete transport happens where the action is registered so the
    application layer stays independent of the SDK and Gradio.
    """

    service: str
    method: str
    permission: str
    availability: Availability = Availability.UNKNOWN
    build_request: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    invoke: Callable[[dict[str, Any]], Awaitable[RpcResult]] | None = None
    extract_artifacts: Callable[[dict[str, Any], RpcResult], list[Any]] | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.service}.{self.method}"
