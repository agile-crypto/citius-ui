"""Rendering and error normalization between the SDK and the action layer."""

from __future__ import annotations

import base64

import grpc
from citius_sdk.errors import (
    AlreadyExistsError,
    AuthenticationError,
    CitiusError,
    DeadlineExceededError,
    FailedPreconditionError,
    InvalidArgumentError,
    NotFoundError,
    PermissionDeniedError,
    UnavailableError,
    UnimplementedError,
)

from citius_ui.actions.model import ResultStatus, RpcResult


class RequestError(ValueError):
    """Raised when a request payload is malformed before it reaches the wire."""


_ERROR_STATUS: dict[type[CitiusError], ResultStatus] = {
    AuthenticationError: ResultStatus.UNAUTHENTICATED,
    PermissionDeniedError: ResultStatus.PERMISSION_DENIED,
    InvalidArgumentError: ResultStatus.INVALID_ARGUMENT,
    FailedPreconditionError: ResultStatus.FAILED_PRECONDITION,
    NotFoundError: ResultStatus.NOT_FOUND,
    UnimplementedError: ResultStatus.UNIMPLEMENTED,
    UnavailableError: ResultStatus.UNAVAILABLE,
    DeadlineExceededError: ResultStatus.DEADLINE_EXCEEDED,
    AlreadyExistsError: ResultStatus.ALREADY_EXISTS,
}


def encode_bytes(value: bytes) -> dict[str, str]:
    """Render bytes with base64 and hex, and UTF-8 text when valid."""
    rendered: dict[str, str] = {
        "base64": base64.b64encode(value).decode("ascii"),
        "hex": value.hex(),
    }
    try:
        rendered["utf8"] = value.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return rendered


def error_result(error: CitiusError) -> RpcResult:
    """Map an SDK error to a normalized failed RpcResult."""
    status = _ERROR_STATUS.get(type(error), ResultStatus.ERROR)
    denial_reason = _denial_reason(error.message) if status is ResultStatus.PERMISSION_DENIED else None
    return RpcResult(status=status, message=error.message, denial_reason=denial_reason)


def _denial_reason(message: str) -> str | None:
    """A hint of which check refused a call, read from the server's message.

    The server sends only the status code and message (decision A1), so this
    is a hint. The auth layer says 'resource "name" ...' when a key or policy
    name pattern refuses, and 'missing permission ...' or 'no policy
    registered for method ...' when the method check does. Any other refusal,
    such as a crypto policy's, is not guessed at.
    """
    lowered = message.lower()
    if "resource" in lowered:
        return "resource_pattern"
    if "missing permission" in lowered or "no policy registered" in lowered:
        return "method_permission"
    return None


def invalid_result(error: Exception) -> RpcResult:
    """Map a malformed request to a normalized INVALID_ARGUMENT RpcResult."""
    return RpcResult(status=ResultStatus.INVALID_ARGUMENT, message=str(error) or type(error).__name__)


def unexpected_result(error: grpc.RpcError | Exception) -> RpcResult:
    """Wrap an unexpected transport failure as a normalized RpcResult."""
    message = str(error).strip() or type(error).__name__
    return RpcResult(status=ResultStatus.UNAVAILABLE, message=message)
