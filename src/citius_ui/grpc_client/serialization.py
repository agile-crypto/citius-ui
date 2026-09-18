"""Rendering and error normalization between the SDK and the action layer."""

from __future__ import annotations

import base64

import grpc
from citius_sdk.errors import (
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
    denial_reason = None
    if status is ResultStatus.PERMISSION_DENIED:
        denial_reason = "resource_pattern" if "resource" in error.message else "method_permission"
    return RpcResult(status=status, message=error.message, denial_reason=denial_reason)


def invalid_result(error: Exception) -> RpcResult:
    """Map a malformed request to a normalized INVALID_ARGUMENT RpcResult."""
    return RpcResult(status=ResultStatus.INVALID_ARGUMENT, message=str(error) or type(error).__name__)


def unexpected_result(error: grpc.RpcError | Exception) -> RpcResult:
    """Wrap an unexpected transport failure as a normalized RpcResult."""
    message = str(error).strip() or type(error).__name__
    return RpcResult(status=ResultStatus.UNAVAILABLE, message=message)
