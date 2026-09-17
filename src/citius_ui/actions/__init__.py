"""Application-layer RPC action model, registry, artifacts, and executor."""

from citius_ui.actions.artifacts import Artifact, ArtifactKind, compatible_targets, is_compatible
from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import Availability, ResultStatus, RpcAction, RpcResult
from citius_ui.actions.registry import ActionRegistry

__all__ = [
    "ActionExecutor",
    "ActionRegistry",
    "Artifact",
    "ArtifactKind",
    "Availability",
    "ExecutionContext",
    "ResultStatus",
    "RpcAction",
    "RpcResult",
    "compatible_targets",
    "is_compatible",
]
