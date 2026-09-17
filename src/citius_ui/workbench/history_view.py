"""Derived views over session history for the Workbench UI.

These functions are transport-independent and read only the session-scoped
history store, so producer responses and activity never cross sessions.
"""

from __future__ import annotations

import json

from citius_ui.actions.artifacts import Artifact, ArtifactKind, compatible_targets
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.history.model import OperationRecord

ACTIVITY_HEADERS = ["Time", "Service", "RPC", "Status", "Resource"]
PRODUCER_HEADERS = ["Time", "Operation", "Type", "Key name", "Key version", "Copyable bundle"]

_PRODUCER_KINDS = {ArtifactKind.SIGNATURE, ArtifactKind.CIPHERTEXT}


def activity_rows(history: MemoryHistoryStore, session_id: str) -> list[list[str]]:
    """Return newest-first session activity rows for display."""
    return [
        [
            record.timestamp.strftime("%H:%M:%S"),
            record.service,
            record.method,
            record.status.value,
            record.resource,
        ]
        for record in history.list(session_id)
    ]


def _producer_artifacts(history: MemoryHistoryStore, session_id: str) -> list[tuple[OperationRecord, Artifact]]:
    pairs: list[tuple[OperationRecord, Artifact]] = []
    for record in history.list(session_id):
        for artifact in record.artifacts:
            if artifact.kind in _PRODUCER_KINDS:
                pairs.append((record, artifact))
    return pairs


def producer_rows(history: MemoryHistoryStore, session_id: str) -> list[list[str]]:
    """Return append-only producer responses with copyable reuse bundles."""
    rows: list[list[str]] = []
    for record, artifact in _producer_artifacts(history, session_id):
        rows.append(
            [
                record.timestamp.strftime("%H:%M:%S"),
                record.method,
                artifact.kind.value,
                artifact.key_name,
                "" if artifact.key_version is None else str(artifact.key_version),
                json.dumps(artifact.bundle(), sort_keys=True),
            ]
        )
    return rows


def latest_consumer_handoff(history: MemoryHistoryStore, session_id: str) -> tuple[str, str, str] | None:
    """Return the (service, method, request_json) to reuse the newest producer output.

    Signatures hand off to Verify and ciphertexts to Decrypt, replaying the
    complete recorded metadata so the original key version is used.
    """
    pairs = _producer_artifacts(history, session_id)
    if not pairs:
        return None
    _, artifact = pairs[0]
    targets = compatible_targets(artifact.kind)
    if not targets:
        return None
    service, method = targets[0]
    return service, method, json.dumps(artifact.bundle(), indent=2)
