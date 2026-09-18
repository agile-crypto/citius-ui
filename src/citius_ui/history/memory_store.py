"""In-memory, session-scoped operation history store."""

from __future__ import annotations

from collections import defaultdict

from citius_ui.history.model import OperationRecord


class MemoryHistoryStore:
    """Session-scoped history retained only in server memory.

    Records are isolated per session id so concurrent browser sessions never see
    each other's history. A per-session limit bounds retention.
    """

    def __init__(self, limit: int = 200) -> None:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        self._limit = limit
        self._records: dict[str, list[OperationRecord]] = defaultdict(list)

    def append(self, record: OperationRecord) -> None:
        session = self._records[record.session_id]
        session.append(record)
        if len(session) > self._limit:
            del session[: len(session) - self._limit]

    def list(self, session_id: str, *, service: str | None = None) -> list[OperationRecord]:
        records = list(self._records.get(session_id, ()))
        if service is not None:
            records = [record for record in records if record.service == service]
        return list(reversed(records))

    def get(self, session_id: str, record_id: str) -> OperationRecord | None:
        for record in self._records.get(session_id, ()):
            if record.id == record_id:
                return record
        return None

    def clear(self, session_id: str) -> None:
        self._records.pop(session_id, None)

    def remove_method(self, session_id: str, method: str) -> None:
        """Drop this session's records for one RPC method, keeping the rest.

        Used by the Workbench's per-RPC "Clear history" control so clearing a
        producer response table (e.g. Sign) doesn't discard unrelated history.
        """
        records = self._records.get(session_id)
        if not records:
            return
        remaining = [record for record in records if record.method != method]
        if remaining:
            self._records[session_id] = remaining
        else:
            self._records.pop(session_id, None)
