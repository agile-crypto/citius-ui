from __future__ import annotations

from datetime import datetime, timezone

from citius_ui.actions.model import ResultStatus
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.history.model import OperationRecord


def _record(session: str, record_id: str, service: str = "CryptoService", method: str = "Sign") -> OperationRecord:
    return OperationRecord(
        id=record_id,
        timestamp=datetime.now(timezone.utc),
        session_id=session,
        subject="citius-producer",
        service=service,
        method=method,
        status=ResultStatus.OK,
    )


def test_history_is_isolated_per_session() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a"))
    store.append(_record("s2", "b"))
    assert [r.id for r in store.list("s1")] == ["a"]
    assert [r.id for r in store.list("s2")] == ["b"]


def test_list_returns_newest_first_and_filters_by_service() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a", service="CryptoService"))
    store.append(_record("s1", "b", service="KeyManagementService"))
    assert [r.id for r in store.list("s1")] == ["b", "a"]
    assert [r.id for r in store.list("s1", service="CryptoService")] == ["a"]


def test_limit_bounds_retention() -> None:
    store = MemoryHistoryStore(limit=2)
    for record_id in ("a", "b", "c"):
        store.append(_record("s1", record_id))
    assert [r.id for r in store.list("s1")] == ["c", "b"]


def test_clear_removes_session_history() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a"))
    store.clear("s1")
    assert store.list("s1") == []


def test_remove_method_drops_only_that_methods_records() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a", method="Sign"))
    store.append(_record("s1", "b", method="Verify"))
    store.append(_record("s1", "c", method="Sign"))
    store.remove_method("s1", "Sign")
    assert [r.id for r in store.list("s1")] == ["b"]


def test_remove_method_clears_all_history_when_nothing_remains() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a", method="Sign"))
    store.remove_method("s1", "Sign")
    assert store.list("s1") == []


def test_remove_method_is_a_no_op_for_unknown_session() -> None:
    store = MemoryHistoryStore()
    store.remove_method("no-such-session", "Sign")
    assert store.list("no-such-session") == []


def test_get_finds_record_by_id() -> None:
    store = MemoryHistoryStore()
    store.append(_record("s1", "a"))
    found = store.get("s1", "a")
    assert found is not None
    assert found.id == "a"
    assert store.get("s1", "missing") is None
