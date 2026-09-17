from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone

from citius_ui.auth.sessions import SessionStore


def _await(awaitable: Awaitable[str]) -> str:
    async def run() -> str:
        return await awaitable

    return asyncio.run(run())


def test_sessions_are_isolated_and_opaque() -> None:
    store = SessionStore()
    a = store.create(subject="citius-ciso", display_name="CISO", access_token="tok-a")
    b = store.create(subject="citius-producer", display_name="Producer", access_token="tok-b")

    assert a.id != b.id
    assert len(a.id) >= 32
    fetched_a = store.get(a.id)
    fetched_b = store.get(b.id)
    assert fetched_a is not None and fetched_a.subject == "citius-ciso"
    assert fetched_b is not None and fetched_b.subject == "citius-producer"
    assert a.history_id != b.history_id


def test_public_view_hides_tokens() -> None:
    store = SessionStore()
    session = store.create(
        subject="citius-producer",
        display_name="Producer",
        access_token="secret-token",
        refresh_token="refresh-token",
        permissions=frozenset({"citius:crypto:sign"}),
    )
    view = session.public_view()
    assert "secret-token" not in str(view)
    assert "refresh-token" not in str(view)
    assert view["authenticated"] is True
    assert view["permissions"] == ["citius:crypto:sign"]


def test_expired_session_is_removed_on_get() -> None:
    store = SessionStore()
    session = store.create(subject="s", display_name="S", ttl_seconds=-1)
    assert session.is_expired()
    assert store.get(session.id) is None


def test_token_provider_reads_latest_token() -> None:
    store = SessionStore()
    session = store.create(subject="s", display_name="S", access_token="first")
    provider = store.token_provider(session.id)

    assert _await(provider()) == "first"
    store.replace_tokens(session.id, access_token="second")
    assert _await(provider()) == "second"


def test_token_provider_returns_empty_after_logout() -> None:
    store = SessionStore()
    session = store.create(subject="s", display_name="S", access_token="tok")
    provider = store.token_provider(session.id)
    store.delete(session.id)
    assert _await(provider()) == ""


def test_replace_tokens_updates_expiry() -> None:
    store = SessionStore()
    session = store.create(subject="s", display_name="S", access_token="tok")
    before = datetime.now(timezone.utc) + timedelta(seconds=30)
    updated = store.replace_tokens(session.id, access_token="tok2", ttl_seconds=3600)
    assert updated is not None
    assert updated.expires_at is not None
    assert updated.expires_at > before
