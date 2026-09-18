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


def test_refreshing_provider_refreshes_near_expiry() -> None:
    from citius_ui.auth.sessions import RefreshedTokens

    store = SessionStore()
    session = store.create(
        subject="s",
        display_name="S",
        access_token="old",
        refresh_token="rt-1",
        ttl_seconds=10,  # inside the default 60s skew window
    )
    calls: list[str] = []

    async def refresher(refresh_token: str) -> RefreshedTokens:
        calls.append(refresh_token)
        return RefreshedTokens(access_token="new", refresh_token="rt-2", expires_in=3600)

    provider = store.refreshing_token_provider(session.id, refresher=refresher)
    assert _await(provider()) == "new"
    assert calls == ["rt-1"]
    # Second call is now far from expiry, so no further refresh occurs.
    assert _await(provider()) == "new"
    assert calls == ["rt-1"]


def test_refreshing_provider_skips_when_token_fresh() -> None:
    from citius_ui.auth.sessions import RefreshedTokens

    store = SessionStore()
    session = store.create(
        subject="s",
        display_name="S",
        access_token="fresh",
        refresh_token="rt-1",
        ttl_seconds=3600,
    )

    async def refresher(_refresh_token: str) -> RefreshedTokens:  # pragma: no cover
        raise AssertionError("refresh must not run for a fresh token")

    provider = store.refreshing_token_provider(session.id, refresher=refresher)
    assert _await(provider()) == "fresh"


def test_refreshing_provider_serializes_concurrent_refreshes() -> None:
    from citius_ui.auth.sessions import RefreshedTokens

    store = SessionStore()
    session = store.create(
        subject="s",
        display_name="S",
        access_token="old",
        refresh_token="rt-1",
        ttl_seconds=5,
    )
    calls = 0

    async def refresher(_refresh_token: str) -> RefreshedTokens:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        return RefreshedTokens(access_token="new", refresh_token="rt-2", expires_in=3600)

    provider = store.refreshing_token_provider(session.id, refresher=refresher)

    async def run() -> list[str]:
        return list(await asyncio.gather(provider(), provider(), provider()))

    results = asyncio.run(run())
    assert results == ["new", "new", "new"]
    assert calls == 1  # one refresh serves all concurrent callers


def test_refreshing_provider_falls_back_on_refresh_failure() -> None:
    from citius_ui.auth.sessions import RefreshedTokens

    store = SessionStore()
    session = store.create(
        subject="s",
        display_name="S",
        access_token="old",
        refresh_token="rt-1",
        ttl_seconds=5,
    )

    async def refresher(_refresh_token: str) -> RefreshedTokens:
        raise RuntimeError("issuer down")

    provider = store.refreshing_token_provider(session.id, refresher=refresher)
    assert _await(provider()) == "old"
