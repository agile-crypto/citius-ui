"""Server-side session store keyed by an opaque session id.

Access and refresh tokens live only in this server-side store. The browser
receives nothing but an opaque, HTTP-only session cookie. Sessions are isolated
by id so concurrent browser sessions never observe each other's identity,
tokens, or history.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True, slots=True)
class RefreshedTokens:
    """Result of a refresh-token exchange used to update a session in place."""

    access_token: str
    refresh_token: str = ""
    expires_in: float | None = None


@dataclass(frozen=True, slots=True)
class Session:
    """One authenticated browser session held entirely server-side."""

    id: str
    subject: str
    display_name: str
    history_id: str
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    expires_at: datetime | None = None
    endpoint: str | None = None
    permissions: frozenset[str] = frozenset()
    key_allow: tuple[str, ...] = ()
    key_deny: tuple[str, ...] = ()

    def is_expired(self, *, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        moment = now or datetime.now(timezone.utc)
        return moment >= self.expires_at

    def seconds_until_expiry(self, *, now: datetime | None = None) -> float | None:
        """Seconds until the access token expires, or None when unknown."""
        if self.expires_at is None:
            return None
        moment = now or datetime.now(timezone.utc)
        return (self.expires_at - moment).total_seconds()

    def public_view(self) -> dict[str, object]:
        """Return identity metadata safe to display, never the raw tokens."""
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "permissions": sorted(self.permissions),
            "key_allow": list(self.key_allow),
            "key_deny": list(self.key_deny),
            "endpoint": self.endpoint,
            "authenticated": bool(self.access_token),
        }


class SessionStore:
    """Thread-safe in-memory session store with opaque ids."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._refresh_locks: dict[str, asyncio.Lock] = {}

    def create(
        self,
        *,
        subject: str,
        display_name: str,
        access_token: str = "",
        refresh_token: str = "",
        id_token: str = "",
        ttl_seconds: float | None = None,
        endpoint: str | None = None,
        permissions: frozenset[str] = frozenset(),
        key_allow: tuple[str, ...] = (),
        key_deny: tuple[str, ...] = (),
    ) -> Session:
        session_id = secrets.token_urlsafe(32)
        history_id = secrets.token_urlsafe(16)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) if ttl_seconds is not None else None
        session = Session(
            id=session_id,
            subject=subject,
            display_name=display_name,
            history_id=history_id,
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=id_token,
            expires_at=expires_at,
            endpoint=endpoint,
            permissions=permissions,
            key_allow=key_allow,
            key_deny=key_deny,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str | None) -> Session | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return None
        if session.is_expired():
            self.delete(session_id)
            return None
        return session

    def replace_tokens(
        self,
        session_id: str,
        *,
        access_token: str,
        refresh_token: str = "",
        ttl_seconds: float | None = None,
    ) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
                if ttl_seconds is not None
                else session.expires_at
            )
            updated = replace(
                session,
                access_token=access_token,
                refresh_token=refresh_token or session.refresh_token,
                expires_at=expires_at,
            )
            self._sessions[session_id] = updated
        return updated

    def delete(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)
            self._refresh_locks.pop(session_id, None)

    def _refresh_lock(self, session_id: str) -> asyncio.Lock:
        with self._lock:
            lock = self._refresh_locks.get(session_id)
            if lock is None:
                lock = asyncio.Lock()
                self._refresh_locks[session_id] = lock
            return lock

    def token_provider(self, session_id: str) -> Callable[[], Awaitable[str]]:
        """Return an async callable that yields the session's current token.

        The provider re-reads the store on each call so a refreshed token is
        picked up without rebuilding the gRPC channel. It returns an empty
        string once the session is gone, which the SDK treats as no auth.
        """

        store = self

        async def provider() -> str:
            session = store.get(session_id)
            return session.access_token if session else ""

        return provider

    def refreshing_token_provider(
        self,
        session_id: str,
        *,
        refresher: Callable[[str], Awaitable[RefreshedTokens]],
        skew_seconds: float = 60.0,
    ) -> Callable[[], Awaitable[str]]:
        """Return a provider that proactively refreshes a near-expiry token.

        Before returning the token, the provider refreshes it when the access
        token expires within ``skew_seconds`` and a refresh token is present.
        Refreshes are serialized per session so concurrent RPCs never trigger
        overlapping refreshes; the second caller observes the token minted by
        the first. Any refresh failure falls back to the current token so a
        transient issuer error does not immediately break an active session.
        """

        store = self

        async def provider() -> str:
            session = store.get(session_id)
            if session is None:
                return ""
            remaining = session.seconds_until_expiry()
            if not session.refresh_token or remaining is None or remaining > skew_seconds:
                return session.access_token

            lock = store._refresh_lock(session_id)
            async with lock:
                # Re-read after acquiring the lock: a concurrent caller may have
                # already refreshed while we waited.
                session = store.get(session_id)
                if session is None:
                    return ""
                remaining = session.seconds_until_expiry()
                if remaining is not None and remaining > skew_seconds:
                    return session.access_token
                try:
                    refreshed = await refresher(session.refresh_token)
                except Exception:
                    # Keep the current token; the SDK surfaces UNAUTHENTICATED
                    # if the server ultimately rejects it.
                    return session.access_token
                updated = store.replace_tokens(
                    session_id,
                    access_token=refreshed.access_token,
                    refresh_token=refreshed.refresh_token,
                    ttl_seconds=refreshed.expires_in,
                )
                return updated.access_token if updated else session.access_token

        return provider
