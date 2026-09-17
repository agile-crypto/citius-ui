"""Environment-backed runtime configuration for the Citius UI."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


def _boolean(values: Mapping[str, str], name: str, default: bool) -> bool:
    raw = values.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _integer(values: Mapping[str, str], name: str, default: int) -> int:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _number(values: Mapping[str, str], name: str, default: float) -> float:
    raw = values.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _optional_path(values: Mapping[str, str], name: str) -> Path | None:
    raw = values.get(name, "").strip()
    return Path(raw).expanduser() if raw else None


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Validated process configuration without credentials or access tokens."""

    ui_host: str = "127.0.0.1"
    ui_port: int = 7860
    citius_endpoint: str = "localhost:50051"
    citius_tls_enabled: bool = True
    citius_tls_ca: Path | None = None
    citius_tls_server_name: str | None = None
    citius_request_timeout_seconds: float = 10.0
    oidc_config_path: Path = Path("../citius-server/bootstrap/zitadel/citius-ui-auth.json")
    session_cookie_name: str = "citius_session"
    session_cookie_secure: bool = True
    history_limit: int = 200

    def __post_init__(self) -> None:
        if not self.ui_host or self.ui_host != self.ui_host.strip():
            raise ValueError("CITIUS_UI_HOST must be non-empty without surrounding whitespace")
        if not 1 <= self.ui_port <= 65535:
            raise ValueError("CITIUS_UI_PORT must be between 1 and 65535")
        if not self.citius_endpoint or self.citius_endpoint != self.citius_endpoint.strip():
            raise ValueError("CITIUS_ENDPOINT must be non-empty without surrounding whitespace")
        if "://" in self.citius_endpoint:
            raise ValueError("CITIUS_ENDPOINT must be a gRPC target without a URL scheme")
        if not self.citius_tls_enabled and (self.citius_tls_ca or self.citius_tls_server_name):
            raise ValueError("Citius TLS options cannot be set when CITIUS_TLS_ENABLED is false")
        if self.citius_request_timeout_seconds <= 0:
            raise ValueError("CITIUS_REQUEST_TIMEOUT_SECONDS must be greater than zero")
        if not self.session_cookie_name or self.session_cookie_name != self.session_cookie_name.strip():
            raise ValueError("CITIUS_SESSION_COOKIE_NAME must be non-empty without surrounding whitespace")
        if self.history_limit <= 0:
            raise ValueError("CITIUS_HISTORY_LIMIT must be greater than zero")

    @classmethod
    def from_env(cls, values: Mapping[str, str] | None = None) -> AppConfig:
        """Resolve configuration from environment-style string values."""

        source = os.environ if values is None else values
        server_name = source.get("CITIUS_TLS_SERVER_NAME", "").strip() or None
        oidc_path = source.get(
            "CITIUS_OIDC_CONFIG_PATH",
            "../citius-server/bootstrap/zitadel/citius-ui-auth.json",
        ).strip()
        if not oidc_path:
            raise ValueError("CITIUS_OIDC_CONFIG_PATH must be non-empty")
        return cls(
            ui_host=source.get("CITIUS_UI_HOST", "127.0.0.1"),
            ui_port=_integer(source, "CITIUS_UI_PORT", 7860),
            citius_endpoint=source.get("CITIUS_ENDPOINT", "localhost:50051"),
            citius_tls_enabled=_boolean(source, "CITIUS_TLS_ENABLED", True),
            citius_tls_ca=_optional_path(source, "CITIUS_TLS_CA"),
            citius_tls_server_name=server_name,
            citius_request_timeout_seconds=_number(source, "CITIUS_REQUEST_TIMEOUT_SECONDS", 10.0),
            oidc_config_path=Path(oidc_path).expanduser(),
            session_cookie_name=source.get("CITIUS_SESSION_COOKIE_NAME", "citius_session"),
            session_cookie_secure=_boolean(source, "CITIUS_SESSION_COOKIE_SECURE", True),
            history_limit=_integer(source, "CITIUS_HISTORY_LIMIT", 200),
        )
