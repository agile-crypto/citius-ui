from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.main import build_app


@pytest.fixture
def client() -> TestClient:
    config = AppConfig(session_cookie_secure=False)
    return TestClient(build_app(config, store=SessionStore()), follow_redirects=False)


def test_health_and_ready(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz").json()
    assert ready["status"] == "ready"


def test_index_shows_login_when_unauthenticated(client: TestClient) -> None:
    body = client.get("/").text
    assert "Development sign-in" in body


def test_dev_login_sets_httponly_session_cookie(client: TestClient) -> None:
    response = client.post("/dev-login", data={"persona": "producer"})
    assert response.status_code == 303
    cookie_header = response.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "citius_session=" in cookie_header


def test_dev_login_rejects_unknown_persona(client: TestClient) -> None:
    response = client.post("/dev-login", data={"persona": "intruder"})
    assert response.status_code == 400


def test_identity_requires_session(client: TestClient) -> None:
    assert client.get("/identity").status_code == 401


def test_identity_returns_metadata_without_token(client: TestClient) -> None:
    client.post("/dev-login", data={"persona": "producer", "access_token": "secret-token"})
    identity = client.get("/identity").json()
    assert identity["subject"] == "citius-producer"
    assert "secret-token" not in str(identity)
    assert "citius:crypto:sign" in identity["permissions"]


def test_logout_clears_session(client: TestClient) -> None:
    client.post("/dev-login", data={"persona": "consumer"})
    assert client.get("/identity").status_code == 200
    client.post("/logout")
    assert client.get("/identity").status_code == 401


def test_concurrent_sessions_are_isolated() -> None:
    config = AppConfig(session_cookie_secure=False)
    app = build_app(config, store=SessionStore())
    producer = TestClient(app, follow_redirects=False)
    consumer = TestClient(app, follow_redirects=False)

    producer.post("/dev-login", data={"persona": "producer"})
    consumer.post("/dev-login", data={"persona": "consumer"})

    assert producer.get("/identity").json()["subject"] == "citius-producer"
    assert consumer.get("/identity").json()["subject"] == "citius-consumer"


def test_logout_via_get_clears_session(client: TestClient) -> None:
    client.post("/dev-login", data={"persona": "ciso"})
    assert client.get("/identity").status_code == 200
    response = client.get("/logout")
    assert response.status_code == 303
    assert client.get("/identity").status_code == 401


def test_login_without_oidc_config_returns_503(tmp_path: Path) -> None:
    config = AppConfig(
        session_cookie_secure=False,
        oidc_config_path=tmp_path / "absent.json",
    )
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)
    assert client.get("/login").status_code == 503
    assert client.get("/auth/callback?code=x&state=y").status_code == 503


def test_login_redirects_to_authorization_endpoint(tmp_path: Path) -> None:
    config_file = tmp_path / "citius-ui-auth.json"
    config_file.write_text(
        json.dumps(
            {
                "issuer": "https://issuer.example",
                "audience": "aud",
                "web_app": {
                    "client_id": "client-123",
                    "redirect_uris": ["http://127.0.0.1/auth/callback"],
                    "post_logout_redirect_uris": ["http://127.0.0.1/"],
                    "enable_refresh_tokens": True,
                },
            }
        ),
        encoding="utf-8",
    )
    config = AppConfig(session_cookie_secure=False, oidc_config_path=config_file)
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)
    response = client.get("/login")
    assert response.status_code == 303
    location = response.headers["location"]
    assert location.startswith("https://issuer.example/oauth/v2/authorize")
    assert "code_challenge_method=S256" in location


def test_auth_callback_rejects_unknown_state(tmp_path: Path) -> None:
    config_file = tmp_path / "citius-ui-auth.json"
    config_file.write_text(
        json.dumps(
            {
                "issuer": "https://issuer.example",
                "audience": "aud",
                "web_app": {
                    "client_id": "client-123",
                    "redirect_uris": ["http://127.0.0.1/auth/callback"],
                    "post_logout_redirect_uris": ["http://127.0.0.1/"],
                    "enable_refresh_tokens": True,
                },
            }
        ),
        encoding="utf-8",
    )
    config = AppConfig(session_cookie_secure=False, oidc_config_path=config_file)
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)
    assert client.get("/auth/callback?code=abc&state=never-issued").status_code == 400
