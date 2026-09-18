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


def _oidc_config_file(tmp_path: Path) -> Path:
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
    return config_file


def _state_from_login(client: TestClient) -> str:
    from urllib.parse import parse_qs, urlparse

    location = client.get("/login").headers["location"]
    return parse_qs(urlparse(location).query)["state"][0]


def test_auth_callback_validates_id_token_and_sets_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import citius_ui.main as main_module
    from citius_ui.auth.oidc import Identity, TokenSet

    async def fake_exchange(_client: object, _config: object, *, code: str, code_verifier: str) -> TokenSet:
        assert code == "auth-code"
        assert code_verifier
        return TokenSet(
            access_token="ACCESS-SECRET-XYZ",
            refresh_token="REFRESH-SECRET-XYZ",
            id_token="IDTOKEN-SECRET-XYZ",
            expires_in=3600,
        )

    captured_nonce: dict[str, str] = {}

    def fake_validate(id_token: str, _config: object, *, nonce: str, **_kwargs: object) -> Identity:
        assert id_token == "IDTOKEN-SECRET-XYZ"
        captured_nonce["nonce"] = nonce
        return Identity(subject="user-1", display_name="Citius Producer", username="citius-producer")

    async def fake_userinfo(_client: object, _config: object, *, access_token: str) -> dict[str, object]:
        assert access_token == "ACCESS-SECRET-XYZ"
        return {
            "sub": "user-1",
            "urn:citius:permissions": ["citius:crypto:sign", "citius:keys:read"],
            "urn:citius:allowed_key_patterns": ["demo-*"],
            "urn:citius:deny_key_patterns": ["demo-restricted-*"],
        }

    monkeypatch.setattr(main_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(main_module, "validate_id_token", fake_validate)
    monkeypatch.setattr(main_module, "fetch_userinfo", fake_userinfo)

    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    store = SessionStore()
    client = TestClient(build_app(config, store=store), follow_redirects=False)

    state = _state_from_login(client)
    response = client.get(f"/auth/callback?code=auth-code&state={state}")
    assert response.status_code == 303
    assert captured_nonce["nonce"]

    identity = client.get("/identity")
    assert identity.status_code == 200
    body = identity.json()
    assert body["subject"] == "user-1"
    assert body["display_name"] == "Citius Producer"
    # Granted permissions and key-access patterns come from the userinfo claims.
    assert body["permissions"] == ["citius:crypto:sign", "citius:keys:read"]
    assert body["key_allow"] == ["demo-*"]
    assert body["key_deny"] == ["demo-restricted-*"]
    # The raw tokens are never exposed to the browser.
    assert "SECRET" not in identity.text


def test_auth_callback_grants_from_id_token_when_userinfo_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import citius_ui.main as main_module
    from citius_ui.auth.oidc import Identity, OIDCError, TokenSet

    async def fake_exchange(_client: object, _config: object, **_kwargs: object) -> TokenSet:
        return TokenSet(access_token="at", refresh_token="rt", id_token="idt", expires_in=3600)

    def fake_validate(_id_token: str, _config: object, **_kwargs: object) -> Identity:
        claims: dict[str, object] = {"urn:citius:permissions": ["citius:crypto:verify"]}
        return Identity(subject="user-2", display_name="Citius Consumer", claims=claims)

    async def failing_userinfo(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise OIDCError("userinfo request failed with status 500")

    monkeypatch.setattr(main_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(main_module, "validate_id_token", fake_validate)
    monkeypatch.setattr(main_module, "fetch_userinfo", failing_userinfo)

    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)

    state = _state_from_login(client)
    assert client.get(f"/auth/callback?code=auth-code&state={state}").status_code == 303
    body = client.get("/identity").json()
    assert body["permissions"] == ["citius:crypto:verify"]


def test_auth_callback_rejects_invalid_id_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import citius_ui.main as main_module
    from citius_ui.auth.oidc import OIDCError, TokenSet

    async def fake_exchange(_client: object, _config: object, *, code: str, code_verifier: str) -> TokenSet:
        return TokenSet(access_token="at", refresh_token="rt", id_token="idt", expires_in=3600)

    def fake_validate(*_args: object, **_kwargs: object) -> object:
        raise OIDCError("nonce mismatch")

    monkeypatch.setattr(main_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(main_module, "validate_id_token", fake_validate)

    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)

    state = _state_from_login(client)
    response = client.get(f"/auth/callback?code=auth-code&state={state}")
    assert response.status_code == 401
    # No session cookie was set.
    assert config.session_cookie_name not in response.cookies
