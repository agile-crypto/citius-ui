from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.main import build_app


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    # No OIDC config file: hosted login is unavailable, so "/" and "/dev-login"
    # deterministically exercise the development sign-in path in these tests,
    # independent of whether a sibling citius-server checkout happens to exist.
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
    return TestClient(build_app(config, store=SessionStore()), follow_redirects=False)


def test_health_and_ready(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz").json()
    assert ready["status"] == "ready"


def test_index_shows_dev_login_when_oidc_unconfigured(client: TestClient) -> None:
    body = client.get("/").text
    assert "Development sign-in" in body


def test_dev_login_page_reachable_via_get(client: TestClient) -> None:
    assert "Development sign-in" in client.get("/dev-login").text


def test_index_redirects_to_hosted_login_when_oidc_configured(tmp_path: Path) -> None:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)
    response = client.get("/")
    assert response.status_code == 303
    assert response.headers["location"].startswith("https://issuer.example/oauth/v2/authorize")


def test_dev_login_page_still_reachable_when_oidc_configured(tmp_path: Path) -> None:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)
    assert "Development sign-in" in client.get("/dev-login").text


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


def test_concurrent_sessions_are_isolated(tmp_path: Path) -> None:
    config = AppConfig(session_cookie_secure=False, oidc_config_path=tmp_path / "absent.json")
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


def test_auth_callback_prefers_userinfo_display_name_over_bare_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reproduces the reported bug: when the OIDC app doesn't embed profile
    # claims in the ID token, validate_id_token falls back to the subject as
    # the display name ("391313365793767427" instead of "Citius CISO"). The
    # callback must recover the real name from the userinfo claims.
    import citius_ui.main as main_module
    from citius_ui.auth.oidc import Identity, TokenSet

    async def fake_exchange(_client: object, _config: object, **_kwargs: object) -> TokenSet:
        return TokenSet(access_token="at", refresh_token="rt", id_token="idt", expires_in=3600)

    def fake_validate(*_args: object, **_kwargs: object) -> Identity:
        return Identity(subject="391313365793767427", display_name="391313365793767427")

    async def fake_userinfo(_client: object, _config: object, *, access_token: str) -> dict[str, object]:
        return {
            "sub": "391313365793767427",
            "name": "Citius CISO",
            "preferred_username": "citius-ciso",
            "urn:citius:permissions": ["citius:policy:read"],
        }

    monkeypatch.setattr(main_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(main_module, "validate_id_token", fake_validate)
    monkeypatch.setattr(main_module, "fetch_userinfo", fake_userinfo)

    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)

    state = _state_from_login(client)
    assert client.get(f"/auth/callback?code=auth-code&state={state}").status_code == 303
    body = client.get("/identity").json()
    assert body["display_name"] == "Citius CISO"
    assert body["subject"] == "391313365793767427"


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


# ── Every path but sign-in and the probes needs a session ─────────────────────

_PAGE = {"accept": "text/html,application/xhtml+xml"}


def test_opening_a_page_without_a_session_sends_you_to_sign_in(client: TestClient) -> None:
    response = client.get("/workbench/", headers=_PAGE)
    assert response.status_code == 303
    assert response.headers["location"] == "/?next=%2Fworkbench%2F"
    # A path nobody has thought of yet is locked the same way.
    assert client.get("/anything/new?x=1", headers=_PAGE).headers["location"] == "/?next=%2Fanything%2Fnew%3Fx%3D1"


def test_calls_without_a_session_get_401_not_a_redirect(client: TestClient) -> None:
    response = client.post("/workbench/gradio_api/queue/join", json={})
    assert response.status_code == 401
    assert response.json() == {"error": "not signed in"}
    assert client.get("/workbench/gradio_api/info").status_code == 401


def test_sign_in_routes_and_probes_stay_open(client: TestClient) -> None:
    for path in ("/", "/dev-login", "/healthz", "/readyz"):
        assert client.get(path, headers=_PAGE).status_code == 200, path
    assert client.get("/logout").status_code == 303
    assert client.get("/identity").status_code == 401  # its own answer, for scripts


def test_a_cookie_from_before_a_restart_is_cleared(client: TestClient) -> None:
    client.cookies.set("citius_session", "from-the-last-process")
    response = client.get("/workbench/", headers=_PAGE)
    assert response.status_code == 303
    assert 'citius_session=""' in response.headers["set-cookie"]


def test_dev_sign_in_returns_to_the_page_asked_for(client: TestClient) -> None:
    page = client.get("/?next=%2Fworkbench%2F").text
    assert '<input type="hidden" name="next" value="/workbench/" />' in page
    response = client.post("/dev-login", data={"persona": "ciso", "next": "/workbench/"})
    assert (response.status_code, response.headers["location"]) == (303, "/workbench/")
    # Signed in, the page opens, and is not cached.
    workbench = client.get("/workbench/", headers=_PAGE)
    assert workbench.status_code == 200
    assert workbench.headers["cache-control"] == "no-store"
    # With a session, a return address is followed straight away.
    assert client.get("/?next=%2Fworkbench%2F").headers["location"] == "/workbench/"


@pytest.mark.parametrize(
    "unsafe",
    ["https://evil.example/", "//evil.example/", "/\\evil.example", "evil", "/ok\r\nSet-Cookie: x=1", "/" + "a" * 3000],
)
def test_a_return_address_off_this_site_is_ignored(client: TestClient, unsafe: str) -> None:
    from citius_ui.main import safe_next

    assert safe_next(unsafe) is None
    assert 'name="next"' not in client.get("/", params={"next": unsafe}).text
    response = client.post("/dev-login", data={"persona": "ciso", "next": unsafe})
    assert response.headers["location"] == "/"


def test_hosted_sign_in_returns_to_the_page_asked_for(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from urllib.parse import parse_qs, urlparse

    import citius_ui.main as main_module
    from citius_ui.auth.oidc import Identity, TokenSet

    async def fake_exchange(_client: object, _config: object, *, code: str, code_verifier: str) -> TokenSet:
        return TokenSet(access_token="at", refresh_token="rt", id_token="idt", expires_in=3600)

    def fake_validate(*_args: object, **_kwargs: object) -> Identity:
        return Identity(subject="user-1", display_name="Citius CISO", username="citius-ciso")

    async def fake_userinfo(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"sub": "user-1"}

    monkeypatch.setattr(main_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(main_module, "validate_id_token", fake_validate)
    monkeypatch.setattr(main_module, "fetch_userinfo", fake_userinfo)
    config = AppConfig(session_cookie_secure=False, oidc_config_path=_oidc_config_file(tmp_path))
    client = TestClient(build_app(config, store=SessionStore()), follow_redirects=False)

    to_sign_in = client.get("/workbench/", headers=_PAGE).headers["location"]
    to_issuer = client.get(to_sign_in).headers["location"]
    assert to_issuer.startswith("https://issuer.example/oauth/v2/authorize")
    state = parse_qs(urlparse(to_issuer).query)["state"][0]
    response = client.get(f"/auth/callback?code=c&state={state}")
    assert (response.status_code, response.headers["location"]) == (303, "/workbench/")
