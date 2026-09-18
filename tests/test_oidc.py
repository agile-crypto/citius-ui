from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from citius_ui.auth.oidc import (
    OIDCConfig,
    OIDCError,
    authorization_url,
    create_pkce_challenge,
    end_session_url,
    exchange_code,
    load_oidc_config,
    refresh_tokens,
)

_CONFIG = {
    "project_id": "390129041866227715",
    "issuer": "https://citius-auth.localhost:8443",
    "audience": "urn:zitadel:iam:org:project:id:390129041866227715:aud",
    "web_app": {
        "client_id": "390994011386609667",
        "redirect_uris": ["http://127.0.0.1:7861/auth/callback"],
        "post_logout_redirect_uris": ["http://127.0.0.1:7861/"],
        "enable_refresh_tokens": True,
    },
}


def _write(tmp_path: Path, data: dict[str, Any]) -> str:
    path = tmp_path / "citius-ui-auth.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_load_oidc_config(tmp_path: Path) -> None:
    config = load_oidc_config(_write(tmp_path, _CONFIG))
    assert config.issuer == "https://citius-auth.localhost:8443"
    assert config.client_id == "390994011386609667"
    assert config.redirect_uri == "http://127.0.0.1:7861/auth/callback"
    assert config.post_logout_redirect_uri == "http://127.0.0.1:7861/"
    assert config.enable_refresh_tokens is True
    assert config.authorization_endpoint.endswith("/oauth/v2/authorize")
    assert config.token_endpoint.endswith("/oauth/v2/token")
    assert config.end_session_endpoint.endswith("/oidc/v1/end_session")


def test_load_oidc_config_rejects_missing_web_app(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="web_app"):
        load_oidc_config(_write(tmp_path, {"issuer": "x"}))


def test_load_oidc_config_rejects_missing_redirect(tmp_path: Path) -> None:
    data = {"issuer": "x", "web_app": {"client_id": "c", "post_logout_redirect_uris": ["/"]}}
    with pytest.raises(ValueError, match="redirect_uris"):
        load_oidc_config(_write(tmp_path, data))


def test_pkce_challenge_is_valid_s256() -> None:
    pkce = create_pkce_challenge()
    assert pkce.method == "S256"
    expected = base64.urlsafe_b64encode(hashlib.sha256(pkce.verifier.encode()).digest())
    assert pkce.challenge == expected.rstrip(b"=").decode()
    assert "=" not in pkce.challenge
    assert pkce.state and pkce.nonce
    assert create_pkce_challenge().verifier != pkce.verifier


def test_authorization_url_contains_pkce_and_state() -> None:
    config = load_oidc_config_dict()
    pkce = create_pkce_challenge()
    url = authorization_url(config, pkce)
    query = parse_qs(urlparse(url).query)
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [config.client_id]
    assert query["code_challenge"] == [pkce.challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [pkce.state]
    assert query["nonce"] == [pkce.nonce]
    assert "offline_access" in query["scope"][0]
    # The configured audience must be requested as a scope so Zitadel embeds the
    # Citius project audience in the access token.
    assert config.audience in query["scope"][0].split(" ")


def test_authorization_url_includes_project_audience_scope() -> None:
    config = OIDCConfig(
        issuer="https://issuer",
        client_id="c",
        audience="urn:zitadel:iam:org:project:id:12345:aud",
        redirect_uri="http://127.0.0.1/cb",
        post_logout_redirect_uri="http://127.0.0.1/",
        enable_refresh_tokens=True,
    )
    query = parse_qs(urlparse(authorization_url(config, create_pkce_challenge())).query)
    scopes = query["scope"][0].split(" ")
    assert "urn:zitadel:iam:org:project:id:12345:aud" in scopes
    # The audience is appended exactly once.
    assert scopes.count("urn:zitadel:iam:org:project:id:12345:aud") == 1


def test_authorization_url_omits_offline_access_without_refresh() -> None:
    config = OIDCConfig(
        issuer="https://issuer",
        client_id="c",
        audience="a",
        redirect_uri="http://127.0.0.1/cb",
        post_logout_redirect_uri="http://127.0.0.1/",
        enable_refresh_tokens=False,
    )
    url = authorization_url(config, create_pkce_challenge())
    query = parse_qs(urlparse(url).query)
    assert "offline_access" not in query["scope"][0]


def load_oidc_config_dict() -> OIDCConfig:
    return OIDCConfig(
        issuer="https://citius-auth.localhost:8443",
        client_id="390994011386609667",
        audience="aud",
        redirect_uri="http://127.0.0.1:7861/auth/callback",
        post_logout_redirect_uri="http://127.0.0.1:7861/",
        enable_refresh_tokens=True,
    )


def _mock_client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_exchange_code_returns_tokens() -> None:
    config = load_oidc_config_dict()
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(pair.split("=", 1) for pair in request.content.decode().split("&"))
        captured.update(body)
        return httpx.Response(
            200,
            json={
                "access_token": "at-123",
                "refresh_token": "rt-456",
                "id_token": "it-789",
                "expires_in": 3600,
            },
        )

    async with _mock_client(handler) as client:
        tokens = await exchange_code(client, config, code="auth-code", code_verifier="verifier")

    assert tokens.access_token == "at-123"
    assert tokens.refresh_token == "rt-456"
    assert tokens.id_token == "it-789"
    assert tokens.expires_in == 3600
    assert captured["grant_type"] == "authorization_code"
    assert captured["code_verifier"] == "verifier"
    assert "client_secret" not in captured


@pytest.mark.asyncio
async def test_exchange_code_raises_on_error_status() -> None:
    config = load_oidc_config_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    async with _mock_client(handler) as client:
        with pytest.raises(OIDCError):
            await exchange_code(client, config, code="bad", code_verifier="v")


@pytest.mark.asyncio
async def test_exchange_code_maps_transport_error_to_oidc_error() -> None:
    config = load_oidc_config_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("TLS verify failed")

    async with _mock_client(handler) as client:
        with pytest.raises(OIDCError, match="token endpoint"):
            await exchange_code(client, config, code="c", code_verifier="v")


@pytest.mark.asyncio
async def test_exchange_code_requires_access_token() -> None:
    config = load_oidc_config_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"refresh_token": "rt"})

    async with _mock_client(handler) as client:
        with pytest.raises(OIDCError):
            await exchange_code(client, config, code="c", code_verifier="v")


@pytest.mark.asyncio
async def test_refresh_tokens_returns_new_access_token() -> None:
    config = load_oidc_config_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(pair.split("=", 1) for pair in request.content.decode().split("&"))
        assert body["grant_type"] == "refresh_token"
        return httpx.Response(200, json={"access_token": "at-new", "refresh_token": "rt-new"})

    async with _mock_client(handler) as client:
        tokens = await refresh_tokens(client, config, refresh_token="rt-old")

    assert tokens.access_token == "at-new"
    assert tokens.refresh_token == "rt-new"


def test_end_session_url_includes_id_token_hint() -> None:
    config = load_oidc_config_dict()
    url = end_session_url(config, id_token="it-789")
    query = parse_qs(urlparse(url).query)
    assert url.startswith(config.end_session_endpoint)
    assert query["id_token_hint"] == ["it-789"]
    assert query["post_logout_redirect_uri"] == [config.post_logout_redirect_uri]


def test_authorization_url_requests_zitadel_roles_scope() -> None:
    config = load_oidc_config_dict()
    query = parse_qs(urlparse(authorization_url(config, create_pkce_challenge())).query)
    assert "urn:zitadel:iam:org:projects:roles" in query["scope"][0].split(" ")


def test_extract_roles_reads_plain_and_project_scoped_claims() -> None:
    from citius_ui.auth.oidc import extract_roles

    claims: dict[str, object] = {
        "sub": "1",
        "urn:zitadel:iam:org:project:roles": {"citius:crypto:sign": {"1": "org"}},
        "urn:zitadel:iam:org:project:12345:roles": {"citius:keys:read": {"1": "org"}},
        "unrelated": {"nope": True},
    }
    assert extract_roles(claims) == frozenset({"citius:crypto:sign", "citius:keys:read"})


def test_extract_roles_handles_list_claims_and_absence() -> None:
    from citius_ui.auth.oidc import extract_roles

    assert extract_roles({"urn:zitadel:iam:org:project:roles": ["a", "b"]}) == frozenset({"a", "b"})
    assert extract_roles({"sub": "1"}) == frozenset()


def test_extract_grants_prefers_citius_permissions_claim() -> None:
    from citius_ui.auth.oidc import extract_grants

    claims: dict[str, object] = {
        "urn:citius:permissions": ["citius:crypto:sign", "citius:keys:read", " "],
        "urn:citius:allowed_key_patterns": ["demo-*"],
        "urn:citius:deny_key_patterns": ["demo-restricted-*"],
        "urn:zitadel:iam:org:project:roles": {"ignored-role": {"1": "org"}},
    }
    grants = extract_grants(claims)
    assert grants.permissions == frozenset({"citius:crypto:sign", "citius:keys:read"})
    assert grants.key_allow == ("demo-*",)
    assert grants.key_deny == ("demo-restricted-*",)


def test_extract_grants_falls_back_to_zitadel_roles() -> None:
    from citius_ui.auth.oidc import extract_grants

    claims: dict[str, object] = {"urn:zitadel:iam:org:project:roles": {"citius:crypto:sign": {"1": "org"}}}
    grants = extract_grants(claims)
    assert grants.permissions == frozenset({"citius:crypto:sign"})
    assert grants.key_allow == ()
    assert grants.key_deny == ()


@pytest.mark.asyncio
async def test_fetch_userinfo_returns_claims() -> None:
    from citius_ui.auth.oidc import fetch_userinfo

    config = load_oidc_config_dict()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(config.userinfo_endpoint)
        assert request.headers["authorization"] == "Bearer at-1"
        return httpx.Response(200, json={"sub": "1", "urn:citius:permissions": ["citius:keys:read"]})

    async with _mock_client(handler) as client:
        claims = await fetch_userinfo(client, config, access_token="at-1")
    assert claims["urn:citius:permissions"] == ["citius:keys:read"]


@pytest.mark.asyncio
async def test_fetch_userinfo_raises_with_error_detail() -> None:
    from citius_ui.auth.oidc import OIDCError, fetch_userinfo

    config = load_oidc_config_dict()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_token", "error_description": "expired"})

    async with _mock_client(handler) as client:
        with pytest.raises(OIDCError, match="invalid_token: expired"):
            await fetch_userinfo(client, config, access_token="at-1")


@pytest.mark.asyncio
async def test_fetch_userinfo_rejects_non_json_response() -> None:
    from citius_ui.auth.oidc import OIDCError, fetch_userinfo

    config = load_oidc_config_dict()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    async with _mock_client(handler) as client:
        with pytest.raises(OIDCError, match="non-JSON"):
            await fetch_userinfo(client, config, access_token="at-1")
