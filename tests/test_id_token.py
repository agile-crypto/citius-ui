"""Unit tests for OIDC ID-token validation and identity extraction.

These build real RS256-signed tokens and stub the JWKS key resolution so the
signature path, issuer/audience/nonce/expiry checks, and identity extraction
are all exercised without contacting a live Zitadel.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from citius_ui.auth import oidc
from citius_ui.auth.oidc import Identity, OIDCConfig, OIDCError, validate_id_token

_ISSUER = "https://issuer.example"
_CLIENT_ID = "client-123"
_NONCE = "nonce-abc"


def _config() -> OIDCConfig:
    return OIDCConfig(
        issuer=_ISSUER,
        client_id=_CLIENT_ID,
        audience="aud",
        redirect_uri="http://127.0.0.1/auth/callback",
        post_logout_redirect_uri="http://127.0.0.1/",
        enable_refresh_tokens=True,
    )


@pytest.fixture()
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _stub_jwks(monkeypatch: pytest.MonkeyPatch, rsa_key: rsa.RSAPrivateKey) -> None:
    class _Key:
        def __init__(self, public_key: Any) -> None:
            self.key = public_key

    class _StubJWKClient:
        def __init__(self, public_key: Any) -> None:
            self._key = _Key(public_key)

        def get_signing_key_from_jwt(self, _token: str) -> Any:
            return self._key

    class _StubCache:
        def __init__(self, public_key: Any) -> None:
            self._client = _StubJWKClient(public_key)

        def get(self, _jwks_uri: str, *, ca_cert: str | None = None) -> Any:
            return self._client

    monkeypatch.setattr(oidc, "_JWKS_CACHE", _StubCache(rsa_key.public_key()))


def _make_token(rsa_key: rsa.RSAPrivateKey, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _CLIENT_ID,
        "sub": "user-sub-1",
        "iat": now,
        "exp": now + 300,
        "nonce": _NONCE,
        "name": "Citius Producer",
        "preferred_username": "citius-producer",
        "email": "citius-producer@citius.local",
    }
    claims.update(overrides)
    return jwt.encode(claims, rsa_key, algorithm="RS256")


def test_validate_id_token_returns_identity(rsa_key: rsa.RSAPrivateKey) -> None:
    identity = validate_id_token(_make_token(rsa_key), _config(), nonce=_NONCE)
    assert isinstance(identity, Identity)
    assert identity.subject == "user-sub-1"
    assert identity.username == "citius-producer"
    assert identity.display_name == "Citius Producer"
    assert identity.email == "citius-producer@citius.local"


def test_validate_rejects_bad_nonce(rsa_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(OIDCError, match="nonce"):
        validate_id_token(_make_token(rsa_key), _config(), nonce="different")


def test_validate_rejects_wrong_issuer(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _make_token(rsa_key, iss="https://evil.example")
    with pytest.raises(OIDCError, match="invalid ID token"):
        validate_id_token(token, _config(), nonce=_NONCE)


def test_validate_rejects_wrong_audience(rsa_key: rsa.RSAPrivateKey) -> None:
    token = _make_token(rsa_key, aud="some-other-client")
    with pytest.raises(OIDCError, match="invalid ID token"):
        validate_id_token(token, _config(), nonce=_NONCE)


def test_validate_rejects_expired(rsa_key: rsa.RSAPrivateKey) -> None:
    now = int(time.time())
    token = _make_token(rsa_key, iat=now - 600, exp=now - 300)
    with pytest.raises(OIDCError, match="invalid ID token"):
        validate_id_token(token, _config(), nonce=_NONCE)


def test_validate_rejects_wrong_signature(rsa_key: rsa.RSAPrivateKey) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(
        {
            "iss": _ISSUER,
            "aud": _CLIENT_ID,
            "sub": "user-sub-1",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "nonce": _NONCE,
        },
        other,
        algorithm="RS256",
    )
    with pytest.raises(OIDCError, match="invalid ID token"):
        validate_id_token(token, _config(), nonce=_NONCE)


def test_validate_rejects_empty_token() -> None:
    with pytest.raises(OIDCError, match="no id_token"):
        validate_id_token("", _config(), nonce=_NONCE)
