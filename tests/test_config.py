from pathlib import Path

import pytest

from citius_ui.config import AppConfig


def test_defaults_are_safe_for_local_tls() -> None:
    config = AppConfig.from_env({})

    assert config.ui_host == "127.0.0.1"
    assert config.ui_port == 7860
    assert config.citius_endpoint == "localhost:50051"
    assert config.citius_tls_enabled is True
    assert config.session_cookie_secure is True
    assert config.oidc_config_path == Path("../citius-server/bootstrap/zitadel/citius-ui-auth.json")


def test_environment_values_are_parsed() -> None:
    config = AppConfig.from_env(
        {
            "CITIUS_UI_HOST": "0.0.0.0",
            "CITIUS_UI_PORT": "8080",
            "CITIUS_ENDPOINT": "citius.internal:443",
            "CITIUS_TLS_ENABLED": "yes",
            "CITIUS_TLS_CA": "/run/certs/ca.pem",
            "CITIUS_TLS_SERVER_NAME": "citius.internal",
            "CITIUS_REQUEST_TIMEOUT_SECONDS": "2.5",
            "CITIUS_OIDC_CONFIG_PATH": "/run/config/ui-auth.json",
            "CITIUS_SESSION_COOKIE_NAME": "citius_demo",
            "CITIUS_SESSION_COOKIE_SECURE": "on",
            "CITIUS_HISTORY_LIMIT": "50",
        }
    )

    assert config.ui_host == "0.0.0.0"
    assert config.ui_port == 8080
    assert config.citius_endpoint == "citius.internal:443"
    assert config.citius_tls_ca == Path("/run/certs/ca.pem")
    assert config.citius_tls_server_name == "citius.internal"
    assert config.citius_request_timeout_seconds == 2.5
    assert config.oidc_config_path == Path("/run/config/ui-auth.json")
    assert config.session_cookie_name == "citius_demo"
    assert config.history_limit == 50


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"CITIUS_UI_PORT": "0"}, "CITIUS_UI_PORT"),
        ({"CITIUS_UI_PORT": "not-a-number"}, "CITIUS_UI_PORT"),
        ({"CITIUS_ENDPOINT": "https://localhost:50051"}, "without a URL scheme"),
        ({"CITIUS_TLS_ENABLED": "sometimes"}, "CITIUS_TLS_ENABLED"),
        (
            {"CITIUS_TLS_ENABLED": "false", "CITIUS_TLS_CA": "/tmp/ca.pem"},
            "TLS options cannot be set",
        ),
        ({"CITIUS_REQUEST_TIMEOUT_SECONDS": "0"}, "greater than zero"),
        ({"CITIUS_OIDC_CONFIG_PATH": " "}, "CITIUS_OIDC_CONFIG_PATH"),
        ({"CITIUS_SESSION_COOKIE_NAME": " "}, "CITIUS_SESSION_COOKIE_NAME"),
        ({"CITIUS_HISTORY_LIMIT": "0"}, "CITIUS_HISTORY_LIMIT"),
    ],
)
def test_invalid_environment_values_fail_closed(values: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        AppConfig.from_env(values)
