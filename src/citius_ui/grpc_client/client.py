"""Per-session Citius client factory over the Python SDK.

Each browser session gets its own SDK clients bound to that session's token
provider, so a bearer token is fetched fresh for every RPC and never shared
across sessions on one channel.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from citius_sdk import ClientConfig, TLSConfig
from citius_sdk.services.crypto import CryptoClient
from citius_sdk.services.crypto_policy import CryptoPolicyClient
from citius_sdk.services.discovery import DiscoveryClient
from citius_sdk.services.key_management import KeyManagementClient
from citius_sdk.services.provider import ProviderClient

from citius_ui.config import AppConfig

TokenSupplier = Callable[[], Awaitable[str]]


class _CallableTokenProvider:
    """Adapts an async token supplier to the SDK TokenProvider protocol."""

    def __init__(self, supplier: TokenSupplier) -> None:
        self._supplier = supplier

    async def token(self) -> str:
        return await self._supplier()


def client_config(config: AppConfig) -> ClientConfig:
    """Translate UI configuration into an SDK ClientConfig."""
    if config.citius_tls_enabled:
        tls = TLSConfig(
            enabled=True,
            ca_cert=config.citius_tls_ca,
            server_name_override=config.citius_tls_server_name,
        )
    else:
        tls = TLSConfig(enabled=False)
    return ClientConfig(
        endpoint=config.citius_endpoint,
        tls=tls,
        timeout=config.citius_request_timeout_seconds,
    )


class CitiusClients:
    """Owns the SDK service clients for one session and closes them together."""

    def __init__(self, config: AppConfig, token_supplier: TokenSupplier) -> None:
        sdk_config = client_config(config)
        provider = _CallableTokenProvider(token_supplier)
        self.crypto = CryptoClient.connect(sdk_config, token_provider=provider)
        self.key_management = KeyManagementClient.connect(sdk_config, token_provider=provider)
        self.crypto_policy = CryptoPolicyClient.connect(sdk_config, token_provider=provider)
        self.discovery = DiscoveryClient.connect(sdk_config, token_provider=provider)
        self.providers = ProviderClient.connect(sdk_config, token_provider=provider)

    async def close(self) -> None:
        await self.crypto.close()
        await self.key_management.close()
        await self.crypto_policy.close()
        await self.discovery.close()
        await self.providers.close()
