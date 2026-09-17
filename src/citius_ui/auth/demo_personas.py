"""Development-only demo persona definitions.

These describe the CISO, producer, and consumer personas as non-secret metadata
for local development sign-in. They are not a substitute for hosted Zitadel
Authorization Code with PKCE, and they carry no passwords or client secrets. A
real access token is supplied only when the interactive login is wired.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DemoPersona:
    """Non-secret persona metadata for development sign-in."""

    key: str
    username: str
    display_name: str
    description: str
    permissions: frozenset[str]
    key_allow: tuple[str, ...] = ()
    key_deny: tuple[str, ...] = ()


DEMO_PERSONAS: dict[str, DemoPersona] = {
    "ciso": DemoPersona(
        key="ciso",
        username="citius-ciso",
        display_name="Citius CISO",
        description="Govern policies and key lifecycle without cryptographic operations.",
        permissions=frozenset(
            {
                "citius:policy:read",
                "citius:policy:write",
                "citius:keys:create",
                "citius:keys:read",
                "citius:keys:rotate",
                "citius:keys:update-policy",
                "citius:discovery:read",
                "citius:provider:read",
            }
        ),
        key_allow=("demo-*",),
    ),
    "producer": DemoPersona(
        key="producer",
        username="citius-producer",
        display_name="Citius Producer",
        description="Create and read keys, encrypt data, and sign messages.",
        permissions=frozenset(
            {
                "citius:policy:read",
                "citius:keys:create",
                "citius:keys:read",
                "citius:discovery:read",
                "citius:provider:read",
                "citius:crypto:sign",
                "citius:crypto:encrypt",
            }
        ),
        key_allow=("demo-*",),
        key_deny=("demo-restricted-*",),
    ),
    "consumer": DemoPersona(
        key="consumer",
        username="citius-consumer",
        display_name="Citius Consumer",
        description="Read keys, decrypt ciphertext, and verify signatures.",
        permissions=frozenset(
            {
                "citius:policy:read",
                "citius:keys:read",
                "citius:discovery:read",
                "citius:crypto:verify",
                "citius:crypto:decrypt",
            }
        ),
        key_allow=("demo-*",),
        key_deny=("demo-restricted-*",),
    ),
}


def get_persona(key: str) -> DemoPersona | None:
    """Return a demo persona by key, or None when unknown."""
    return DEMO_PERSONAS.get(key)
