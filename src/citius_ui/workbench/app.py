"""Service-organized Gradio Workbench wired to the SDK-backed actions."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import gradio as gr

from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import Availability
from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.grpc_client.client import CitiusClients
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.workbench.actions import build_registry, registry_overview
from citius_ui.workbench.history_view import (
    ACTIVITY_HEADERS,
    PRODUCER_HEADERS,
    activity_rows,
    latest_consumer_handoff,
    producer_rows,
)

_AVAILABILITY_BADGE = {
    Availability.AVAILABLE: "🟢 Available",
    Availability.UNIMPLEMENTED: "🟡 Unimplemented by the server",
    Availability.UNAVAILABLE: "🟠 Unavailable (missing dependency)",
    Availability.FORBIDDEN: "🔴 Forbidden for this identity",
    Availability.UNKNOWN: "⚪ Unknown until probed",
}

CSS = """
.title-container { text-align: center; margin: 12px 0 18px; padding: 24px;
                   background: #a4c2f4; border-radius: 10px;
                   box-shadow: 0 4px 8px rgba(0, 0, 0, .10); }
.title-container h1 { color: #17233b; font-size: 2.35rem; margin: 0 0 8px; }
.title-container p { color: #263a5d; font-size: 1rem; margin: 0; }
.title-container hr { width: 80%; height: 2px; background: #ffffff; border: 0; margin: 12px auto; }
.section-title { border-left: 5px solid #6d83f2; padding: 6px 12px; margin: 18px 0 10px; }
.section-title h2 { font-size: 1.2rem; margin: 0; }
.identity-note { border-left: 4px solid #5b8c5a; padding: 8px 12px; }
footer { visibility: hidden; }
"""

SERVICE_LABELS = {
    "CryptoPolicyService": "Crypto Policy",
    "KeyManagementService": "Key Management",
    "CryptoService": "Cryptographic Operations",
    "AlgorithmDiscoveryService": "Algorithm Discovery",
    "ProviderService": "Provider Management",
    "KeyEstablishmentService": "Key Establishment",
    "StreamingCryptoService": "Streaming Cryptography",
}

SERVICE_ORDER = [
    "CryptoPolicyService",
    "KeyManagementService",
    "CryptoService",
    "AlgorithmDiscoveryService",
    "ProviderService",
    "KeyEstablishmentService",
    "StreamingCryptoService",
]

REQUEST_EXAMPLES: dict[tuple[str, str], dict[str, Any]] = {
    ("CryptoPolicyService", "CreateCryptoPolicy"): {
        "name": "demo-signing-policy",
        "policy_document": "version: v1\nallowed_operations: [SIGN, VERIFY]",
        "format": "yaml",
    },
    ("CryptoPolicyService", "ReadCryptoPolicy"): {"name": "demo-signing-policy"},
    ("KeyManagementService", "CreateKey"): {
        "name": "demo-signing-key",
        "policy": "demo-signing-policy",
        "template_id": "ecdsa-p256-sha256",
    },
    ("KeyManagementService", "ReadKey"): {"name": "demo-signing-key"},
    ("CryptoService", "Sign"): {"key_name": "demo-signing-key", "message": "Hello from Citius"},
    ("CryptoService", "Encrypt"): {
        "key_name": "demo-encryption-key",
        "plaintext": "Sensitive demo payload",
    },
}


def _ordered_services(grouped: dict[str, list[tuple[str, Availability]]]) -> list[str]:
    known = [service for service in SERVICE_ORDER if service in grouped]
    extra = [service for service in grouped if service not in SERVICE_ORDER]
    return known + extra


def build_workbench(config: AppConfig, sessions: SessionStore, history: MemoryHistoryStore) -> gr.Blocks:
    """Build the Gradio Workbench that executes actions for the current session."""

    grouped = registry_overview()

    def _example(service: str, method: str) -> str:
        return json.dumps(REQUEST_EXAMPLES.get((service, method), {}), indent=2)

    def _run(
        request: gr.Request, service: str, method: str, request_json: str
    ) -> tuple[str, str, list[list[str]], list[list[str]]]:
        session = sessions.get(request.cookies.get(config.session_cookie_name))
        if session is None:
            return "UNAUTHENTICATED", "No active session. Sign in again.", [], []
        activity = activity_rows(history, session.history_id)
        producers = producer_rows(history, session.history_id)
        try:
            payload = json.loads(request_json or "{}")
        except json.JSONDecodeError as exc:
            return "INVALID_ARGUMENT", f"Request is not valid JSON: {exc}", activity, producers

        clients = CitiusClients(config, sessions.token_provider(session.id))
        registry = build_registry(clients)
        action = registry.get(service, method)
        if action.availability is not Availability.AVAILABLE:
            return (
                action.availability.value.upper(),
                _AVAILABILITY_BADGE[action.availability],
                activity,
                producers,
            )

        executor = ActionExecutor(history)
        context = ExecutionContext(
            session_id=session.history_id,
            subject=session.subject,
            endpoint=config.citius_endpoint,
        )

        async def _execute() -> tuple[str, str]:
            try:
                result, _ = await executor.execute(action, context, payload)
                return result.status.value, json.dumps(
                    {"message": result.message, "response": result.response}, indent=2
                )
            finally:
                await clients.close()

        status, response = asyncio.run(_execute())
        return (
            status,
            response,
            activity_rows(history, session.history_id),
            producer_rows(history, session.history_id),
        )

    with gr.Blocks(
        title="Citius API Workbench",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><hr><h1>Citius API Workbench</h1>"
            "<p>Explore the gRPC API by service and connect individual calls "
            "into governed cryptographic workflows.</p><hr></div>",
            padding=False,
        )

        identity_banner = gr.Markdown("Loading identity…", elem_classes="identity-note")

        gr.HTML(
            "<div class='section-title'><h2>Service capability overview</h2></div>",
            padding=False,
        )
        for service in _ordered_services(grouped):
            label = SERVICE_LABELS.get(service, service)
            with gr.Accordion(f"{label} · {service}", open=(service == "CryptoService")):
                badges = "\n".join(
                    f"- `{method}` — {_AVAILABILITY_BADGE[availability]}" for method, availability in grouped[service]
                )
                gr.Markdown(badges)

        gr.HTML(
            "<div class='section-title'><h2>Execute an RPC</h2></div>",
            padding=False,
        )
        gr.Markdown(
            "Select a service and RPC, edit its protobuf-shaped JSON request, and "
            "execute it. Every call runs through the shared executor and is recorded "
            "in this session's history. Unimplemented server RPCs are shown honestly."
        )

        service_names = _ordered_services(grouped)
        with gr.Row():
            service_dd = gr.Dropdown(service_names, label="Service", value=service_names[0])
            method_dd = gr.Dropdown(
                [m for m, _ in grouped[service_names[0]]],
                label="RPC",
                value=grouped[service_names[0]][0][0],
            )
        with gr.Row(equal_height=False):
            with gr.Column(scale=1):
                request_box = gr.Code(
                    value=_example(service_names[0], grouped[service_names[0]][0][0]),
                    language="json",
                    label="Request (JSON)",
                )
                run_btn = gr.Button("Execute", variant="primary")
            with gr.Column(scale=1):
                status_box = gr.Textbox(label="Status", interactive=False)
                response_box = gr.Code(language="json", label="Response", interactive=False)

        gr.HTML(
            "<div class='section-title'><h2>Previous producer responses</h2></div>",
            padding=False,
        )
        gr.Markdown(
            "Successful Sign, DigestSign, and Encrypt responses appear here with a "
            "copyable value-plus-metadata bundle. Reuse the newest one to prefill "
            "Verify or Decrypt, replaying its recorded key version."
        )
        producer_table = gr.Dataframe(
            headers=PRODUCER_HEADERS,
            col_count=(len(PRODUCER_HEADERS), "fixed"),
            interactive=False,
            wrap=True,
            label="Producer responses",
        )
        reuse_btn = gr.Button("Reuse latest producer response ↴")

        gr.HTML(
            "<div class='section-title'><h2>Session activity</h2></div>",
            padding=False,
        )
        activity_table = gr.Dataframe(
            headers=ACTIVITY_HEADERS,
            col_count=(len(ACTIVITY_HEADERS), "fixed"),
            interactive=False,
            wrap=True,
            label="Session activity",
        )

        def _identity(request: gr.Request) -> str:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return "**No active session.** Sign in again to execute RPCs."
            view = session.public_view()
            return (
                f"**Signed in as {view['display_name']}** (`{view['subject']}`) · "
                f"endpoint `{view['endpoint']}` · "
                f"{'authenticated' if view['authenticated'] else 'no token supplied'}"
            )

        def _on_service(service: str) -> tuple[Any, str]:
            method_choices = [m for m, _ in grouped[service]]
            first = method_choices[0]
            return gr.update(choices=method_choices, value=first), _example(service, first)

        def _on_method(service: str, method: str) -> str:
            return _example(service, method)

        def _load_activity(request: gr.Request) -> tuple[list[list[str]], list[list[str]]]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return [], []
            return (
                activity_rows(history, session.history_id),
                producer_rows(history, session.history_id),
            )

        def _reuse(request: gr.Request) -> tuple[Any, Any, str]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return gr.update(), gr.update(), "{}"
            handoff = latest_consumer_handoff(history, session.history_id)
            if handoff is None:
                return gr.update(), gr.update(), "{}"
            service, method, request_json = handoff
            return (
                gr.update(value=service),
                gr.update(choices=[m for m, _ in grouped[service]], value=method),
                request_json,
            )

        blocks.load(_identity, outputs=identity_banner)
        blocks.load(_load_activity, outputs=[activity_table, producer_table])
        service_dd.change(_on_service, inputs=service_dd, outputs=[method_dd, request_box])
        method_dd.change(_on_method, inputs=[service_dd, method_dd], outputs=request_box)
        run_btn.click(
            _run,
            inputs=[service_dd, method_dd, request_box],
            outputs=[status_box, response_box, activity_table, producer_table],
        )
        reuse_btn.click(_reuse, outputs=[service_dd, method_dd, request_box])

    return blocks
