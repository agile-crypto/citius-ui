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

_AVAILABILITY_BADGE = {
    Availability.AVAILABLE: "🟢 Available",
    Availability.UNIMPLEMENTED: "🟡 Unimplemented by the server",
    Availability.UNAVAILABLE: "🟠 Unavailable (missing dependency)",
    Availability.FORBIDDEN: "🔴 Forbidden for this identity",
    Availability.UNKNOWN: "⚪ Unknown until probed",
}

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


def build_workbench(config: AppConfig, sessions: SessionStore, history: MemoryHistoryStore) -> gr.Blocks:
    """Build the Gradio Workbench that executes actions for the current session."""

    grouped = registry_overview()

    def _example(service: str, method: str) -> str:
        return json.dumps(REQUEST_EXAMPLES.get((service, method), {}), indent=2)

    def _run(request: gr.Request, service: str, method: str, request_json: str) -> tuple[str, str]:
        session = sessions.get(request.cookies.get(config.session_cookie_name))
        if session is None:
            return "UNAUTHENTICATED", "No active session. Sign in again."
        try:
            payload = json.loads(request_json or "{}")
        except json.JSONDecodeError as exc:
            return "INVALID_ARGUMENT", f"Request is not valid JSON: {exc}"

        clients = CitiusClients(config, sessions.token_provider(session.id))
        registry = build_registry(clients)
        action = registry.get(service, method)
        if action.availability is not Availability.AVAILABLE:
            return action.availability.value.upper(), _AVAILABILITY_BADGE[action.availability]

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

        return asyncio.run(_execute())

    with gr.Blocks(title="Citius API Workbench") as blocks:
        gr.Markdown("# Citius API Workbench")
        gr.Markdown(
            "Every RPC runs through the shared executor and is recorded in this "
            "session's history. Unimplemented server RPCs are shown honestly."
        )
        for service, methods in grouped.items():
            with gr.Accordion(service, open=(service == "CryptoService")):
                badges = "\n".join(
                    f"- `{method}` — {_AVAILABILITY_BADGE[availability]}" for method, availability in methods
                )
                gr.Markdown(badges)

        service_names = list(grouped)
        with gr.Row():
            service_dd = gr.Dropdown(service_names, label="Service", value=service_names[0])
            method_dd = gr.Dropdown(
                [m for m, _ in grouped[service_names[0]]],
                label="RPC",
                value=grouped[service_names[0]][0][0],
            )
        request_box = gr.Code(
            value=_example(service_names[0], grouped[service_names[0]][0][0]),
            language="json",
            label="Request (JSON)",
        )
        run_btn = gr.Button("Execute", variant="primary")
        status_box = gr.Textbox(label="Status", interactive=False)
        response_box = gr.Code(language="json", label="Response", interactive=False)

        def _on_service(service: str) -> tuple[Any, str]:
            method_choices = [m for m, _ in grouped[service]]
            first = method_choices[0]
            return gr.update(choices=method_choices, value=first), _example(service, first)

        def _on_method(service: str, method: str) -> str:
            return _example(service, method)

        service_dd.change(_on_service, inputs=service_dd, outputs=[method_dd, request_box])
        method_dd.change(_on_method, inputs=[service_dd, method_dd], outputs=request_box)
        run_btn.click(
            _run,
            inputs=[service_dd, method_dd, request_box],
            outputs=[status_box, response_box],
        )

    return blocks
