"""Service-organized Gradio Workbench wired to the SDK-backed actions.

Services are light parent accordions; each implemented RPC is a nested child
accordion with per-field forms aligned to api/proto, clickable examples, an
inline output panel, and, for producer RPCs, an inline history table with a
per-RPC clear. Every execution funnels through the shared ActionExecutor so
results are redacted and recorded in the session's history. Contract-only RPCs
are listed honestly as unavailable.
"""

from __future__ import annotations

import json
from typing import Any

import gradio as gr

from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import Availability
from citius_ui.auth.sessions import SessionStore
from citius_ui.config import AppConfig
from citius_ui.grpc_client.client import CitiusClients
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.showcases.runbooks import RUNBOOKS, render_markdown
from citius_ui.workbench.actions import build_registry, registry_overview
from citius_ui.workbench.forms import FORMS, FormField, RpcFormSpec, build_request

_AVAILABILITY_BADGE = {
    Availability.AVAILABLE: "Available",
    Availability.UNIMPLEMENTED: "Unimplemented by the server",
    Availability.UNAVAILABLE: "Unavailable (missing dependency)",
    Availability.FORBIDDEN: "Forbidden for this identity",
    Availability.UNKNOWN: "Unknown until probed",
}

CSS = """
:root { --citius-ink: #2f3d6b; --citius-accent: #8aa0e0; }
.title-container { text-align: center; margin: 8px 0 18px; padding: 26px;
                   background: linear-gradient(135deg, #dbe4fb, #eef2fb);
                   border-radius: 14px; box-shadow: 0 4px 16px rgba(120, 140, 200, .18); }
.title-container h1 { color: #2f3d6b; font-size: 2.1rem; margin: 0 0 8px; }
.title-container p { color: #56628c; margin: 0; }
.identity-note { border-left: 4px solid #7aa37a; background: #f4faf4; padding: 10px 14px;
                 border-radius: 0 8px 8px 0; color: #37533a; }
.service-accordion { border: 0 !important; margin: 8px 0 !important; }
.service-accordion > button, .service-accordion > .label-wrap {
    background: #dbe4fb !important; color: #2f3d6b !important;
    font-size: 1.05rem !important; font-weight: 700 !important;
    border-radius: 10px !important; padding: 12px 16px !important;
    box-shadow: 0 2px 8px rgba(120, 140, 200, .16) !important; }
.service-accordion > button span, .service-accordion > .label-wrap span { color: #2f3d6b !important; }
.service-body { gap: 6px !important; padding: 6px 4px 2px !important; }
.workbench-column { gap: 8px !important; }
.rpc-accordion { margin: 5px 0 !important;
                 border: 1px solid #e6ebf7 !important; border-left: 4px solid #d6ddf0 !important;
                 border-radius: 8px !important; background: #fbfcff !important; }
.rpc-accordion > button, .rpc-accordion > .label-wrap {
    font-weight: 600 !important; color: #46527f !important; padding: 9px 13px !important; }
.rpc-accordion.rpc-open { border-left: 4px solid var(--citius-accent) !important;
                          background: #f2f5fe !important; box-shadow: inset 0 0 0 1px #e0e7f8 !important; }
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


def _ordered_services(grouped: dict[str, list[tuple[str, Availability]]]) -> list[str]:
    known = [service for service in SERVICE_ORDER if service in grouped]
    extra = [service for service in grouped if service not in SERVICE_ORDER]
    return known + extra


def _split_columns(services: list[str]) -> tuple[list[str], list[str]]:
    """Split services into two balanced columns to reduce vertical spread."""
    midpoint = (len(services) + 1) // 2
    return services[:midpoint], services[midpoint:]


def _forms_for(service: str) -> list[RpcFormSpec]:
    return [form for form in FORMS if form.service == service]


def _render_input(spec: FormField) -> gr.components.Component:
    label = f"{spec.label} (optional)" if spec.optional else spec.label
    if spec.kind == "area":
        return gr.Textbox(label=label, placeholder=spec.placeholder, lines=6, max_lines=24)
    if spec.kind == "number":
        return gr.Number(label=label)
    if spec.kind == "bool":
        return gr.Checkbox(label=label)
    if spec.kind == "dropdown":
        value = spec.choices[0] if (spec.choices and not spec.optional) else None
        return gr.Dropdown(label=label, choices=list(spec.choices), value=value, allow_custom_value=True)
    return gr.Textbox(label=label, placeholder=spec.placeholder)


def build_workbench(config: AppConfig, sessions: SessionStore, history: MemoryHistoryStore) -> gr.Blocks:
    """Build the Gradio Workbench that executes actions for the current session."""

    grouped = registry_overview()

    def _run_form(
        spec: RpcFormSpec,
    ) -> Any:
        async def _handler(request: gr.Request, *values: object) -> tuple[str, str, Any]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return "UNAUTHENTICATED", "No active session. Sign in again.", gr.update()
            payload = build_request(spec, list(values))
            clients = CitiusClients(config, sessions.token_provider(session.id))
            registry = build_registry(clients)
            action = registry.get(spec.service, spec.method)
            executor = ActionExecutor(history)
            context = ExecutionContext(
                session_id=session.history_id,
                subject=session.subject,
                endpoint=config.citius_endpoint,
            )

            try:
                result, _ = await executor.execute(action, context, payload)
                status = result.status.value
                response = json.dumps({"message": result.message, "response": result.response}, indent=2)
            finally:
                await clients.close()

            if spec.produces:
                return status, response, _producer_rows(session.history_id, spec.method)
            return status, response, gr.update()

        return _handler

    def _producer_rows(history_id: str, method: str) -> list[list[str]]:
        rows: list[list[str]] = []
        for record in history.list(history_id):
            if record.method != method:
                continue
            for artifact in record.artifacts:
                rows.append(
                    [
                        record.timestamp.strftime("%H:%M:%S"),
                        artifact.key_name,
                        "" if artifact.key_version is None else str(artifact.key_version),
                        json.dumps(artifact.bundle(), sort_keys=True),
                    ]
                )
        return rows

    def _render_rpc(spec: RpcFormSpec) -> None:
        with gr.Accordion(spec.method, open=False, elem_classes=["rpc-accordion"]) as accordion:
            inputs = [_render_input(field) for field in spec.fields]
            with gr.Row():
                run = gr.Button(spec.action_label, variant="primary")
                clear = gr.Button("Clear", variant="secondary")
            with gr.Accordion("Output", open=True, visible=False) as output_row:
                status_box = gr.Textbox(label="Status", interactive=False)
                response_box = gr.Code(language="json", label="Response", interactive=False)
                history_table = None
                if spec.produces:
                    history_table = gr.Dataframe(
                        headers=["Time", "Key name", "Key version", "Bundle"],
                        col_count=(4, "fixed"),
                        label=f"Previous {spec.method} responses",
                        interactive=False,
                        wrap=True,
                    )
            if spec.examples:
                with gr.Accordion("Examples", open=True):
                    gr.Examples(examples=[list(example) for example in spec.examples], inputs=inputs)

            outputs = [status_box, response_box, history_table if history_table is not None else status_box]
            run.click(lambda: gr.update(visible=True), outputs=output_row)
            run.click(_run_form(spec), inputs=[*inputs], outputs=outputs)

            clear_targets = [*inputs, status_box, response_box]
            clear.click(lambda targets=clear_targets: [None for _ in targets], outputs=clear_targets)
            if history_table is not None:
                clear.click(lambda: [], outputs=history_table)

            def _mark_open() -> dict[str, object]:
                return gr.update(elem_classes=["rpc-accordion", "rpc-open"])

            def _mark_closed() -> dict[str, object]:
                return gr.update(elem_classes=["rpc-accordion"])

            accordion.expand(_mark_open, outputs=accordion)
            accordion.collapse(_mark_closed, outputs=accordion)

    with gr.Blocks(
        title="Citius API Workbench",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><h1>Citius API Workbench</h1>"
            "<p>Open a service, then open an RPC to edit its fields and run it. "
            "Every call is recorded in this session's history.</p></div>",
            padding=False,
        )
        identity_banner = gr.Markdown("Loading identity…", elem_classes="identity-note")

        availability = {(service, method): avail for service, methods in grouped.items() for method, avail in methods}

        def _resolver(service: str, method: str) -> Availability:
            return availability.get((service, method), Availability.UNKNOWN)

        with gr.Tabs():
            with gr.Tab("API Workbench"):
                with gr.Row(equal_height=False):
                    for column_services in _split_columns(_ordered_services(grouped)):
                        with gr.Column(scale=1, min_width=360, elem_classes=["workbench-column"]):
                            for service in column_services:
                                label = SERVICE_LABELS.get(service, service)
                                with gr.Accordion(
                                    f"{label} · {service}", open=False, elem_classes=["service-accordion"]
                                ):
                                    with gr.Column(elem_classes=["service-body"]):
                                        implemented = {form.method for form in _forms_for(service)}
                                        for form in _forms_for(service):
                                            _render_rpc(form)
                                        unavailable = [
                                            f"`{method}` — {_AVAILABILITY_BADGE[availability_state]}"
                                            for method, availability_state in grouped.get(service, [])
                                            if method not in implemented
                                        ]
                                        if unavailable:
                                            with gr.Accordion(
                                                "Not yet available", open=False, elem_classes=["rpc-accordion"]
                                            ):
                                                gr.Markdown("\n".join(f"- {row}" for row in unavailable))

            with gr.Tab("Demo runbooks"):
                with gr.Column(elem_classes=["service-body"]):
                    gr.Markdown(
                        "Guidance over the same Workbench RPCs. Each step names the browser "
                        "identity to use and the expected outcome; only safe bundles cross "
                        "browsers, never tokens."
                    )
                    for runbook in RUNBOOKS:
                        with gr.Accordion(runbook.title, open=False, elem_classes=["rpc-accordion"]):
                            gr.Markdown(render_markdown(runbook, _resolver))

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

        blocks.load(_identity, outputs=identity_banner)

    return blocks
