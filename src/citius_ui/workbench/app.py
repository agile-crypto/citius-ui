"""Service-organized Gradio Workbench wired to the SDK-backed actions.

Services are light parent accordions; each implemented RPC is a nested child
accordion with per-field forms aligned to api/proto, clickable examples, an
inline output panel, and, for producer RPCs, an inline history table with a
real per-RPC "Clear history" (removes those records from the session's
history store, not just the display) and a copyable JSON bundle of the latest
response. Consumer RPCs (Verify, Decrypt, DigestVerify) accept that bundle
pasted back in and fill their fields from it. Every execution funnels through
the shared ActionExecutor so results are redacted and recorded in the
session's history. Contract-only RPCs are listed honestly as unavailable.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
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

# Producer method -> the consumer RPC its "Latest response bundle" pastes
# into. Sign and DigestSign both produce a Signature artifact but populate
# different bundle fields (message vs. digest), so this is keyed by method
# rather than by the coarser artifact kind.
_CONSUMER_HINT = {
    "Sign": "Verify",
    "DigestSign": "DigestVerify",
    "Encrypt": "Decrypt",
}

# Light values live on :root and dark overrides on `:root .dark`, mirroring how
# Gradio scopes its own theme variables, so both flip together whether the mode
# comes from the OS preference or a forced ?__theme= query parameter.
CSS = """
:root {
  --citius-ink: #2f3d6b; --citius-ink-soft: #56628c; --citius-accent: #8aa0e0;
  --citius-banner-start: #dbe4fb; --citius-banner-end: #eef2fb;
  --citius-header-bg: #dbe4fb; --citius-header-ink: #2f3d6b;
  --citius-surface: #fbfcff; --citius-surface-open: #f2f5fe; --citius-rpc-ink: #46527f;
  --citius-border: #e6ebf7; --citius-border-idle: #d6ddf0; --citius-ring: #e0e7f8;
  --citius-note-bg: #f4faf4; --citius-note-border: #7aa37a; --citius-note-ink: #37533a;
  --citius-shadow: rgba(120, 140, 200, .18); --citius-shadow-soft: rgba(120, 140, 200, .16);
}
:root .dark {
  --citius-ink: #cdd7f5; --citius-ink-soft: #93a1cc;
  --citius-banner-start: #252e4d; --citius-banner-end: #1a2138;
  --citius-header-bg: #27334f; --citius-header-ink: #cdd7f5;
  --citius-surface: #1b2234; --citius-surface-open: #222c48; --citius-rpc-ink: #aab8e0;
  --citius-border: #2e3a5c; --citius-border-idle: #3a4666; --citius-ring: #34406a;
  --citius-note-bg: #17251b; --citius-note-border: #5d8c62; --citius-note-ink: #a9c9ac;
  --citius-shadow: rgba(0, 0, 0, .35); --citius-shadow-soft: rgba(0, 0, 0, .30);
}
.title-container { text-align: center; margin: 8px 0 18px; padding: 26px;
                   background: linear-gradient(135deg, var(--citius-banner-start), var(--citius-banner-end));
                   border-radius: 14px; box-shadow: 0 4px 16px var(--citius-shadow); }
.title-container h1 { color: var(--citius-ink); font-size: 2.1rem; margin: 0 0 8px; }
.title-container p { color: var(--citius-ink-soft); margin: 0; }
.identity-note { border-left: 4px solid var(--citius-note-border); background: var(--citius-note-bg);
                 padding: 10px 14px; border-radius: 0 8px 8px 0; color: var(--citius-note-ink); }
.service-accordion { border: 0 !important; margin: 8px 0 !important; }
.service-accordion > button, .service-accordion > .label-wrap {
    background: var(--citius-header-bg) !important; color: var(--citius-header-ink) !important;
    font-size: 1.05rem !important; font-weight: 700 !important;
    border-radius: 10px !important; padding: 12px 16px !important;
    box-shadow: 0 2px 8px var(--citius-shadow-soft) !important; }
.service-accordion > button span, .service-accordion > .label-wrap span {
    color: var(--citius-header-ink) !important; }
.service-body { gap: 6px !important; padding: 6px 4px 2px !important; }
.workbench-column { gap: 8px !important; }
.rpc-accordion { margin: 5px 0 !important;
                 border: 1px solid var(--citius-border) !important;
                 border-left: 4px solid var(--citius-border-idle) !important;
                 border-radius: 8px !important; background: var(--citius-surface) !important; }
.rpc-accordion > button, .rpc-accordion > .label-wrap {
    font-weight: 600 !important; color: var(--citius-rpc-ink) !important; padding: 9px 13px !important; }
.rpc-accordion.rpc-open { border-left: 4px solid var(--citius-accent) !important;
                          background: var(--citius-surface-open) !important;
                          box-shadow: inset 0 0 0 1px var(--citius-ring) !important; }
.logout-button { max-width: 140px; align-self: flex-end; }
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


def _render_response(
    status: str,
    message: str = "",
    *,
    response: dict[str, Any] | None = None,
    denial_reason: str | None = None,
) -> str:
    """Render the response panel JSON with any server error kept visible."""
    body: dict[str, Any] = {"status": status}
    if message:
        body["message" if status == "OK" else "error"] = message
    if denial_reason:
        body["denial_reason"] = denial_reason
    body["response"] = response or {}
    return json.dumps(body, indent=2)


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


def build_workbench(
    config: AppConfig,
    sessions: SessionStore,
    history: MemoryHistoryStore,
    *,
    token_provider_factory: Callable[[str], Callable[[], Awaitable[str]]] | None = None,
) -> gr.Blocks:
    """Build the Gradio Workbench that executes actions for the current session.

    ``token_provider_factory`` maps a session id to the async token provider used
    for that session's RPCs. It defaults to the store's plain provider; the host
    injects a refreshing provider when OIDC refresh is configured.
    """

    grouped = registry_overview()
    make_provider = token_provider_factory or sessions.token_provider

    def _run_form(
        spec: RpcFormSpec,
    ) -> Any:
        async def _handler(request: gr.Request, *values: object) -> tuple[str, str, Any, Any]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return (
                    "UNAUTHENTICATED",
                    _render_response("UNAUTHENTICATED", "No active session. Sign in again."),
                    gr.update(),
                    gr.update(),
                )
            try:
                payload = build_request(spec, list(values))
            except ValueError as exc:
                return (
                    "INVALID_ARGUMENT",
                    _render_response("INVALID_ARGUMENT", str(exc)),
                    gr.update(),
                    gr.update(),
                )

            try:
                clients = CitiusClients(config, make_provider(session.id))
            except Exception as exc:  # noqa: BLE001 - misconfigured endpoint/TLS must render, not crash
                return (
                    "UNAVAILABLE",
                    _render_response("UNAVAILABLE", f"could not create a Citius client: {exc}"),
                    gr.update(),
                    gr.update(),
                )
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
                response = _render_response(
                    status,
                    result.message,
                    response=result.response,
                    denial_reason=result.denial_reason,
                )
            finally:
                try:
                    await clients.close()
                except Exception:  # noqa: BLE001 - closing must never mask the result
                    pass

            if spec.produces:
                rows = _producer_rows(session.history_id, spec.method)
                # rows are newest-first (see MemoryHistoryStore.list), so the
                # first row is this response's bundle when the call succeeded.
                latest_bundle = rows[0][3] if rows else ""
                return status, response, rows, latest_bundle
            return status, response, gr.update(), gr.update()

        return _handler

    def _clear_producer_history(method: str) -> Callable[[gr.Request], Awaitable[tuple[list[list[str]], str]]]:
        async def _handler(request: gr.Request) -> tuple[list[list[str]], str]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is not None:
                history.remove_method(session.history_id, method)
            return [], ""

        return _handler

    def _fill_from_bundle(spec: RpcFormSpec) -> Callable[[str], tuple[Any, ...]]:
        """Parse a pasted producer bundle and fill the matching request fields.

        Fields whose key isn't present in the bundle are left untouched
        (gr.update() is a no-op), so pasting a bundle from an incompatible
        producer still fills whatever fields do match instead of failing
        outright or blanking unrelated fields (e.g. scope_params).
        """

        def _handler(bundle_text: str) -> tuple[Any, ...]:
            no_op = tuple(gr.update() for _ in spec.fields)
            text = (bundle_text or "").strip()
            if not text:
                return (*no_op, "Paste a bundle JSON first.")
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                return (*no_op, f"Not valid JSON: {exc}")
            if not isinstance(parsed, dict):
                return (*no_op, "Bundle must be a JSON object.")

            values: list[Any] = []
            filled = 0
            for field in spec.fields:
                if field.key not in parsed:
                    values.append(gr.update())
                    continue
                raw = parsed[field.key]
                if field.key == "metadata" and not isinstance(raw, str):
                    raw = json.dumps(raw)
                values.append(raw)
                filled += 1
            note = f"Filled {filled} field(s) from the bundle." if filled else "Bundle had no fields matching this RPC."
            return (*values, note)

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

            if spec.consumes:
                with gr.Accordion(f"Paste a {spec.consumes} bundle", open=False, elem_classes=["rpc-accordion"]):
                    gr.Markdown(
                        f"Copy a {spec.consumes} bundle from the **Latest response bundle** box of the "
                        "producing RPC — typically in another browser signed in as a different identity, "
                        "as in the multi-browser demo runbooks. Only the bundle crosses browsers, never a "
                        "token. Paste it here, then fill the fields above."
                    )
                    paste_box = gr.Textbox(
                        label=f"{spec.consumes} bundle (JSON)",
                        lines=3,
                        max_lines=10,
                        placeholder='{"key_name": "...", ...}',
                    )
                    fill_button = gr.Button("Fill fields from bundle", variant="secondary")
                    fill_note = gr.Markdown()
                fill_button.click(_fill_from_bundle(spec), inputs=[paste_box], outputs=[*inputs, fill_note])

            with gr.Row():
                run = gr.Button(spec.action_label, variant="primary")
                clear = gr.Button("Clear", variant="secondary")
            with gr.Accordion("Output", open=True, visible=False) as output_row:
                status_box = gr.Textbox(label="Status", interactive=False)
                response_box = gr.Code(language="json", label="Response", interactive=False)
                history_table = None
                latest_bundle = None
                if spec.produces:
                    latest_bundle = gr.Textbox(
                        label=(
                            f"Latest response bundle — copy into {_CONSUMER_HINT.get(spec.method, 'a compatible RPC')} "
                            "(often in another browser)"
                        ),
                        interactive=False,
                        show_copy_button=True,
                        lines=3,
                        max_lines=10,
                    )
                    history_table = gr.Dataframe(
                        headers=["Time", "Key name", "Key version", "Bundle"],
                        col_count=(4, "fixed"),
                        label=f"Previous {spec.method} responses",
                        interactive=False,
                        wrap=True,
                    )
                    clear_history = gr.Button("Clear history", variant="secondary", size="sm")
            if spec.examples:
                with gr.Accordion("Examples", open=True):
                    gr.Examples(examples=[list(example) for example in spec.examples], inputs=inputs)

            outputs = [
                status_box,
                response_box,
                history_table if history_table is not None else status_box,
                latest_bundle if latest_bundle is not None else status_box,
            ]
            run.click(lambda: gr.update(visible=True), outputs=output_row)
            run.click(_run_form(spec), inputs=[*inputs], outputs=outputs)

            clear_targets = [*inputs, status_box, response_box]
            clear.click(lambda targets=clear_targets: [None for _ in targets], outputs=clear_targets)

            if history_table is not None and latest_bundle is not None:
                clear_history.click(
                    _clear_producer_history(spec.method),
                    outputs=[history_table, latest_bundle],
                )

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
        with gr.Row():
            with gr.Accordion("View granted permissions", open=False, elem_classes=["rpc-accordion"]):
                permissions_view = gr.Markdown("Sign in to see effective permissions.")
        gr.Button("Log out", link="/logout", variant="secondary", elem_classes=["logout-button"])

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

        def _identity(request: gr.Request) -> tuple[str, str]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return (
                    "**No active session.** Sign in again to execute RPCs.",
                    "Sign in to see effective permissions.",
                )
            banner = (
                f"**Signed in as {session.display_name}** (`{session.subject}`) · "
                f"endpoint `{session.endpoint}` · "
                f"{'authenticated' if session.access_token else 'no token supplied'}"
            )
            permissions = sorted(session.permissions)
            key_allow = session.key_allow
            key_deny = session.key_deny
            lines = ["**Method permissions**", ""]
            if permissions:
                lines += [f"- `{perm}`" for perm in permissions]
            else:
                lines.append("- (none granted to this identity)")
            lines.append("")
            allow_text = ", ".join(f"`{pattern}`" for pattern in key_allow) or "(none)"
            deny_text = ", ".join(f"`{pattern}`" for pattern in key_deny) or "(none)"
            lines.append(f"**Resource access** · allow: {allow_text} · deny: {deny_text}")
            return banner, "\n".join(lines)

        blocks.load(_identity, outputs=[identity_banner, permissions_view])

    return blocks
