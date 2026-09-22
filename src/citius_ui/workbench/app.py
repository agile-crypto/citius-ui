"""Service-organized Gradio Workbench wired to the SDK-backed actions.

Services render as flat cards in a responsive grid (no nested accordions): a
single accordion per service holds a method dropdown, the selected method's
fields, and Execute/Clear, with per-field forms aligned to api/proto,
clickable examples, an inline output panel, and, for producer RPCs, an inline
history table with a real per-RPC "Clear history" (removes those records from
the session's history store, not just the display) and a copyable JSON bundle
of the latest response. Consumer RPCs (Verify, Decrypt, DigestVerify) accept
that bundle pasted back in and fill their fields from it. Every execution
funnels through the shared ActionExecutor so results are redacted and
recorded in the session's history. Services with no implemented RPCs render
as a muted, still-expandable card listing their contract methods honestly as
unavailable.
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

# Service -> accent class, for the services with at least one implemented RPC
# (the rest render as an unaccented, muted card).
_ACCENT_BY_SERVICE: dict[str, str] = {
    "CryptoPolicyService": "accent-purple",
    "KeyManagementService": "accent-teal",
    "CryptoService": "accent-coral",
}

_SPAN_TWO_LABEL = "⇔ Span two columns"
_SPAN_ONE_LABEL = "⇔ Single column"

_TOGGLE_THEME_JS = "() => { document.body.classList.toggle('dark'); }"


def _span_toggle_js(button_elem_id: str) -> str:
    """Client-side toggle: flip one card between one and two grid columns.

    Pure DOM manipulation (no server round-trip) -- grid-column is a normal
    CSS Grid property, so this plays correctly with the auto-fit column-count
    math instead of fighting it the way a free-drag pixel-width resize handle
    would.
    """
    return f"""() => {{
  const btn = document.getElementById('{button_elem_id}');
  const card = btn.closest('.svc-card');
  card.classList.toggle('span-2');
  btn.textContent = card.classList.contains('span-2') ? '{_SPAN_ONE_LABEL}' : '{_SPAN_TWO_LABEL}';
}}"""


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
  --citius-zone-bg: #e3e9f8; --citius-zone-border: #e2e4ea; --citius-field-bg: #ffffff;
  --citius-muted-bg: #f0f1f4; --citius-muted-ink: #9599a6;
  --citius-accent-purple: #7f77dd; --citius-accent-teal: #1d9e75; --citius-accent-coral: #d85a30;
}
:root .dark {
  --citius-ink: #cdd7f5; --citius-ink-soft: #93a1cc;
  --citius-banner-start: #252e4d; --citius-banner-end: #1a2138;
  --citius-header-bg: #27334f; --citius-header-ink: #cdd7f5;
  --citius-surface: #1b2234; --citius-surface-open: #222c48; --citius-rpc-ink: #aab8e0;
  --citius-border: #2e3a5c; --citius-border-idle: #3a4666; --citius-ring: #34406a;
  --citius-note-bg: #17251b; --citius-note-border: #5d8c62; --citius-note-ink: #a9c9ac;
  --citius-shadow: rgba(0, 0, 0, .35); --citius-shadow-soft: rgba(0, 0, 0, .30);
  --citius-zone-bg: #12162a; --citius-zone-border: #2a2e3a; --citius-field-bg: #262b38;
  --citius-muted-bg: #181c2c; --citius-muted-ink: #666c7d;
  --citius-accent-purple: #9a92e8; --citius-accent-teal: #3fceA0; --citius-accent-coral: #ef8a63;
}
.title-container { text-align: center; margin: 8px 0 18px; padding: 26px;
                   background: linear-gradient(135deg, var(--citius-banner-start), var(--citius-banner-end));
                   border-radius: 14px; box-shadow: 0 4px 16px var(--citius-shadow); height: 100%; }
.title-container h1 { color: var(--citius-ink); font-size: 2.1rem; margin: 0 0 8px; }
.title-container p { color: var(--citius-ink-soft); margin: 0; }
/* The theme toggle floats out of the normal flow in the top-right corner so
   it never competes with the title bar. elem_classes land on Gradio's outer
   .block wrapper, so fixed-position that and style the inner <button>. */
.theme-toggle { position: fixed !important; top: 12px !important; right: 14px !important; z-index: 1000 !important;
                width: 40px !important; min-width: 40px !important; max-width: 40px !important;
                margin: 0 !important; padding: 0 !important; }
.theme-toggle button {
    border-radius: 999px !important; width: 40px !important; min-width: 40px !important; height: 40px !important;
    padding: 0 !important; background: var(--citius-surface) !important; color: var(--citius-ink) !important;
    border: 1px solid var(--citius-border) !important; box-shadow: 0 2px 8px var(--citius-shadow) !important;
    font-size: 1.1rem !important; line-height: 1 !important; cursor: pointer !important; }
.theme-toggle button:hover { border-color: var(--citius-accent) !important; }
.identity-note { border-left: 4px solid var(--citius-note-border); background: var(--citius-note-bg);
                 padding: 10px 14px; border-radius: 0 8px 8px 0; color: var(--citius-note-ink); }
.service-body { gap: 6px !important; padding: 6px 4px 2px !important; }
.rpc-accordion { margin: 5px 0 !important;
                 border: 1px solid var(--citius-border) !important;
                 border-left: 4px solid var(--citius-border-idle) !important;
                 border-radius: 8px !important; background: var(--citius-surface) !important; }
.rpc-accordion > button, .rpc-accordion > .label-wrap {
    font-weight: 600 !important; color: var(--citius-rpc-ink) !important; padding: 9px 13px !important; }
.logout-button { max-width: 140px; align-self: flex-end; }

/* Method, Request, Examples, and Output each sit in their own bordered,
   tinted zone so the four read as clearly separate regions within a service
   card. gr.Column carries a "column" class (not "block"), so .method-zone/
   .request-zone alone are specific enough and never compete with the
   ".svc-card .block" background-stripping rule below; gr.Accordion
   (.examples-zone/.output-zone) IS a "block", so that rule needs the
   compound ".block.examples-zone" / ".block.output-zone" selector to win
   instead. */
.svc-card .method-zone, .svc-card .request-zone {
    border: 0.5px solid var(--citius-zone-border) !important; border-radius: 10px !important;
    background: var(--citius-zone-bg) !important; padding: 10px 12px !important; margin: 2px 0 8px !important; }
.svc-card .block.examples-zone, .svc-card .block.output-zone {
    border: 0.5px solid var(--citius-zone-border) !important; border-radius: 10px !important;
    background: var(--citius-zone-bg) !important; margin: 2px 0 8px !important; box-shadow: none !important; }
.svc-card .examples-zone > button, .svc-card .examples-zone > .label-wrap,
.svc-card .output-zone > button, .svc-card .output-zone > .label-wrap {
    background: transparent !important; color: var(--citius-ink-soft) !important; box-shadow: none !important; }

/* Gradio wraps every field in its own bordered/backgrounded ".block", and
   groups consecutive fields into a backgrounded ".form" container. Strip both
   inside a service card so labels sit directly on the zone/card background;
   the input/textarea/select elements below keep their own field background. */
.svc-card .block, .svc-card .form {
    background: transparent !important; border: none !important; box-shadow: none !important; }

/* The "Paste a bundle" accordion is a .block too, so the strip rule above
   would otherwise flatten it -- restore its usual surface/border look so it
   still reads as a distinct nested section, matching non-card instances of
   the same class ("View granted permissions", the runbooks list). */
.svc-card .block.rpc-accordion {
    border: 1px solid var(--citius-border) !important;
    border-left: 4px solid var(--citius-border-idle) !important;
    background: var(--citius-surface) !important; }

/* Dropdown nests its listbox input inside two ".wrap" divs: an outer one
   (".wrap.default.full") that Gradio gives its own default gray background,
   and an inner one around the actual input. Both get the plain field
   background with no border of their own -- the field only needs to read as
   a lighter cutout against the zone's background, not another bordered box
   stacked inside the zone's own border. */
.svc-card .wrap.default.full, .svc-card .wrap:has(input[role="listbox"]) {
    background: var(--citius-field-bg) !important; border: none !important; }

.workbench-grid input, .workbench-grid textarea, .workbench-grid select {
    background: var(--citius-field-bg) !important; border: none !important; }

/* Checkboxes must be excluded from the generic input rule above: giving them
   the field background makes them invisible (white-on-white in light mode)
   and "border: none" removes their box. Restore a real, clickable control
   with an accent tick, and make sure nothing overlays it. */
.workbench-grid input[type="checkbox"] {
    -webkit-appearance: checkbox !important; appearance: checkbox !important;
    width: 18px !important; height: 18px !important; min-width: 18px !important;
    accent-color: var(--citius-accent-purple) !important;
    background: var(--citius-field-bg) !important;
    border: 1px solid var(--citius-border-idle) !important; border-radius: 4px !important;
    cursor: pointer !important; pointer-events: auto !important; opacity: 1 !important;
    position: static !important; margin: 0 8px 0 0 !important; }
.workbench-grid label:has(> input[type="checkbox"]),
.workbench-grid .checkbox-container { cursor: pointer !important; pointer-events: auto !important; }


/* The Response code block's syntax highlighting is a fixed dark theme
   (unrelated to the page's own light/dark toggle), so its token colors are
   only readable against a dark background. Force that background rather
   than the page theme's, so the two can never end up light-on-light. */
.output-zone .cm-editor { background: #1e1e1e !important; border-radius: 6px !important; }

/* Services render as flat cards in a responsive grid capped at two columns
   (auto-fit picks 1 vs 2 tracks from the viewport; a card can opt into
   spanning both via the "Span" toggle below its method dropdown). */
.workbench-grid { display: grid !important; align-items: start !important;
    grid-template-columns: repeat(auto-fit, minmax(max(280px, calc(50% - 7px)), 1fr)) !important;
    gap: 14px !important; }
.workbench-grid > .form { min-width: 0 !important; }
.svc-card.span-2 { grid-column: 1 / -1 !important; }
.span-toggle-btn { font-size: .78rem !important; padding: 3px 12px !important; border-radius: 999px !important;
    background: transparent !important; border: 1px solid var(--citius-border) !important;
    color: var(--citius-ink-soft) !important; width: fit-content !important; min-width: 0 !important;
    margin: 0 0 8px !important; box-shadow: none !important; }

.svc-card { border-radius: 12px !important; border: 1px solid var(--citius-border) !important;
    box-shadow: 0 2px 8px var(--citius-shadow-soft) !important; background: var(--citius-surface) !important;
    border-left-width: 3px !important; border-left-style: solid !important;
    border-left-color: var(--citius-border-idle) !important; padding: 0 !important; margin: 0 !important; }
.svc-card > button, .svc-card > .label-wrap {
    background: var(--citius-header-bg) !important; color: var(--citius-header-ink) !important;
    font-size: 1.05rem !important; font-weight: 700 !important; letter-spacing: .15px !important;
    border-radius: 12px 12px 0 0 !important; box-shadow: none !important; padding: 10px 14px !important; }
.svc-card > button span, .svc-card > .label-wrap span { color: var(--citius-header-ink) !important; }
.svc-card > div:last-child { padding: 8px 14px 12px !important; }
.accent-purple { border-left-color: var(--citius-accent-purple) !important; }
.accent-teal { border-left-color: var(--citius-accent-teal) !important; }
.accent-coral { border-left-color: var(--citius-accent-coral) !important; }

/* Muted variant is still a real .svc-card accordion (expandable to show its
   contract RPCs), just recolored so it reads as "not yet available" rather
   than a runnable service. */
.svc-card.svc-muted { background: var(--citius-muted-bg) !important; border-left-color: transparent !important; }
.svc-card.svc-muted > button, .svc-card.svc-muted > .label-wrap {
    background: var(--citius-muted-bg) !important; color: var(--citius-muted-ink) !important;
    font-weight: 600 !important; }
.svc-card.svc-muted .prose, .svc-card.svc-muted li {
    color: var(--citius-muted-ink) !important; font-size: .85rem !important; }
.svc-card.svc-muted > div:last-child { padding: 2px 14px 12px !important; }

/* The rest of a partially-implemented service's contract methods, nested
   inside its card. Deliberately quieter than the card itself (no border/
   shadow, smaller text) so it reads as a footnote, not another card. */
.pending-methods { border: none !important; background: transparent !important; box-shadow: none !important;
    margin-top: 4px !important; }
.pending-methods > button, .pending-methods > .label-wrap {
    background: transparent !important; color: var(--citius-ink-soft) !important;
    font-size: .8rem !important; font-weight: 400 !important; padding: 4px 0 !important; box-shadow: none !important; }
.pending-methods .prose, .pending-methods li { color: var(--citius-ink-soft) !important; font-size: .8rem !important; }

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
    # Only append "(optional)" when the label does not already convey it, and
    # never for checkboxes (an unchecked box already reads as "not set").
    label = spec.label
    if spec.optional and spec.kind != "bool" and "optional" not in spec.label.lower():
        label = f"{spec.label} (optional)"
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
        async def _handler(request: gr.Request, *values: object) -> tuple[Any, ...]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return (
                    "UNAUTHENTICATED",
                    _render_response("UNAUTHENTICATED", "No active session. Sign in again."),
                    gr.update(),
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
                labels, mapping, latest = _producer_history(session.history_id, spec.method)
                # Select the newest entry and show its copyable bundle.
                selected = labels[0] if labels else None
                return (
                    status,
                    response,
                    gr.update(choices=labels, value=selected),
                    mapping,
                    latest,
                )
            return status, response, gr.update(), gr.update(), gr.update()

        return _handler

    def _clear_producer_history(method: str) -> Callable[[gr.Request], Awaitable[tuple[Any, dict[str, str], str]]]:
        async def _handler(request: gr.Request) -> tuple[Any, dict[str, str], str]:
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is not None:
                history.remove_method(session.history_id, method)
            return gr.update(choices=[], value=None), {}, ""

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

    def _producer_history(history_id: str, method: str) -> tuple[list[str], dict[str, str], str]:
        """Return (dropdown labels, label->bundle map, latest bundle) for a producer.

        Records are newest-first (see MemoryHistoryStore.list). Each produced
        artifact becomes one selectable entry whose bundle JSON can be copied
        and pasted straight into the consumer RPC.
        """
        labels: list[str] = []
        mapping: dict[str, str] = {}
        for record in history.list(history_id):
            if record.method != method:
                continue
            for artifact in record.artifacts:
                version = "" if artifact.key_version is None else f" · v{artifact.key_version}"
                label = f"{record.timestamp.strftime('%H:%M:%S')} · {artifact.key_name}{version}"
                # Disambiguate identical labels (same second/key/version).
                if label in mapping:
                    label = f"{label} ({len(mapping)})"
                mapping[label] = json.dumps(artifact.bundle(), indent=2)
                labels.append(label)
        latest = mapping[labels[0]] if labels else ""
        return labels, mapping, latest

    def _render_rpc_body(spec: RpcFormSpec, *, visible: bool) -> gr.Column:
        """Render one method's fields, actions, and output, toggled by the method dropdown."""
        with gr.Column(visible=visible) as body:
            # Core fields render up front; optional filter groups are collapsed
            # into on-demand sections so the form is not overloaded. The flat
            # ``inputs`` list stays in ``spec.fields`` order for build_request,
            # examples, run/clear/fill wiring regardless of render order.
            components: dict[str, gr.components.Component] = {}
            with gr.Column(elem_classes=["request-zone"]):
                for field in spec.core_fields():
                    components[field.key] = _render_input(field)
                for group_name, group_fields in spec.grouped_fields():
                    with gr.Accordion(group_name, open=False, elem_classes=["rpc-accordion", "filter-group"]):
                        group_inputs = [_render_input(field) for field in group_fields]
                        for field, component in zip(group_fields, group_inputs, strict=True):
                            components[field.key] = component
                        clear_group = gr.Button("Clear this section", variant="secondary", size="sm")
                        clear_group.click(
                            lambda inputs=group_inputs: [None for _ in inputs],
                            outputs=group_inputs,
                        )
            inputs = [components[field.key] for field in spec.fields]

            if spec.consumes:
                with gr.Accordion(f"Paste a {spec.consumes} bundle", open=True, elem_classes=["rpc-accordion"]):
                    gr.Markdown(
                        f"Paste a {spec.consumes} bundle copied from the producing RPC's **Response history** "
                        "(here or in another browser signed in as a different identity, as in the multi-browser "
                        "demo runbooks). Only the bundle crosses browsers, never a token. Filling from the bundle "
                        "populates the value and metadata for you; the manual fields below are for advanced use."
                    )
                    paste_box = gr.Textbox(
                        label=f"{spec.consumes} bundle (JSON)",
                        lines=4,
                        max_lines=12,
                        placeholder='{"key_name": "...", ...}',
                    )
                    fill_button = gr.Button("Fill fields from bundle", variant="primary")
                    fill_note = gr.Markdown()
                fill_button.click(_fill_from_bundle(spec), inputs=[paste_box], outputs=[*inputs, fill_note])

            with gr.Row():
                run = gr.Button(spec.action_label, variant="primary")
                clear = gr.Button("Clear", variant="secondary")
            with gr.Accordion("Output", open=True, visible=False, elem_classes=["output-zone"]) as output_row:
                status_box = gr.Textbox(label="Status", interactive=False)
                # The full response always exists: the complete server reply.
                response_box = gr.Code(language="json", label="Full response", interactive=False)
                history_select = None
                bundle_state = None
                bundle_box = None
                if spec.produces:
                    consumer = _CONSUMER_HINT.get(spec.method, "a compatible RPC")
                    gr.Markdown(
                        f"**Response history** — pick any past {spec.method} response, then copy its bundle "
                        f"(key name, version, and value + metadata) and paste it into **{consumer}**."
                    )
                    # label -> bundle JSON, so selecting an entry shows its bundle.
                    bundle_state = gr.State({})
                    history_select = gr.Dropdown(
                        label="Response history (newest first)",
                        choices=[],
                        interactive=True,
                    )
                    # Editable + copy button so the bundle is mouse-selectable and
                    # copyable, unlike the old read-only dataframe cell.
                    bundle_box = gr.Textbox(
                        label=f"Bundle — copy and paste into {consumer}",
                        interactive=True,
                        show_copy_button=True,
                        lines=6,
                        max_lines=20,
                        placeholder="Run this RPC to produce a bundle, or select an entry above.",
                    )
                    clear_history = gr.Button("Clear history", variant="secondary", size="sm")

                    def _show_selected(label: str | None, mapping: dict[str, str]) -> str:
                        return mapping.get(label, "") if label else ""

                    history_select.change(_show_selected, inputs=[history_select, bundle_state], outputs=bundle_box)
            if spec.examples:
                with gr.Accordion("Examples", open=True, elem_classes=["examples-zone"]):
                    gr.Examples(examples=[list(example) for example in spec.examples], inputs=inputs)

            if spec.produces and history_select is not None:
                outputs = [status_box, response_box, history_select, bundle_state, bundle_box]
            else:
                outputs = [status_box, response_box, status_box, status_box, status_box]
            run.click(lambda: gr.update(visible=True), outputs=output_row)
            run.click(_run_form(spec), inputs=[*inputs], outputs=outputs)

            clear_targets = [*inputs, status_box, response_box]
            clear.click(lambda targets=clear_targets: [None for _ in targets], outputs=clear_targets)

            if spec.produces and history_select is not None:
                clear_history.click(
                    _clear_producer_history(spec.method),
                    outputs=[history_select, bundle_state, bundle_box],
                )
        return body

    def _render_service_card(service: str, *, open_by_default: bool) -> None:
        forms = _forms_for(service)
        label = SERVICE_LABELS.get(service, service)
        accent = _ACCENT_BY_SERVICE.get(service)
        card_classes = ["svc-card", accent] if accent else ["svc-card"]
        with gr.Accordion(f"{label} · {service}", open=open_by_default, elem_classes=card_classes):
            span_toggle_id = f"span-toggle-{service}"
            span_toggle = gr.Button(_SPAN_TWO_LABEL, elem_id=span_toggle_id, elem_classes=["span-toggle-btn"])
            span_toggle.click(None, js=_span_toggle_js(span_toggle_id))
            with gr.Column(elem_classes=["method-zone"]):
                method = gr.Dropdown(choices=[form.method for form in forms], value=forms[0].method, label="Method")
            bodies = [_render_rpc_body(form, visible=(index == 0)) for index, form in enumerate(forms)]
            method.change(
                lambda selected, _forms=forms: [gr.update(visible=(f.method == selected)) for f in _forms],
                inputs=method,
                outputs=bodies,
            )

            # A service can be partially implemented (e.g. Key Management has
            # CreateKey/ReadKey/TransformKey but not ListKeys/DeleteKey/...);
            # list the rest here so the full contract stays visible, not just
            # the subset with a form.
            implemented = {form.method for form in forms}
            pending = [
                (method_name, availability_state)
                for method_name, availability_state in grouped.get(service, [])
                if method_name not in implemented
            ]
            if pending:
                with gr.Accordion(
                    f"{len(pending)} more not yet available", open=False, elem_classes=["pending-methods"]
                ):
                    gr.Markdown(
                        "\n".join(f"- `{method_name}` — {_AVAILABILITY_BADGE[avail]}" for method_name, avail in pending)
                    )

    def _render_unavailable_card(service: str) -> None:
        """Render a muted, still-expandable card listing a service's contract RPCs.

        None of these methods are implemented by the server yet, but the
        contract already defines them, so they stay visible rather than
        disappearing.
        """
        label = SERVICE_LABELS.get(service, service)
        with gr.Accordion(f"{label} · {service}", open=False, elem_classes=["svc-card", "svc-muted"]):
            gr.Markdown(
                "\n".join(
                    f"- `{method}` — {_AVAILABILITY_BADGE[availability_state]}"
                    for method, availability_state in grouped.get(service, [])
                )
            )

    with gr.Blocks(
        title="Citius API Workbench",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        # The theme toggle floats in the top-right corner via CSS (position:
        # fixed) so it is always reachable without competing with the title
        # bar for horizontal space or shrinking it.
        theme_toggle = gr.Button("◐", elem_classes=["theme-toggle"])
        theme_toggle.click(None, js=_TOGGLE_THEME_JS)
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
                with gr.Column(elem_classes=["workbench-grid"]):
                    for service in _ordered_services(grouped):
                        if _forms_for(service):
                            _render_service_card(service, open_by_default=False)
                        else:
                            _render_unavailable_card(service)

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
