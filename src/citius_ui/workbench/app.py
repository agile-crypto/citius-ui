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

import atexit
import json
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import gradio as gr
from citius_sdk.errors import CitiusError

from citius_ui.actions.executor import ActionExecutor, ExecutionContext
from citius_ui.actions.model import Availability, RpcAction, RpcResult
from citius_ui.auth.sessions import Session, SessionStore
from citius_ui.config import AppConfig
from citius_ui.grpc_client.client import CitiusClients
from citius_ui.grpc_client.serialization import error_result
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.showcases.diagram import LEGEND, goal_card, next_step, sequence_diagram
from citius_ui.showcases.inventory import collect as collect_inventory
from citius_ui.showcases.inventory import render_markdown as render_inventory
from citius_ui.showcases.inventory import to_cyclonedx
from citius_ui.showcases.model import ExpectedOutcome, Runbook, StepState
from citius_ui.showcases.replay import StepResult, form_values, run_step
from citius_ui.showcases.runbooks import RUNBOOKS, render_markdown
from citius_ui.workbench.actions import build_registry, registry_overview
from citius_ui.workbench.catalogue import choices_for, load_choices
from citius_ui.workbench.forms import FORMS, FORMS_BY_METHOD, FormField, RpcFormSpec, build_request

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

# Inventory table columns, in display order (keys of Inventory.table() rows).
_INVENTORY_COLUMNS = (
    "name",
    "version",
    "algorithm",
    "template_id",
    "pq_ready",
    "nist_quantum_security_level",
    "fips_approved_algorithm",
    "provider",
    "provider_fips_140",
    "fips_ready",
    "lifecycle_state",
)

# The Workbench tab's id, so a runbook step can switch to it.
_WORKBENCH_TAB = "workbench"

# One private directory per process holds the CBOM exports. Each export
# replaces the one before, and the directory goes when the process exits, so
# exports do not pile up in the temp directory.
_cbom_dir: Path | None = None


def _write_cbom(bom: dict[str, Any]) -> Path:
    """Write ``bom`` as the only file in the process's CBOM directory."""
    global _cbom_dir  # noqa: PLW0603 - one directory for the life of the process
    if _cbom_dir is None or not _cbom_dir.is_dir():
        _cbom_dir = Path(tempfile.mkdtemp(prefix="citius-cbom-"))
        atexit.register(shutil.rmtree, _cbom_dir, ignore_errors=True)
    for old in _cbom_dir.glob("citius-cbom-*.json"):
        old.unlink(missing_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = _cbom_dir / f"citius-cbom-{stamp}.json"
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    path.chmod(0o600)
    return path


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
  --citius-seq-ink: #2f3d6b; --citius-seq-line: #56628c; --citius-seq-actor: #e6ebfb;
  --citius-seq-actor-edge: #9aa9d8; --citius-seq-lifeline: #c3cce6;
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
  --citius-seq-ink: #d7def5; --citius-seq-line: #aab8e0; --citius-seq-actor: #27334f;
  --citius-seq-actor-edge: #5a6a9c; --citius-seq-lifeline: #3f4c75;
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

/* A runbook's goal: the claim, before and after, and its proofs. A proof
   reads muted until its steps have gone as expected, then in full ink (the
   card renders it in bold). Gradio puts the class on both the block and
   its inner .prose, so the frame goes on the block only. */
.block.goal-card { border-left: 4px solid var(--citius-accent-teal) !important;
             background: var(--citius-surface-open) !important;
             padding: 10px 14px !important; border-radius: 0 8px 8px 0 !important; }
.goal-card li { color: var(--citius-muted-ink) !important; }
.goal-card li strong { color: var(--citius-ink) !important; }
/* Mermaid stretches a diagram to the full width, which makes a long runbook
   several screens tall; cap it so it scales down instead. */
.runbook-diagram .mermaid svg { max-width: 860px !important; }
/* Gradio draws a diagram once, in the theme the page loaded with, and the
   toggle only flips the page's "dark" class, so Mermaid's own colours stay
   behind. Its stylesheet sits inside each diagram without !important, so
   these rules win and follow the theme variables above. The step bands keep
   their own semi-transparent fills, which read on both backgrounds. */
.runbook-diagram .mermaid svg { color: var(--citius-seq-ink) !important; }
.runbook-diagram .mermaid .messageText, .runbook-diagram .mermaid text.actor > tspan,
.runbook-diagram .mermaid .noteText, .runbook-diagram .mermaid .noteText > tspan {
    fill: var(--citius-seq-ink) !important; stroke: none !important; }
.runbook-diagram .mermaid .messageLine0, .runbook-diagram .mermaid .messageLine1 {
    stroke: var(--citius-seq-line) !important; }
.runbook-diagram .mermaid marker path, .runbook-diagram .mermaid .marker {
    fill: var(--citius-seq-line) !important; stroke: var(--citius-seq-line) !important; }
.runbook-diagram .mermaid rect.actor, .runbook-diagram .mermaid .actor-man circle {
    fill: var(--citius-seq-actor) !important; stroke: var(--citius-seq-actor-edge) !important; }
.runbook-diagram .mermaid .actor-man line { stroke: var(--citius-seq-actor-edge) !important; }
.runbook-diagram .mermaid .actor-line { stroke: var(--citius-seq-lifeline) !important; }

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
.output-zone .cm-editor, .step-response .cm-editor { background: #1e1e1e !important; border-radius: 6px !important; }

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


_VERDICT = {
    StepState.PASSED: "as expected",
    StepState.DIFFERS: "a value differs from what the step expects",
    StepState.FAILED: "not as expected",
}


_NO_RESPONSE_LABEL = "Response"


def _response_label(result: StepResult) -> str:
    return f"Response · step {result.index} ({result.step.method}, {result.status or 'not sent'})"


def _response_json(result: StepResult) -> str:
    """What a step sent and got back, as the Workbench's output panel shows it."""
    body: dict[str, Any] = {"status": result.status or "not sent"}
    if result.message:
        body["message" if result.status == "OK" else "error"] = result.message
    if not result.status:
        body["error"] = result.detail
    body["request"] = dict(result.request)
    body["response"] = dict(result.response)
    return json.dumps(body, indent=2, default=str)


def _diagram(runbook: Runbook, results: dict[int, StepResult]) -> str:
    """The runbook's sequence diagram, with what its colours mean above it."""
    return f"_{LEGEND}_\n\n{sequence_diagram(runbook, results)}"


def _step_outcome(result: StepResult) -> str:
    """One line on how a step went, and what to do when it went wrong."""
    step = result.step
    verdict = _VERDICT.get(result.state, result.state.value)
    lines = [f"**Step {result.index}** ({step.persona}, {step.method}): {result.status or 'no call'}, {verdict}."]
    if result.detail:
        lines.append("`" + result.detail.replace("`", "'") + "`")
    if result.state is StepState.FAILED:
        if result.status == "PERMISSION_DENIED" and step.expected is ExpectedOutcome.SUCCESS:
            lines.append(f"This step is for the {step.persona}: run it in the {step.persona}'s browser.")
        elif result.status in ("NOT_FOUND", "ALREADY_EXISTS"):
            lines.append(
                "An earlier step may not have run, or keys from an earlier run exist. "
                "Run the earlier steps, or Reset and use a fresh server."
            )
    return "  \n".join(lines)


def _render_input(spec: FormField) -> gr.components.Component:
    # Only append "(optional)" when the label does not already convey it, and
    # never for checkboxes (an unchecked box already reads as "not set").
    label = spec.label
    if spec.optional and spec.kind != "bool" and "optional" not in spec.label.lower():
        label = f"{spec.label} (optional)"
    info = spec.help or None
    if spec.kind == "area":
        return gr.Textbox(label=label, placeholder=spec.placeholder, lines=6, max_lines=24, info=info)
    if spec.kind == "number":
        return gr.Number(label=label, info=info)
    if spec.kind == "bool":
        return gr.Checkbox(label=label, info=info)
    if spec.kind == "dropdown":
        value = spec.choices[0] if (spec.choices and not spec.optional) else None
        return gr.Dropdown(label=label, choices=list(spec.choices), value=value, allow_custom_value=True, info=info)
    return gr.Textbox(label=label, placeholder=spec.placeholder, info=info)


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
    # Dropdowns whose choices come from the server's catalogue, filled on page load.
    live_fields: list[tuple[FormField, gr.components.Component]] = []
    # Per RPC, its form inputs in field order; per service, its card and method
    # dropdown. Runbook steps prefill through these.
    form_inputs: dict[tuple[str, str], list[gr.components.Component]] = {}
    service_cards: dict[str, tuple[gr.Accordion, gr.Dropdown]] = {}

    def _open_clients(session: Session) -> CitiusClients:
        """Clients that call the server with the session's token."""
        return CitiusClients(config, make_provider(session.id))

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
                clients = _open_clients(session)
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
            form_inputs[(spec.service, spec.method)] = inputs
            live_fields.extend((field, components[field.key]) for field in spec.fields if field.choices_from)

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

    async def _build_inventory(request: gr.Request) -> tuple[str, list[list[Any]], Any]:
        """Collect the session's inventory; offer its CBOM as a download."""
        hidden = gr.update(visible=False)
        session = sessions.get(request.cookies.get(config.session_cookie_name))
        if session is None:
            return "**No active session.** Sign in again.", [], hidden
        try:
            clients = _open_clients(session)
        except Exception as exc:  # noqa: BLE001 - misconfigured endpoint/TLS must render, not crash
            return f"**UNAVAILABLE** · could not create a Citius client: {exc}", [], hidden
        try:
            inventory = await collect_inventory(clients)
        except CitiusError as error:
            result = error_result(error)
            return f"**{result.status.value}** · ListKeys failed: {result.message}", [], hidden
        finally:
            try:
                await clients.close()
            except Exception:  # noqa: BLE001 - closing must never mask the result
                pass
        rows = [[row[column] for column in _INVENTORY_COLUMNS] for row in inventory.table()]
        path = _write_cbom(to_cyclonedx(inventory))
        return render_inventory(inventory), rows, gr.update(value=str(path), visible=True)

    def _render_service_card(service: str, *, open_by_default: bool) -> None:
        forms = _forms_for(service)
        label = SERVICE_LABELS.get(service, service)
        accent = _ACCENT_BY_SERVICE.get(service)
        card_classes = ["svc-card", accent] if accent else ["svc-card"]
        with gr.Accordion(f"{label} · {service}", open=open_by_default, elem_classes=card_classes) as card:
            span_toggle_id = f"span-toggle-{service}"
            span_toggle = gr.Button(_SPAN_TWO_LABEL, elem_id=span_toggle_id, elem_classes=["span-toggle-btn"])
            span_toggle.click(None, js=_span_toggle_js(span_toggle_id))
            with gr.Column(elem_classes=["method-zone"]):
                method = gr.Dropdown(choices=[form.method for form in forms], value=forms[0].method, label="Method")
            service_cards[service] = (card, method)
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

    def _render_runbook(runbook: Runbook, tabs: gr.Tabs) -> None:
        """The runbook's goal card and sequence diagram, and a step picker to run or prefill.

        **Run step** sends the step's request through the same executor as
        the Workbench, so the call lands in the session's history, and colours
        the step by its result. Results and bundles live in a ``gr.State``, so
        each browser tab has its own, and only runs from here count: calls
        made in the Workbench do not change the diagram. **Reset** clears them.

        **Prefill** switches to the Workbench tab, opens the step's service
        card, selects its method, and sets its form. Only RPCs with a form
        can be prefilled; the outputs are fixed when the page is built, so
        they cover every card and form the runbook uses.
        """
        steps = [step for step in runbook.steps if (step.service, step.method) in form_inputs]
        if not steps:
            return
        numbers = [runbook.steps.index(step) + 1 for step in steps]
        labels = [f"{number}. {step.persona} · {step.title}" for number, step in zip(numbers, steps, strict=True)]
        services = sorted({step.service for step in steps})
        rpcs = sorted({(step.service, step.method) for step in steps})
        outputs: list[Any] = [tabs]
        for service in services:
            outputs.extend(service_cards[service])
        for rpc in rpcs:
            outputs.extend(form_inputs[rpc])
        goal_view = gr.Markdown(goal_card(runbook), elem_classes=["goal-card"])
        run_state = gr.State(value=None)
        # The controls and the last result sit above the diagram, which can be
        # taller than the screen.
        with gr.Row():
            picker = gr.Dropdown(choices=labels, value=labels[0], label="Step", scale=4)
            run = gr.Button("Run step", variant="primary", scale=1)
            prefill = gr.Button("Prefill in Workbench", variant="secondary", scale=1)
            reset = gr.Button("Reset", variant="secondary", scale=1)
        outcome = gr.Markdown("")
        # The exact request and response of a step, for a closer look. It shows
        # the step just run, or the one picked in the step list if it has run.
        with gr.Accordion(
            _NO_RESPONSE_LABEL, open=False, elem_classes=["rpc-accordion", "step-response"]
        ) as response_box:
            response_view = gr.Code(value="", language="json", interactive=False, show_label=False)
        diagram_view = gr.Markdown(_diagram(runbook, {}), elem_classes=["runbook-diagram"])

        def _prefill(label: str) -> list[Any]:
            step = steps[labels.index(label)] if label in labels else steps[0]
            updates: list[Any] = [gr.Tabs(selected=_WORKBENCH_TAB)]
            for service in services:
                if service == step.service:
                    updates += [gr.update(open=True), gr.update(value=step.method)]
                else:
                    updates += [gr.update(), gr.update()]
            for rpc in rpcs:
                spec = FORMS_BY_METHOD[rpc]
                if rpc != (step.service, step.method):
                    updates += [gr.update() for _ in spec.fields]
                    continue
                for field, value in zip(spec.fields, form_values(step), strict=True):
                    if value is None and field.kind == "bool":
                        value = False
                    updates.append(gr.update(value=value))
            return updates

        async def _run_runbook_step(label: str, state: dict[str, Any] | None, request: gr.Request) -> tuple[Any, ...]:
            state = state or {"results": {}, "bundles": {}}
            number = numbers[labels.index(label)] if label in labels else numbers[0]
            step = runbook.steps[number - 1]
            unchanged = (gr.update(), gr.update())
            kept = (gr.update(), gr.update())
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is None:
                return (*unchanged, "**No active session.** Sign in again to run steps.", state, gr.update(), *kept)
            try:
                clients = _open_clients(session)
            except Exception as exc:  # noqa: BLE001 - misconfigured endpoint/TLS must render, not crash
                message = f"**UNAVAILABLE** · could not create a Citius client: {exc}"
                return (*unchanged, message, state, gr.update(), *kept)
            executor = ActionExecutor(history)
            context = ExecutionContext(
                session_id=session.history_id,
                subject=session.subject,
                endpoint=config.citius_endpoint,
                scenario_run_id=f"{runbook.key}:{number}",
            )

            async def invoke(action: RpcAction, payload: dict[str, Any]) -> RpcResult:
                result, _ = await executor.execute(action, context, payload)
                return result

            bundles = dict(state["bundles"])
            try:
                result = await run_step(number, step, build_registry(clients), bundles, invoke=invoke)
            finally:
                try:
                    await clients.close()
                except Exception:  # noqa: BLE001 - closing must never mask the result
                    pass
            results = {**state["results"], number: result}
            upcoming = next_step(runbook, results)
            moved = result.state is StepState.PASSED and upcoming in numbers
            chosen = labels[numbers.index(upcoming)] if moved and upcoming is not None else label
            return (
                goal_card(runbook, results),
                _diagram(runbook, results),
                _step_outcome(result),
                {"results": results, "bundles": bundles},
                gr.update(value=chosen),
                gr.update(label=_response_label(result)),
                _response_json(result),
            )

        def _reset_runbook() -> tuple[Any, ...]:
            return (
                goal_card(runbook),
                _diagram(runbook, {}),
                "",
                None,
                gr.update(value=labels[0]),
                gr.update(label=_NO_RESPONSE_LABEL),
                "",
            )

        def _show_response(label: str, state: dict[str, Any] | None) -> tuple[Any, Any]:
            """Picking a step that has run shows its response; any other pick leaves the view as it is."""
            number = numbers[labels.index(label)] if label in labels else None
            result = (state or {}).get("results", {}).get(number)
            if result is None:
                return gr.update(), gr.update()
            return gr.update(label=_response_label(result)), _response_json(result)

        prefill.click(_prefill, inputs=picker, outputs=outputs)
        views = [goal_view, diagram_view, outcome, run_state, picker, response_box, response_view]
        run.click(_run_runbook_step, inputs=[picker, run_state], outputs=views)
        reset.click(_reset_runbook, outputs=views)
        # .input fires only when a person picks, not when Run step moves the picker on.
        picker.input(_show_response, inputs=[picker, run_state], outputs=[response_box, response_view])

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
        # Gradio copies each download into its cache; drop copies after an hour.
        delete_cache=(3600, 3600),
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

        with gr.Tabs() as tabs:
            with gr.Tab("API Workbench", id=_WORKBENCH_TAB):
                with gr.Column(elem_classes=["workbench-grid"]):
                    for service in _ordered_services(grouped):
                        if _forms_for(service):
                            _render_service_card(service, open_by_default=False)
                        else:
                            _render_unavailable_card(service)

            with gr.Tab("Crypto inventory"):
                with gr.Column(elem_classes=["service-body"]):
                    gr.Markdown(
                        "Every key this identity can read, with what the catalogue says about its "
                        "algorithm (quantum-safe, FIPS-approved) and the FIPS 140 level of the "
                        "instance holding it. Export it as a CycloneDX 1.6 CBOM."
                    )
                    build_inventory_button = gr.Button("Build inventory", variant="primary")
                    inventory_report = gr.Markdown()
                    inventory_table = gr.Dataframe(headers=list(_INVENTORY_COLUMNS), interactive=False, wrap=True)
                    cbom_download = gr.DownloadButton("Download CBOM (CycloneDX JSON)", visible=False)
                    build_inventory_button.click(
                        _build_inventory,
                        outputs=[inventory_report, inventory_table, cbom_download],
                    )

            with gr.Tab("Demo runbooks"):
                with gr.Column(elem_classes=["service-body"]):
                    gr.Markdown(
                        "Each runbook shows what it proves and, as a sequence diagram, who calls "
                        "what. Pick a step and **Run step** to run it here: the diagram colours it "
                        "by the result, and bundles pass to later steps. **Prefill** loads the step "
                        "into the Workbench instead. Steps for another identity (R7) run in that "
                        "identity's browser; only safe bundles cross browsers, never tokens."
                    )
                    for runbook in RUNBOOKS:
                        with gr.Accordion(runbook.title, open=False, elem_classes=["rpc-accordion"]):
                            _render_runbook(runbook, tabs)
                            # The summary and every step's explanation, hint and
                            # what to look for: there when wanted, hidden otherwise.
                            with gr.Accordion("Details", open=False, elem_classes=["rpc-accordion"]):
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

        async def _load_catalogue(request: gr.Request) -> list[Any]:
            """Offer the session's view of instances, provider types and scopes as choices."""
            loaded: dict[str, tuple[str, ...]] = {}
            session = sessions.get(request.cookies.get(config.session_cookie_name))
            if session is not None:
                try:
                    clients = _open_clients(session)
                except Exception:  # noqa: BLE001 - without a client the static choices stay
                    clients = None
                if clients is not None:
                    try:
                        loaded = await load_choices(clients, {field.choices_from for field, _ in live_fields})
                    finally:
                        try:
                            await clients.close()
                        except Exception:  # noqa: BLE001 - closing must never break the page
                            pass
            return [
                gr.update(choices=choices_for(field.choices, field.optional, loaded.get(field.choices_from)))
                for field, _ in live_fields
            ]

        if live_fields:
            blocks.load(_load_catalogue, outputs=[component for _, component in live_fields])

    return blocks
