"""Temporary decision-aid mock of a per-RPC Workbench surface.

This module renders the reference UI's structure so we can evaluate it before
committing to it in the SDK-wired Workbench: each service is a panel of per-RPC
tabs, every RPC exposes its common fields individually with clickable examples,
an inline collapsible Output, and, for producer RPCs, an inline history table
with a Clear that also resets that RPC's history. Advanced protobuf fields stay
behind a collapsed JSON editor so the common case is simple without hiding the
full surface.

It performs no cryptography and makes no gRPC or OIDC calls; it exists only to
compare layouts and decide how far to expose the API surface per RPC.
"""

from __future__ import annotations

import json
from typing import Any

import gradio as gr

CSS = """
.title-container { text-align: center; margin: 12px 0 18px; padding: 24px;
                   background: #a4c2f4; border-radius: 10px;
                   box-shadow: 0 4px 8px rgba(0, 0, 0, .10); }
.title-container h1 { color: #17233b; font-size: 2.2rem; margin: 0 0 8px; }
.title-container p { color: #263a5d; margin: 0; }
.section-title { border-left: 5px solid #6d83f2; padding: 6px 12px; margin: 18px 0 8px; }
.section-title h2 { font-size: 1.15rem; margin: 0; }
.mock-note { border-left: 4px solid #d8a400; padding: 8px 12px; margin-bottom: 12px; }
footer { visibility: hidden; }
"""


def _section(title: str) -> None:
    gr.HTML(f"<div class='section-title'><h2>{title}</h2></div>", padding=False)


def _preview(**fields: Any) -> str:
    return json.dumps({k: v for k, v in fields.items() if v not in ("", None)}, indent=2)


def _simple_rpc_tab(
    tab_label: str,
    action_label: str,
    field_specs: list[tuple[str, str]],
    examples: list[list[str]],
    advanced_placeholder: str = "{}",
) -> None:
    """Render one RPC as a tab with individual fields, output, examples, advanced JSON."""
    with gr.Tab(tab_label):
        inputs = [gr.Textbox(label=label, placeholder=placeholder) for label, placeholder in field_specs]
        with gr.Accordion("Advanced protobuf fields (JSON)", open=False):
            gr.Code(value=advanced_placeholder, language="json", label="Advanced request overrides")
        with gr.Row():
            run = gr.Button(action_label, variant="primary")
            gr.Button("Clear", variant="secondary")
        with gr.Accordion("Output", open=True, visible=False) as output_row:
            gr.JSON(label="Response")
        if examples:
            with gr.Accordion("Examples", open=True):
                gr.Examples(examples=examples, inputs=inputs)
        # Reveal the output panel on run in the real wiring; here it is illustrative.
        run.click(lambda: gr.update(visible=True), outputs=output_row)


def _producer_rpc_tab(
    tab_label: str,
    action_label: str,
    field_specs: list[tuple[str, str]],
    value_label: str,
    examples: list[list[str]],
) -> None:
    """Render a producer RPC with an inline per-RPC history and a Clear that resets it."""
    with gr.Tab(tab_label):
        inputs = [gr.Textbox(label=label, placeholder=placeholder) for label, placeholder in field_specs]
        with gr.Row():
            run = gr.Button(action_label, variant="primary")
            clear = gr.Button("Clear", variant="secondary")
        with gr.Accordion("Output", open=True, visible=False) as output_row:
            gr.JSON(label="Response")
            gr.Textbox(label=value_label, max_lines=4)
            history = gr.Dataframe(
                headers=["Key name", "Key version", value_label, "Metadata"],
                col_count=(4, "fixed"),
                label=f"Previous {tab_label.lower()} responses",
                interactive=False,
                wrap=True,
            )
        if examples:
            with gr.Accordion("Examples", open=True):
                gr.Examples(examples=examples, inputs=inputs)
        run.click(lambda: gr.update(visible=True), outputs=output_row)
        clear.click(lambda: [], outputs=history)


def build_mock_surface() -> gr.Blocks:
    """Build the reference-style per-RPC decision-aid mock."""
    with gr.Blocks(
        title="Citius Workbench · per-RPC layout mock",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><h1>Citius API Workbench — layout mock</h1>"
            "<p>Reference-style per-RPC forms with inline output and history. "
            "No cryptography, gRPC, or auth is performed.</p></div>",
            padding=False,
        )
        gr.HTML(
            "<div class='mock-note'><strong>Decision aid:</strong> each RPC exposes its "
            "common fields directly; advanced protobuf fields stay behind a JSON editor. "
            "History lives inside the producing RPC and is cleared per RPC.</div>",
            padding=False,
        )

        _section("Crypto Policy")
        with gr.Column(variant="panel"):
            _simple_rpc_tab(
                "Create Policy",
                "Create",
                [("Policy name", "demo-signing-policy"), ("Policy document", "version: v1 …"), ("Format", "yaml")],
                [["demo-signing-policy", "version: v1\nallowed_operations: [SIGN, VERIFY]", "yaml"]],
            )
            _simple_rpc_tab("Read Policy", "Read", [("Policy name", "demo-signing-policy")], [["demo-signing-policy"]])
            _simple_rpc_tab(
                "Update Policy",
                "Update",
                [
                    ("Policy name", "demo-signing-policy"),
                    ("Policy document", "version: v2 …"),
                    ("Format", "yaml"),
                    ("Expected version", "1"),
                ],
                [["demo-signing-policy", "version: v2", "yaml", "1"]],
            )

        _section("Key Management")
        with gr.Column(variant="panel"):
            _simple_rpc_tab(
                "Create Key",
                "Create",
                [
                    ("Key name", "demo-signing-key"),
                    ("Policy", "demo-signing-policy"),
                    ("Template", "ecdsa-p256-sha256"),
                    ("Provider", "software"),
                ],
                [["demo-signing-key", "demo-signing-policy", "ecdsa-p256-sha256", "software"]],
                advanced_placeholder=json.dumps(
                    {"scope_spec": {}, "provider_requirements": {}, "provider_configuration": {}}, indent=2
                ),
            )
            _simple_rpc_tab(
                "Read Key",
                "Read",
                [("Key name", "demo-signing-key"), ("Version", "(latest)")],
                [["demo-signing-key", ""]],
            )
            _simple_rpc_tab(
                "Transform Key",
                "Transform",
                [("Key name", "demo-signing-key"), ("Template", "ml-dsa-65"), ("Retain key bytes", "false")],
                [["demo-signing-key", "ml-dsa-65", "false"]],
            )

        _section("Cryptographic Operations")
        with gr.Column(variant="panel"):
            _producer_rpc_tab(
                "Sign",
                "Sign",
                [("Key name", "demo-signing-key"), ("Message", "Hello from Citius")],
                "Signature",
                [["demo-signing-key", "Hello from Citius"]],
            )
            _simple_rpc_tab(
                "Verify",
                "Verify",
                [
                    ("Key name", "demo-signing-key"),
                    ("Message", "Hello from Citius"),
                    ("Signature", "base64 …"),
                    ("Metadata", "{key_version: 1}"),
                ],
                [],
            )
            _producer_rpc_tab(
                "Encrypt",
                "Encrypt",
                [("Key name", "demo-encryption-key"), ("Plaintext", "Sensitive demo payload")],
                "Ciphertext",
                [["demo-encryption-key", "Sensitive demo payload"]],
            )
            _simple_rpc_tab(
                "Decrypt",
                "Decrypt",
                [("Key name", "demo-encryption-key"), ("Ciphertext", "base64 …"), ("Metadata", "{key_version: 1}")],
                [],
            )

    return blocks


def main() -> None:
    build_mock_surface().launch(server_name="127.0.0.1", server_port=7862)


if __name__ == "__main__":
    main()
