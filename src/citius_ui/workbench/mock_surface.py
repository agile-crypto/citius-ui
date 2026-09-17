"""Temporary decision-aid mock of a per-RPC Workbench surface.

This module renders the reference UI's structure so we can evaluate it before
committing to it in the SDK-wired Workbench. Each service is a collapsible
accordion. Opening a service reveals a selector listing its RPCs; choosing an
RPC shows that RPC's form. Fields mirror the Citius protobuf request messages in
api/proto: common scalar fields are exposed directly, policy and document fields
use resizable text areas, and the mutually-exclusive scope/context parameters
stay behind a collapsed advanced JSON editor.

It performs no cryptography and makes no gRPC or OIDC calls; it exists only to
compare layouts and decide how far to expose the API surface per RPC.
"""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class Field:
    """One form field aligned with a protobuf request field."""

    proto: str
    label: str
    kind: str = "text"  # text | area | number | bool | dropdown
    placeholder: str = ""
    choices: tuple[str, ...] = ()
    optional: bool = False


@dataclass(frozen=True, slots=True)
class RpcForm:
    """A single RPC's form: its request fields and whether it produces artifacts."""

    method: str
    action_label: str
    fields: tuple[Field, ...]
    produces: str = ""  # "" | Signature | Ciphertext
    advanced: str = ""  # JSON hint for scope/context params


_POLICY_DOC = Field("policy_document", "Policy document", kind="area", placeholder="version: v1 …")

SERVICES: dict[str, tuple[RpcForm, ...]] = {
    "Crypto Policy · CryptoPolicyService": (
        RpcForm(
            "CreateCryptoPolicy",
            "Create",
            (
                Field("name", "Policy name", placeholder="demo-signing-policy"),
                _POLICY_DOC,
                Field("format", "Format", kind="dropdown", choices=("json", "rego", "cedar", "yaml"), optional=True),
            ),
        ),
        RpcForm(
            "ReadCryptoPolicy",
            "Read",
            (Field("name", "Policy name", placeholder="demo-signing-policy"),),
        ),
        RpcForm(
            "UpdateCryptoPolicy",
            "Update",
            (
                Field("name", "Policy name", placeholder="demo-signing-policy"),
                _POLICY_DOC,
                Field("format", "Format", kind="dropdown", choices=("json", "rego", "cedar", "yaml"), optional=True),
                Field("expected_version", "Expected version", kind="number", optional=True),
            ),
        ),
    ),
    "Key Management · KeyManagementService": (
        RpcForm(
            "CreateKey",
            "Create",
            (
                Field("name", "Key name", placeholder="demo-signing-key"),
                Field("policy", "Policy", placeholder="demo-signing-policy"),
                Field("template_id", "Template ID", placeholder="ecdsa-p256-sha256", optional=True),
                Field("provider_id", "Provider ID", placeholder="software", optional=True),
            ),
            advanced='{\n  "scope_spec": {},\n  "provider_requirements": {},\n  "provider_configuration": {}\n}',
        ),
        RpcForm(
            "ReadKey",
            "Read",
            (
                Field("name", "Key name", placeholder="demo-signing-key"),
                Field("version", "Version", kind="number", optional=True),
            ),
        ),
        RpcForm(
            "TransformKey",
            "Transform",
            (
                Field("name", "Key name", placeholder="demo-signing-key"),
                Field("template_id", "Template ID", placeholder="ml-dsa-65", optional=True),
                Field("retain_key_bytes", "Retain key bytes", kind="bool"),
            ),
            advanced='{\n  "scope_spec": {}\n}',
        ),
    ),
    "Cryptographic Operations · CryptoService": (
        RpcForm(
            "Sign",
            "Sign",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("input", "Input (message)", kind="area", placeholder="Hello from Citius"),
            ),
            produces="Signature",
            advanced='{\n  "no_context": {}\n}',
        ),
        RpcForm(
            "Verify",
            "Verify",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("input", "Input (message)", kind="area", placeholder="Hello from Citius"),
                Field("signature", "Signature (base64)", kind="area"),
                Field("metadata", "Operation metadata (JSON)", kind="area"),
            ),
            advanced='{\n  "no_context": {}\n}',
        ),
        RpcForm(
            "Encrypt",
            "Encrypt",
            (
                Field("key_name", "Key name", placeholder="demo-encryption-key"),
                Field("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
            ),
            produces="Ciphertext",
            advanced='{\n  "no_params": {}\n}',
        ),
        RpcForm(
            "Decrypt",
            "Decrypt",
            (
                Field("key_name", "Key name", placeholder="demo-encryption-key"),
                Field("ciphertext", "Ciphertext (base64)", kind="area"),
                Field("metadata", "Operation metadata (JSON)", kind="area"),
            ),
            advanced='{\n  "no_params": {}\n}',
        ),
        RpcForm(
            "DigestSign",
            "Digest sign",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("digest", "Digest (base64)", kind="area"),
                Field("hash_algorithm", "Hash algorithm", optional=True),
            ),
            produces="Signature",
        ),
        RpcForm(
            "DigestVerify",
            "Digest verify",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("digest", "Digest (base64)", kind="area"),
                Field("signature", "Signature (base64)", kind="area"),
                Field("metadata", "Operation metadata (JSON)", kind="area"),
                Field("hash_algorithm", "Hash algorithm", optional=True),
            ),
        ),
    ),
}


def _render_field(spec: Field) -> None:
    label = f"{spec.label} (optional)" if spec.optional else spec.label
    if spec.kind == "area":
        gr.Textbox(label=label, placeholder=spec.placeholder, lines=4, max_lines=20)
    elif spec.kind == "number":
        gr.Number(label=label)
    elif spec.kind == "bool":
        gr.Checkbox(label=label)
    elif spec.kind == "dropdown":
        gr.Dropdown(label=label, choices=list(spec.choices), allow_custom_value=True)
    else:
        gr.Textbox(label=label, placeholder=spec.placeholder)


def _render_rpc_form(form: RpcForm, visible: bool) -> gr.Group:
    with gr.Group(visible=visible) as group:
        gr.Markdown(f"**{form.method}** — request fields mirror `api/proto`.")
        for spec in form.fields:
            _render_field(spec)
        if form.advanced:
            with gr.Accordion("Advanced scope/context parameters (JSON)", open=False):
                gr.Code(value=form.advanced, language="json", label="Advanced request overrides")
        with gr.Row():
            run = gr.Button(form.action_label, variant="primary")
            clear = gr.Button("Clear", variant="secondary")
        with gr.Accordion("Output", open=True, visible=False) as output_row:
            gr.JSON(label="Response")
            if form.produces:
                gr.Textbox(label=f"Current {form.produces}", max_lines=4)
                history = gr.Dataframe(
                    headers=["Key name", "Key version", form.produces, "Metadata"],
                    col_count=(4, "fixed"),
                    label=f"Previous {form.method} responses",
                    interactive=False,
                    wrap=True,
                )
                clear.click(lambda: [], outputs=history)
        run.click(lambda: gr.update(visible=True), outputs=output_row)
    return group


def build_mock_surface() -> gr.Blocks:
    """Build the reference-style per-RPC decision-aid mock with service accordions."""
    with gr.Blocks(
        title="Citius Workbench · per-RPC layout mock",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><h1>Citius API Workbench — layout mock</h1>"
            "<p>Open a service, pick an RPC, and edit its fields. No cryptography, "
            "gRPC, or auth is performed.</p></div>",
            padding=False,
        )
        gr.HTML(
            "<div class='mock-note'><strong>Decision aid:</strong> common fields are "
            "exposed directly and mirror api/proto; document fields are resizable; "
            "scope/context parameters stay behind an advanced JSON editor. History "
            "lives inside the producing RPC and clears per RPC.</div>",
            padding=False,
        )

        for service_label, forms in SERVICES.items():
            with gr.Accordion(service_label, open=False):
                selector = gr.Radio(
                    choices=[form.method for form in forms],
                    value=forms[0].method,
                    label="RPC",
                )
                groups = [_render_rpc_form(form, visible=(index == 0)) for index, form in enumerate(forms)]

                def _select(chosen: str, forms: tuple[RpcForm, ...] = forms) -> list[dict[str, object]]:
                    return [gr.update(visible=(form.method == chosen)) for form in forms]

                selector.change(_select, inputs=selector, outputs=groups)

    return blocks


def main() -> None:
    build_mock_surface().launch(server_name="127.0.0.1", server_port=7862)


if __name__ == "__main__":
    main()
