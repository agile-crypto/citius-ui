"""Temporary decision-aid mock of a per-RPC Workbench surface.

This module renders a candidate layout for the SDK-wired Workbench so we can
evaluate it before committing. Services are large colored parent accordions;
each RPC is a lighter, indented child accordion that highlights when open, so it
is always clear which service and RPC you are on. Fields mirror the Citius
protobuf request messages in api/proto: common scalar fields are exposed
directly, document fields use resizable text boxes, the mutually-exclusive
scope/context parameter is a small dropdown with an advanced JSON editor for the
full surface, and clickable examples prefill the fields.

It performs no cryptography and makes no gRPC or OIDC calls; it exists only to
compare layouts and decide how far to expose the API surface per RPC.
"""

from __future__ import annotations

from dataclasses import dataclass

import gradio as gr

CSS = """
:root { --citius-indigo: #4b5bd6; --citius-indigo-dark: #37409e; --citius-sky: #a4c2f4; }
.title-container { text-align: center; margin: 8px 0 18px; padding: 26px;
                   background: linear-gradient(135deg, #4b5bd6, #7a8cf0);
                   border-radius: 14px; box-shadow: 0 8px 22px rgba(75, 91, 214, .28); }
.title-container h1 { color: #ffffff; font-size: 2.2rem; margin: 0 0 8px; letter-spacing: .3px; }
.title-container p { color: #e6ebff; margin: 0; }
.mock-note { border-left: 4px solid #d8a400; background: #fffbea; padding: 10px 14px;
             margin-bottom: 16px; border-radius: 0 8px 8px 0; }

/* Parent (service) accordion: bold indigo header bar. */
.service-accordion { border: 0 !important; margin: 14px 0 !important; }
.service-accordion > button, .service-accordion > .label-wrap {
    background: linear-gradient(135deg, var(--citius-indigo), var(--citius-indigo-dark)) !important;
    color: #ffffff !important; font-size: 1.1rem !important; font-weight: 700 !important;
    border-radius: 10px !important; padding: 14px 18px !important;
    box-shadow: 0 4px 12px rgba(55, 64, 158, .25) !important; }
.service-accordion > button span, .service-accordion > .label-wrap span { color: #ffffff !important; }

/* Child (RPC) accordion: light card with an indigo left accent that brightens when open. */
.rpc-accordion { margin: 8px 0 8px 14px !important;
                 border: 1px solid #dfe4f5 !important; border-left: 4px solid #c3cbe8 !important;
                 border-radius: 8px !important; background: #fbfcff !important; }
.rpc-accordion > button, .rpc-accordion > .label-wrap {
    font-weight: 600 !important; color: #2b336b !important; padding: 10px 14px !important; }
.rpc-accordion.rpc-open { border-left: 4px solid var(--citius-indigo) !important;
                          background: #eef1ff !important; box-shadow: inset 0 0 0 1px #cdd5f5 !important; }
.rpc-accordion.rpc-open > button, .rpc-accordion.rpc-open > .label-wrap { color: var(--citius-indigo-dark) !important; }

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
    """A single RPC's form: request fields, examples, and artifact output."""

    method: str
    action_label: str
    fields: tuple[Field, ...]
    examples: tuple[tuple[object, ...], ...] = ()
    produces: str = ""  # "" | Signature | Ciphertext
    advanced: str = ""


_POLICY_DOC = Field("policy_document", "Policy document", kind="area", placeholder="version: v1 …")
_SAMPLE_POLICY = "version: v1\nallowed_operations: [SIGN, VERIFY]\nallowed_templates: [ecdsa-p256-sha256]"

# Scope oneof branches from api/proto (encryption scope_params / signing scope_context).
_ENCRYPT_SCOPES = ("no_params", "aead_params", "xts_params", "asymmetric_params", "vendor_params")
_SIGN_SCOPES = ("no_context", "domain_context", "vendor_context")

SERVICES: dict[str, tuple[RpcForm, ...]] = {
    "🛡️  Crypto Policy · CryptoPolicyService": (
        RpcForm(
            "CreateCryptoPolicy",
            "Create",
            (
                Field("name", "Policy name", placeholder="demo-signing-policy"),
                _POLICY_DOC,
                Field("format", "Format", kind="dropdown", choices=("json", "rego", "cedar", "yaml"), optional=True),
            ),
            examples=(
                ("demo-signing-policy", _SAMPLE_POLICY, "yaml"),
                ("demo-restricted-policy", "version: v1\nallowed_operations: [VERIFY]", "yaml"),
            ),
        ),
        RpcForm(
            "ReadCryptoPolicy",
            "Read",
            (Field("name", "Policy name", placeholder="demo-signing-policy"),),
            examples=(("demo-signing-policy",),),
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
            examples=(("demo-signing-policy", _SAMPLE_POLICY + "\nmax_key_age_days: 90", "yaml", 1),),
        ),
    ),
    "🔑  Key Management · KeyManagementService": (
        RpcForm(
            "CreateKey",
            "Create",
            (
                Field("name", "Key name", placeholder="demo-signing-key"),
                Field("policy", "Policy", placeholder="demo-signing-policy"),
                Field("template_id", "Template ID", placeholder="ecdsa-p256-sha256", optional=True),
                Field("provider_id", "Provider ID", placeholder="software", optional=True),
            ),
            examples=(
                ("demo-signing-key", "demo-signing-policy", "ecdsa-p256-sha256", "software"),
                ("demo-encryption-key", "demo-signing-policy", "aes-256-gcm", "software"),
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
            examples=(("demo-signing-key", None),),
        ),
        RpcForm(
            "TransformKey",
            "Transform",
            (
                Field("name", "Key name", placeholder="demo-signing-key"),
                Field("template_id", "Template ID", placeholder="ml-dsa-65", optional=True),
                Field("retain_key_bytes", "Retain key bytes", kind="bool"),
            ),
            examples=(("demo-signing-key", "ml-dsa-65", False),),
            advanced='{\n  "scope_spec": {}\n}',
        ),
    ),
    "🔐  Cryptographic Operations · CryptoService": (
        RpcForm(
            "Sign",
            "Sign",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("input", "Input (message)", kind="area", placeholder="Hello from Citius"),
                Field("scope_context", "Signature context (scope)", kind="dropdown", choices=_SIGN_SCOPES),
            ),
            examples=(("demo-signing-key", "Hello from Citius", "no_context"),),
            produces="Signature",
            advanced='{\n  "domain_context": {"context": "demo"}\n}',
        ),
        RpcForm(
            "Verify",
            "Verify",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("input", "Input (message)", kind="area", placeholder="Hello from Citius"),
                Field("signature", "Signature (base64)", kind="area"),
                Field("metadata", "Operation metadata (JSON)", kind="area"),
                Field("scope_context", "Signature context (scope)", kind="dropdown", choices=_SIGN_SCOPES),
            ),
            examples=(
                ("demo-signing-key", "Hello from Citius", "<paste signature>", '{"key_version": 1}', "no_context"),
            ),
            advanced='{\n  "domain_context": {"context": "demo"}\n}',
        ),
        RpcForm(
            "Encrypt",
            "Encrypt",
            (
                Field("key_name", "Key name", placeholder="demo-encryption-key"),
                Field("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
                Field("scope_params", "Encryption scope", kind="dropdown", choices=_ENCRYPT_SCOPES),
            ),
            examples=(
                ("demo-encryption-key", "Sensitive demo payload", "aead_params"),
                ("demo-cbc-key", "Sensitive demo payload", "no_params"),
            ),
            produces="Ciphertext",
            advanced='{\n  "aead_params": {"aad": ""}\n}',
        ),
        RpcForm(
            "Decrypt",
            "Decrypt",
            (
                Field("key_name", "Key name", placeholder="demo-encryption-key"),
                Field("ciphertext", "Ciphertext (base64)", kind="area"),
                Field("metadata", "Operation metadata (JSON)", kind="area"),
                Field("scope_params", "Encryption scope", kind="dropdown", choices=_ENCRYPT_SCOPES),
            ),
            examples=(("demo-encryption-key", "<paste ciphertext>", '{"key_version": 1}', "aead_params"),),
            advanced='{\n  "aead_params": {"aad": ""}\n}',
        ),
        RpcForm(
            "DigestSign",
            "Digest sign",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("digest", "Digest (base64)", kind="area"),
                Field("hash_algorithm", "Hash algorithm", optional=True),
            ),
            examples=(("demo-signing-key", "<paste digest>", "SHA-256"),),
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
            examples=(("demo-signing-key", "<paste digest>", "<paste signature>", '{"key_version": 1}', "SHA-256"),),
        ),
    ),
}


def _render_field(spec: Field) -> gr.components.Component:
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


def _render_rpc_accordion(form: RpcForm) -> None:
    with gr.Accordion(form.method, open=False, elem_classes=["rpc-accordion"]) as accordion:
        inputs = [_render_field(spec) for spec in form.fields]
        if form.advanced:
            with gr.Accordion("Advanced scope/context parameters (JSON)", open=False):
                gr.Code(value=form.advanced, language="json", label="Advanced request overrides")
        with gr.Row():
            run = gr.Button(form.action_label, variant="primary")
            clear = gr.Button("Clear", variant="secondary")
        with gr.Accordion("Output", open=True, visible=False) as output_row:
            gr.JSON(label="Response")
            history = None
            if form.produces:
                gr.Textbox(label=f"Current {form.produces}", max_lines=4)
                history = gr.Dataframe(
                    headers=["Key name", "Key version", form.produces, "Metadata"],
                    col_count=(4, "fixed"),
                    label=f"Previous {form.method} responses",
                    interactive=False,
                    wrap=True,
                )
        if form.examples:
            with gr.Accordion("Examples", open=True):
                gr.Examples(examples=[list(example) for example in form.examples], inputs=inputs)
        run.click(lambda: gr.update(visible=True), outputs=output_row)
        if history is not None:
            clear.click(lambda: [], outputs=history)
        clear.click(lambda inputs=inputs: [None for _ in inputs], outputs=inputs)

        # Highlight the RPC accordion while it is open.
        def _mark_open() -> dict[str, object]:
            return gr.update(elem_classes=["rpc-accordion", "rpc-open"])

        def _mark_closed() -> dict[str, object]:
            return gr.update(elem_classes=["rpc-accordion"])

        accordion.expand(_mark_open, outputs=accordion)
        accordion.collapse(_mark_closed, outputs=accordion)


def build_mock_surface() -> gr.Blocks:
    """Build the styled mock with distinct parent/child accordions and examples."""
    with gr.Blocks(
        title="Citius Workbench · per-RPC layout mock",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><h1>Citius API Workbench</h1>"
            "<p>Open a service, then open an RPC to edit its fields and run it. "
            "No cryptography, gRPC, or auth is performed.</p></div>",
            padding=False,
        )
        gr.HTML(
            "<div class='mock-note'><strong>Decision aid:</strong> services are the "
            "bold indigo bars; each RPC is an indented card that highlights when open. "
            "Common fields mirror api/proto, documents are resizable, the scope is a "
            "dropdown with advanced JSON, and examples prefill the fields.</div>",
            padding=False,
        )

        for service_label, forms in SERVICES.items():
            with gr.Accordion(service_label, open=False, elem_classes=["service-accordion"]):
                for form in forms:
                    _render_rpc_accordion(form)

    return blocks


def main() -> None:
    build_mock_surface().launch(server_name="127.0.0.1", server_port=7862)


if __name__ == "__main__":
    main()
