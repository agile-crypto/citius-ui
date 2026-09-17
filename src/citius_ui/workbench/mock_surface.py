"""Temporary decision-aid mock of a per-RPC Workbench surface.

This module renders the reference UI's structure so we can evaluate it before
committing to it in the SDK-wired Workbench. Each service is a collapsible
accordion; every RPC is its own nested accordion listing all RPCs and letting
each open or collapse independently. Fields mirror the Citius protobuf request
messages in api/proto: common scalar fields are exposed directly, policy and
document fields use resizable text areas, mutually-exclusive scope/context
parameters stay behind a collapsed advanced JSON editor, and clickable examples
prefill the individual fields.

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
    """A single RPC's form: request fields, examples, and artifact output."""

    method: str
    action_label: str
    fields: tuple[Field, ...]
    examples: tuple[tuple[object, ...], ...] = ()
    produces: str = ""  # "" | Signature | Ciphertext
    advanced: str = ""  # JSON hint for scope/context params


_POLICY_DOC = Field("policy_document", "Policy document", kind="area", placeholder="version: v1 …")
_SAMPLE_POLICY = "version: v1\nallowed_operations: [SIGN, VERIFY]\nallowed_templates: [ecdsa-p256-sha256]"

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
    "Cryptographic Operations · CryptoService": (
        RpcForm(
            "Sign",
            "Sign",
            (
                Field("key_name", "Key name", placeholder="demo-signing-key"),
                Field("input", "Input (message)", kind="area", placeholder="Hello from Citius"),
            ),
            examples=(("demo-signing-key", "Hello from Citius"),),
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
            examples=(("demo-signing-key", "Hello from Citius", "<paste signature>", '{"key_version": 1}'),),
            advanced='{\n  "no_context": {}\n}',
        ),
        RpcForm(
            "Encrypt",
            "Encrypt",
            (
                Field("key_name", "Key name", placeholder="demo-encryption-key"),
                Field("plaintext", "Plaintext", kind="area", placeholder="Sensitive demo payload"),
            ),
            examples=(("demo-encryption-key", "Sensitive demo payload"),),
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
            examples=(("demo-encryption-key", "<paste ciphertext>", '{"key_version": 1}'),),
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
        return gr.Textbox(label=label, placeholder=spec.placeholder, lines=4, max_lines=20)
    if spec.kind == "number":
        return gr.Number(label=label)
    if spec.kind == "bool":
        return gr.Checkbox(label=label)
    if spec.kind == "dropdown":
        return gr.Dropdown(label=label, choices=list(spec.choices), allow_custom_value=True)
    return gr.Textbox(label=label, placeholder=spec.placeholder)


def _render_rpc_accordion(form: RpcForm) -> None:
    with gr.Accordion(form.method, open=False):
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
        clear_outputs = [*inputs]
        if history is not None:
            clear.click(lambda: [], outputs=history)
        clear.click(lambda: [None for _ in clear_outputs], outputs=clear_outputs)


def build_mock_surface() -> gr.Blocks:
    """Build the reference-style mock with nested service and per-RPC accordions."""
    with gr.Blocks(
        title="Citius Workbench · per-RPC layout mock",
        theme=gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"]),
        css=CSS,
        fill_width=True,
    ) as blocks:
        gr.HTML(
            "<div class='title-container'><h1>Citius API Workbench — layout mock</h1>"
            "<p>Open a service, then open an RPC to edit its fields and run it. No "
            "cryptography, gRPC, or auth is performed.</p></div>",
            padding=False,
        )
        gr.HTML(
            "<div class='mock-note'><strong>Decision aid:</strong> services and RPCs "
            "are collapsible accordions; common fields mirror api/proto and document "
            "fields are resizable; scope/context parameters stay behind an advanced "
            "JSON editor; examples prefill the fields. History lives inside the "
            "producing RPC and clears per RPC.</div>",
            padding=False,
        )

        for service_label, forms in SERVICES.items():
            with gr.Accordion(service_label, open=False):
                for form in forms:
                    _render_rpc_accordion(form)

    return blocks


def main() -> None:
    build_mock_surface().launch(server_name="127.0.0.1", server_port=7862)


if __name__ == "__main__":
    main()
