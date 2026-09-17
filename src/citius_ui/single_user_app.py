"""Single-identity Gradio mock for the Citius API Workbench."""

from __future__ import annotations

import copy
import json
from threading import Lock
from typing import Any

import gradio as gr

from citius_ui.config import AppConfig
from citius_ui.mock_engine import (
    IMPLEMENTED,
    PERSONAS,
    SERVICES,
    execute,
    history_record,
    history_rows,
    initial_state,
    parse_json,
    persona_summary,
    producer_response_rows,
    request_example,
)

CSS = """
.title-container { text-align: center; margin: 12px 0 18px; padding: 24px;
                   background: #a4c2f4; border-radius: 10px;
                   box-shadow: 0 4px 8px rgba(0, 0, 0, .10); }
.title-container h1 { color: #17233b; font-size: 2.35rem; margin: 0 0 8px; }
.title-container p { color: #263a5d; font-size: 1rem; margin: 0; }
.title-container hr { width: 80%; height: 2px; background: #ffffff; border: 0; margin: 12px auto; }
.section-title { border-left: 5px solid #6d83f2; padding: 6px 12px; margin: 18px 0 10px; }
.section-title h2 { font-size: 1.2rem; margin: 0; }
.mock-note { border-left: 4px solid #d8a400; padding: 8px 12px; margin-bottom: 14px; }
.identity-note { border-left: 4px solid #5b8c5a; padding: 8px 12px; }
footer { visibility: hidden; }
"""


HISTORY_HEADERS = ["ID", "Time", "Identity", "Service", "RPC", "Status", "Resource"]
RESPONSE_HISTORY_HEADERS = [
    "Time",
    "Operation",
    "Response type",
    "Key Name",
    "Key version",
    "Copyable response bundle",
]

# Policies and keys model shared Citius server state. Login, history, and retained
# crypto responses remain in each browser's gr.State.
_SHARED_BACKEND = {"policies": {}, "keys": {}, "key_versions": {}}
_SHARED_BACKEND_LOCK = Lock()


WORKBENCH_EXAMPLES: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
    "CryptoPolicyService": [
        (
            "Signing policy",
            "CreateCryptoPolicy",
            request_example("CryptoPolicyService", "CreateCryptoPolicy"),
        ),
        (
            "Encryption policy",
            "CreateCryptoPolicy",
            {
                "name": "demo-encryption-policy",
                "policy_document": {
                    "version": "v1",
                    "allowed_operations": ["ENCRYPT", "DECRYPT"],
                    "allowed_templates": ["aes-256-gcm"],
                    "allowed_providers": ["software"],
                },
            },
        ),
        ("Read signing policy", "ReadCryptoPolicy", {"name": "demo-signing-policy"}),
    ],
    "KeyManagementService": [
        (
            "ECDSA signing key",
            "CreateKey",
            request_example("KeyManagementService", "CreateKey"),
        ),
        (
            "AES encryption key",
            "CreateKey",
            {
                "name": "demo-encryption-key",
                "policy": "demo-encryption-policy",
                "template_id": "aes-256-gcm",
                "provider_id": "software",
                "provider_requirements": {"constant_time": True, "memory_safe": True},
            },
        ),
        (
            "Requirements-selected key",
            "CreateKey",
            {
                "name": "demo-requirements-key",
                "policy": "demo-signing-policy",
                "algorithm_requirements": {
                    "operation": "SIGN",
                    "minimum_security_strength_bits": 128,
                    "quantum_safe": True,
                },
                "provider_requirements": {
                    "constant_time": True,
                    "memory_safe": True,
                    "hardware_backed": False,
                },
            },
        ),
        ("Read signing key", "ReadKey", {"name": "demo-signing-key"}),
        (
            "Transform to ML-DSA",
            "TransformKey",
            request_example("KeyManagementService", "TransformKey"),
        ),
    ],
    "CryptoService": [
        ("Sign message", "Sign", request_example("CryptoService", "Sign")),
        (
            "Verify latest local signature",
            "Verify",
            request_example("CryptoService", "Verify"),
        ),
        ("Encrypt payload", "Encrypt", request_example("CryptoService", "Encrypt")),
        (
            "Decrypt latest local ciphertext",
            "Decrypt",
            request_example("CryptoService", "Decrypt"),
        ),
        (
            "Sign a digest",
            "DigestSign",
            {
                "key_name": "demo-signing-key",
                "digest": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
            },
        ),
        (
            "Verify a digest",
            "DigestVerify",
            {
                "key_name": "demo-signing-key",
                "digest": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
                "signature": "paste-signature-from-response-history",
                "metadata": {"key_version": 1},
            },
        ),
    ],
    "AlgorithmDiscoveryService": [
        ("List templates", "ListTemplates", {}),
        ("Get ECDSA template", "GetTemplate", {"template_id": "ecdsa-p256-sha256"}),
        ("List scopes", "ListScopes", {}),
    ],
    "ProviderService": [
        ("List providers", "ListProviders", {}),
        ("Get software provider", "GetProvider", {"provider_id": "software"}),
        (
            "Match secure providers",
            "MatchProviders",
            {"requirements": {"constant_time": True, "memory_safe": True}},
        ),
    ],
    "KeyEstablishmentService": [
        (
            "Wrap a key",
            "WrapKey",
            {"wrapping_key_name": "demo-wrapping-key", "key_name": "demo-encryption-key"},
        ),
        (
            "Derive a key",
            "DeriveKey",
            {"base_key_name": "demo-encryption-key", "derived_key_name": "demo-derived-key"},
        ),
    ],
    "StreamingCryptoService": [
        ("Start encryption", "EncryptInit", {"key_name": "demo-encryption-key"}),
        ("Encrypt a chunk", "EncryptUpdate", {"stream_id": "paste-stream-id", "chunk": "Hello"}),
        ("Finish encryption", "EncryptFinal", {"stream_id": "paste-stream-id"}),
    ],
}


def _service_examples(service: str) -> tuple[list[list[str]], list[str]]:
    configured = WORKBENCH_EXAMPLES.get(service, [])
    rows = [[method, json.dumps(request, indent=2)] for _, method, request in configured]
    labels = [label for label, _, _ in configured]
    return rows, labels


def _capability_rows() -> list[list[str]]:
    rows: list[list[str]] = []
    for service, methods in SERVICES.items():
        implemented = sum((service, method) in IMPLEMENTED for method in methods)
        rows.append([service, str(len(methods)), str(implemented), str(len(methods) - implemented)])
    return rows


def _method_changed(service: str, method: str):
    return json.dumps(request_example(service, method), indent=2), _availability(service, method)


def _availability(service: str, method: str) -> str:
    if (service, method) in IMPLEMENTED:
        return f"✅ **Available in assessed server** · `/{service}/{method}`"
    return f"🟡 **Contract present; server implementation pending** · `/{service}/{method}`"


def _login(persona: str, state: dict[str, Any]):
    state = copy.deepcopy(state or initial_state())
    state["authenticated_persona"] = persona
    return (
        state,
        gr.update(visible=False),
        gr.update(visible=True),
        persona_summary(persona),
        f"Signed in as **{PERSONAS[persona]['username']}**. This browser session now has one fixed identity.",
    )


def _logout():
    return (
        initial_state(),
        gr.update(visible=True),
        gr.update(visible=False),
        "Signed out. Session history and retained responses were cleared from this browser session.",
        [],
        [],
        {},
    )


def _execute_workbench(service: str, method: str, request_text: str, state: dict[str, Any]):
    state = copy.deepcopy(state or initial_state())
    persona = state.get("authenticated_persona")
    if not persona:
        result = {
            "status": "UNAUTHENTICATED",
            "error": {"message": "Sign in before executing an RPC", "category": "session"},
            "mock": True,
        }
        return state, result, _metadata(service, method, result), history_rows(state), producer_response_rows(state)

    try:
        request = parse_json(request_text)
    except (json.JSONDecodeError, ValueError) as exc:
        result = {"status": "INVALID_JSON", "error": {"message": str(exc)}, "mock": True}
        return state, result, _metadata(service, method, result), history_rows(state), producer_response_rows(state)

    with _SHARED_BACKEND_LOCK:
        for field in _SHARED_BACKEND:
            state[field] = copy.deepcopy(_SHARED_BACKEND[field])
        state, result = execute(state, persona, service, method, request)
        for field in _SHARED_BACKEND:
            _SHARED_BACKEND[field] = copy.deepcopy(state[field])

    return state, result, _metadata(service, method, result), history_rows(state), producer_response_rows(state)


def _metadata(service: str, method: str, result: dict[str, Any]) -> str:
    return f"### {result['status']}\n\n`caas.crypto.v1.{service}/{method}` · mock response · simulated 15 ms"


def _clear_history(state: dict[str, Any]):
    state = copy.deepcopy(state or initial_state())
    state["history"] = []
    state["artifacts"] = {"signatures": [], "ciphertexts": []}
    return state, [], [], {"status": "CLEARED", "message": "This browser session's history was cleared."}


def build_app() -> gr.Blocks:
    theme = gr.themes.Base(font=["IBM Plex Sans", "Arial", "sans-serif"])
    with gr.Blocks(css=CSS, theme=theme, title="Citius API Workbench · Flow Mock", fill_width=True) as app:
        session = gr.State(initial_state())

        gr.HTML(
            "<div class='title-container'><hr><h1>Citius API Workbench</h1>"
            "<p>Explore the gRPC API by service and connect individual calls "
            "into governed cryptographic workflows.</p><hr></div>"
        )
        gr.HTML(
            "<div class='mock-note'><strong>Interactive mock:</strong> no Citius or Zitadel calls are made; "
            "authentication, authorization, and cryptographic outputs are simulated.</div>"
        )

        gr.HTML("<div class='section-title'><h2>Session</h2></div>")
        with gr.Column(variant="panel", visible=True) as login_panel:
            gr.Markdown(
                "### Mock sign-in\nChoose one identity for this browser session. For a multi-user demo, "
                "use separate browser profiles or different browsers."
            )
            with gr.Row(equal_height=True):
                login_persona = gr.Dropdown(choices=list(PERSONAS), value="CISO", label="Identity")
                sign_in = gr.Button("Sign in", variant="primary")

        with gr.Column(variant="panel", visible=False) as active_session_panel:
            with gr.Row(equal_height=True):
                identity_card = gr.Markdown()
                with gr.Column(scale=1):
                    gr.Textbox(value="grpcs://localhost:50051", label="Citius endpoint", interactive=False)
                    gr.Textbox(value="Connected · mock TLS channel", label="Connection", interactive=False)
                    logout = gr.Button("Log out", variant="secondary")
        session_message = gr.Markdown("Sign in to execute RPCs.", elem_classes="identity-note")

        with gr.Accordion("Multi-browser demo runbook", open=False):
            gr.Markdown(
                "1. Open three isolated browser profiles and sign in as **CISO**, **Producer**, and **Consumer**.\n"
                "2. CISO creates policy and performs lifecycle operations.\n"
                "3. Producer creates keys and produces signatures or ciphertexts.\n"
                "4. Copy a complete bundle from **Previous producer responses**.\n"
                "5. Paste its key name, value, and metadata into Verify or Decrypt in the Consumer browser.\n\n"
                "> Each browser has private identity and history. Mock policies and keys are shared, "
                "like the real Citius server."
            )

        gr.HTML("<div class='section-title'><h2>API Workbench</h2></div>")
        gr.Markdown(
            "Services follow the gRPC contract. Open a service, select an RPC, "
            "edit its protobuf-shaped JSON request, and execute it."
        )

        workbench_panels: list[dict[str, Any]] = []
        service_labels = {
            "CryptoPolicyService": "Crypto Policy",
            "KeyManagementService": "Key Management",
            "CryptoService": "Cryptographic Operations",
            "AlgorithmDiscoveryService": "Algorithm Discovery",
            "ProviderService": "Provider Management",
            "KeyEstablishmentService": "Key Establishment",
            "StreamingCryptoService": "Streaming Cryptography",
        }
        service_order = [
            "CryptoPolicyService",
            "KeyManagementService",
            "CryptoService",
            "AlgorithmDiscoveryService",
            "ProviderService",
            "KeyEstablishmentService",
            "StreamingCryptoService",
        ]
        response_history = None
        for service_name in service_order:
            methods = SERVICES[service_name]
            with gr.Accordion(service_labels[service_name], open=service_name == "CryptoPolicyService"):
                service_state = gr.State(service_name)
                method = gr.Dropdown(choices=methods, value=methods[0], label="RPC method")
                availability = gr.Markdown(_availability(service_name, methods[0]))
                request_json = gr.Code(
                    value=json.dumps(request_example(service_name, methods[0]), indent=2),
                    language="json",
                    label="Request",
                    lines=14,
                )
                example_rows, example_labels = _service_examples(service_name)
                with gr.Accordion("Examples — click to populate", open=True):
                    gr.Examples(
                        examples=example_rows,
                        example_labels=example_labels,
                        inputs=[method, request_json],
                        outputs=[request_json, availability],
                        fn=lambda rpc, payload, svc=service_name: (
                            payload,
                            _availability(svc, rpc),
                        ),
                        run_on_click=True,
                        cache_examples=False,
                    )
                with gr.Row():
                    execute_button = gr.Button("Execute", variant="primary")
                    reset_example = gr.Button("Load example", variant="secondary")
                with gr.Accordion("Output", open=True):
                    rpc_metadata = gr.Markdown("### Ready\n\nSelect an RPC and execute the mock request.")
                    workbench_output = gr.JSON(label="Current response")
                if service_name == "CryptoService":
                    gr.Markdown(
                        "### Previous producer responses\n"
                        "Successful Sign, DigestSign, and Encrypt responses append here with their **Key Name**. "
                        "Copy the complete bundle—including metadata—to process old data after key changes."
                    )
                    response_history = gr.Dataframe(
                        value=[],
                        headers=RESPONSE_HISTORY_HEADERS,
                        interactive=False,
                        wrap=True,
                        label="Signature and ciphertext response history",
                    )
                workbench_panels.append(
                    {
                        "service": service_state,
                        "method": method,
                        "availability": availability,
                        "request": request_json,
                        "execute": execute_button,
                        "reset": reset_example,
                        "metadata": rpc_metadata,
                        "output": workbench_output,
                    }
                )

        with gr.Accordion("Session activity", open=False):
            gr.Markdown(
                "All attempted RPCs in this browser session are retained, including authorization denials "
                "and unimplemented methods."
            )
            with gr.Row():
                history_filter = gr.Dropdown(
                    choices=["All services", *SERVICES], value="All services", label="Filter by service"
                )
                refresh_history = gr.Button("Refresh")
                clear_history = gr.Button("Clear session history")
            history_table = gr.Dataframe(
                value=[], headers=HISTORY_HEADERS, interactive=False, label="Session operations"
            )
            with gr.Row():
                record_id = gr.Textbox(label="Inspect operation ID", placeholder="op-001")
                inspect_button = gr.Button("Inspect")
            history_detail = gr.JSON(label="Request and response detail")

        with gr.Accordion("Capability overview", open=False):
            gr.Dataframe(
                value=_capability_rows(),
                headers=["gRPC service", "Contract RPCs", "Implemented", "Pending"],
                interactive=False,
            )
            gr.Markdown(
                "Typed form or JSON request → Python gRPC client → access token metadata → "
                "Citius authorization and policy enforcement → normalized response → browser-session history"
            )

        assert response_history is not None
        sign_in.click(
            _login,
            [login_persona, session],
            [session, login_panel, active_session_panel, identity_card, session_message],
        )
        logout.click(
            _logout,
            None,
            [
                session,
                login_panel,
                active_session_panel,
                session_message,
                history_table,
                response_history,
                history_detail,
            ],
        )
        for panel in workbench_panels:
            panel["method"].change(
                _method_changed,
                [panel["service"], panel["method"]],
                [panel["request"], panel["availability"]],
            )
            panel["reset"].click(
                lambda svc, rpc: json.dumps(request_example(svc, rpc), indent=2),
                [panel["service"], panel["method"]],
                panel["request"],
            )
            panel["execute"].click(
                _execute_workbench,
                [panel["service"], panel["method"], panel["request"], session],
                [session, panel["output"], panel["metadata"], history_table, response_history],
            )
        refresh_history.click(
            lambda state, service: history_rows(state, service), [session, history_filter], history_table
        )
        history_filter.change(
            lambda state, service: history_rows(state, service), [session, history_filter], history_table
        )
        inspect_button.click(history_record, [session, record_id], history_detail)
        clear_history.click(_clear_history, session, [session, history_table, response_history, history_detail])

    return app


def main() -> None:
    config = AppConfig.from_env()
    build_app().launch(server_name=config.ui_host, server_port=config.ui_port)
