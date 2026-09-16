# Citius UI

This repository currently contains a runnable mock of the proposed Citius Console. It does not connect to Citius or Zitadel and must not be used to validate security behavior.

The prototype explores:

- One focused **API Workbench**, plus a compact multi-browser demo runbook.
- Reference-style Gradio workbench navigation using native service accordions,
  RPC selectors, request editors, clickable examples, and output panels.
- One fixed CISO, producer, or consumer identity per browser session.
- Shared mock policies and keys, matching the real server boundary, with identity
  and operation history isolated per browser session.
- Reference-style append-only signature/ciphertext response history inside the
  Cryptographic Operations section. Every row includes the key name, key version,
  and a copyable value-plus-operation-metadata bundle for backward-compatibility tests.
- Visible success, `PERMISSION_DENIED`, and `UNIMPLEMENTED` outcomes.

## Run

The current workstation already has a compatible Gradio installation, so the quickest local command is:

```bash
PYTHONPATH=src python3 -m citius_ui.single_user_app
```

Then open <http://127.0.0.1:7860>.

If that port is already occupied, set `CITIUS_UI_PORT`, for example:

```bash
CITIUS_UI_PORT=7861 PYTHONPATH=src python3 -m citius_ui.single_user_app
```

For an isolated environment:

```bash
uv sync --extra dev
uv run citius-ui-mock
```

## Test

```bash
PYTHONPATH=src pytest
```

## Mock limitations

- Authentication is a mock sign-in screen, not Zitadel login. Switching identity
  requires logout; use separate browser profiles for concurrent demo users.
- Cryptographic values are deterministic placeholders, not real cryptography.
- Artifact compatibility models the Citius `OperationMetadata.key_version`
  contract; rotation remains marked pending until its server RPC is implemented.
- RPC availability mirrors the implementation assessment captured in `IMPLEMENTATION_PLAN.md`.
- Policies and keys are shared in the mock process; identity and history exist only
  in the Gradio browser session.
