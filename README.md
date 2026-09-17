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

Copy `.env.example` into deployment-specific environment configuration and
adjust the Citius target, TLS trust, and generated non-secret OIDC configuration
path. The application does not load `.env` automatically; inject these values
through the process environment or deployment secret/configuration mechanism.

The default paths assume `citius-ui` and `citius-server` are sibling checkouts.
Run the canonical Zitadel setup from `citius-server` to generate
`bootstrap/zitadel/citius-ui-auth.json`; the UI never provisions identities.

## Test

```bash
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy
uv run pytest
uv build
```

CI runs the same gates and Gitleaks secret scanning. This project uses the
Apache-2.0 license, matching the Citius server and Python SDK repositories.

## Mock limitations

- Authentication is a mock sign-in screen, not Zitadel login. Switching identity
  requires logout; use separate browser profiles for concurrent demo users.
- Cryptographic values are deterministic placeholders, not real cryptography.
- Artifact compatibility models the Citius `OperationMetadata.key_version`
  contract; rotation remains marked pending until its server RPC is implemented.
- RPC availability mirrors the implementation assessment captured in `IMPLEMENTATION_PLAN.md`.
- Policies and keys are shared in the mock process; identity and history exist only
  in the Gradio browser session.
