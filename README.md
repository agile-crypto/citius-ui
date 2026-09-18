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

### FastAPI host with server-side sessions

The `citius-ui` entry point mounts the Gradio Workbench inside FastAPI behind an
opaque, HTTP-only session cookie. Development sign-in seeds one of the demo
personas per browser session; hosted Authorization Code with PKCE replaces this
dev sign-in in a later phase.

```bash
uv run citius-ui
```

Then open <http://127.0.0.1:7860>, sign in as a persona, and open
`/workbench`. Access tokens live only in the server-side session store and are
never written to the browser or logs. `/healthz` and `/readyz` expose liveness
and readiness. Switching identity requires logging out; use separate browser
profiles for concurrent personas.

Copy `.env.example` into deployment-specific environment configuration and
adjust the Citius target, TLS trust, and generated non-secret OIDC configuration
path. The application does not load `.env` automatically; inject these values
through the process environment or deployment secret/configuration mechanism.

`citius-ui` and `citius-server` are **independent repositories**; clone them
wherever you like. Run the canonical Zitadel setup from your `citius-server`
checkout to generate `bootstrap/zitadel/citius-ui-auth.json`; the UI never
provisions identities. The `CITIUS_OIDC_CONFIG_PATH` default assumes the two
repos happen to sit side by side, but you should set it explicitly to point at
wherever your `citius-server` checkout lives.

## Local test stack (Zitadel + citius-server)

`citius-server` is a separate repository that owns a one-command local stack. It
brings up **Zitadel and a containerized `citius-server` together**, provisions
the CISO/producer/consumer demo users, and emits the non-secret config this UI
consumes. The UI never starts Zitadel or the server itself — it only reads the
emitted config.

Clone `citius-server` separately and bring the stack up from that checkout (see
its `bootstrap/zitadel/README.md` for the full lifecycle). The examples below
use `CITIUS_SERVER_DIR` for the absolute path to your `citius-server` clone:

```bash
# path to your separate citius-server checkout — set this to your own location
export CITIUS_SERVER_DIR=/path/to/citius-server

# one-time: install mkcert and trust its local CA
mkcert -install

# bring up Zitadel + a containerized citius-server and provision demo users
( cd "$CITIUS_SERVER_DIR" && CITIUS_SERVER=1 make zitadel-up )

# preflight: confirm the emitted config points at a reachable, trusted stack
"$CITIUS_SERVER_DIR"/bootstrap/zitadel/smoke-test.sh
```

That emits two non-secret files under `$CITIUS_SERVER_DIR/bootstrap/zitadel/`:

- `citius-ui-auth.json` — issuer, OIDC web-app client id, and audience for the
  hosted Authorization Code + PKCE login.
- `citius-stack.json` — the consolidated descriptor: `citius_server.endpoint`,
  `tls_ca`, `tls_server_name`, and the same Zitadel values.

Secrets (introspection client secret, PATs, masterkey, demo passwords) stay in
`citius-zitadel.env`/`generated-config.json`, which remain mode `0600` and
gitignored.

Point the UI at the stack with the launcher script, which derives every
setting (endpoint, TLS CA, TLS server name, OIDC config, and the listen port
from the registered redirect URI) out of the emitted config:

```bash
# CITIUS_SERVER_DIR defaults to the sibling ../citius-server when it exists.
CITIUS_SERVER_DIR=/path/to/citius-server ./start-citius-ui.sh
```

The script requires `jq` and `uv`, validates that the stack config and CA exist,
warns if the listen port would not match the registered OIDC redirect URI, and
prints the resolved settings on startup.

To wire it manually instead, read the emitted config from your `citius-server`
checkout:

```bash
Z="$CITIUS_SERVER_DIR/bootstrap/zitadel"
stack="$Z/citius-stack.json"
CA="$(jq -r .citius_server.tls_ca "$stack")"
export CITIUS_UI_PORT=7861   # must match citius-ui-auth.json redirect_uris[0]
export CITIUS_SESSION_COOKIE_SECURE=false
export CITIUS_ENDPOINT="$(jq -r .citius_server.endpoint "$stack")"
export CITIUS_TLS_ENABLED=true
export CITIUS_TLS_CA="$CA"
export CITIUS_TLS_SERVER_NAME="$(jq -r .citius_server.tls_server_name "$stack")"
export CITIUS_OIDC_CONFIG_PATH="$Z/citius-ui-auth.json"
export CITIUS_OIDC_CA_CERT="$CA"
uv run citius-ui
```

The local certificate is issued for `citius-auth.localhost`, so
`CITIUS_TLS_SERVER_NAME` overrides hostname verification when dialing
`127.0.0.1`. `CITIUS_OIDC_CA_CERT` (defaulting to `CITIUS_TLS_CA`) trusts the
Zitadel issuer's mkcert certificate when exchanging the auth code and fetching
the JWKS; without it the hosted-login callback returns 401. The UI forwards the
current session's hosted-login token to the Python SDK per RPC; the server
enforces its own method and resource authorization.

### Hosted login (Authorization Code + PKCE)

`GET /login` starts the production-style flow: the UI generates PKCE + state +
nonce and redirects the browser to the Zitadel hosted login. After sign-in,
`/auth/callback` validates `state`, exchanges the code with the PKCE verifier,
verifies the ID token's signature (JWKS), issuer, audience, nonce, and expiry,
and creates a server-side session. Access/refresh/ID tokens never reach the
browser. When refresh tokens are enabled the session token is proactively
refreshed as it nears expiry. The UI must listen on the port that matches the
registered redirect URI in `citius-ui-auth.json` (e.g. `7861`), and
`CITIUS_OIDC_CA_CERT` (defaulting to `CITIUS_TLS_CA`) trusts the issuer's JWKS.

 The dev sign-in at `/` remains available for local work without the hosted flow.

Tear down or reset from your `citius-server` checkout:

| Command | Effect |
|---|---|
| `CITIUS_SERVER=1 bootstrap/zitadel/bootstrap.sh down` | Stop containers, preserve data and emitted config. |
| `CITIUS_SERVER=1 bootstrap/zitadel/bootstrap.sh reset` | Stop, wipe data volumes and generated artefacts, then `up`. |
| `CITIUS_SERVER=1 bootstrap/zitadel/bootstrap.sh nuke` | `reset` plus delete `.env` so every secret regenerates. |

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
