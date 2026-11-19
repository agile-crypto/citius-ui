# Citius UI

The Citius Console: a Gradio API Workbench, hosted in FastAPI, that calls a
`citius-server` through the Python SDK and signs users in through Zitadel
hosted login. A standalone mock (`citius-ui-mock`) also runs without any server;
its cryptography is placeholder only, so it must not be used to validate
security behavior.

## Getting started

These steps start a local Zitadel + `citius-server` stack in containers, then
the Citius UI against it. Both `citius-server` and `citius-python-sdk` are git
submodules of this repository, so a single recursive clone brings everything.

The stack runs with either Docker or Podman. **Podman has been tested on macOS;
Docker has not been tested yet**, on either OS.

### Prerequisites

- You need an SSH key registered with GitHub that can read the
`agile-crypto/citius-server` and `agile-crypto/citius-python-sdk` repositories, as the submodule URLs use SSH. You can find the details to generate a new SSH key [here](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent). 
- Ports **8880**, **8443**, **50051** and **7861**
must be free on the host.

#### macOS

| Tool | Install | Why |
|---|---|---|
| Xcode Command Line Tools (`git`, `make`, `curl`) | `xcode-select --install` | Clone, run the Makefile targets |
| [Homebrew](https://brew.sh) | see brew.sh | Installs the tools below |
| `jq` | `brew install jq` (macOS 15+ ships one) | Parses the generated stack config |
| Go 1.26+ | `brew install go` | The bootstrap runs the Zitadel provisioning tool with `go run` |
| `mkcert` | `brew install mkcert` (add `brew install nss` for Firefox) | Issues the local TLS certificate |
| `uv` | `brew install uv` | Runs the UI; downloads Python 3.11+ if needed |
| A container engine | Podman **or** Docker, see below | Runs Zitadel, Postgres, Traefik and `citius-server` |

**Podman (tested):**

1. Install [Podman Desktop](https://podman-desktop.io) or `brew install podman`.
2. Install a Compose v2 provider, which `podman compose` delegates to:
   `brew install docker-compose` (v2.24 or later; the compose files use
   `!override` and `up --wait`).
3. Create and start the VM: `podman machine init && podman machine start`.
   The default rootless machine is fine.
4. Enable Docker compatibility (Podman Desktop → Settings → Docker
   Compatibility) so `/var/run/docker.sock` exists inside the VM. Traefik reads
   that socket to discover the containers.

**Docker (not tested):** install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
(it includes Compose v2) and start it. Make sure the default socket
`/var/run/docker.sock` is enabled (Settings → Advanced) and that `docker
context use desktop-linux` is selected, so `docker` talks to Docker Desktop and
not to another engine.

#### Linux

| Tool | Debian / Ubuntu | Fedora / RHEL | Why |
|---|---|---|---|
| `git`, `make`, `curl`, `jq` | `sudo apt install git make curl jq` | `sudo dnf install git make curl jq` | Clone, Makefile targets, stack config |
| Go 1.26+ | [go.dev/doc/install](https://go.dev/doc/install) (distro packages are usually too old) | same | Zitadel provisioning tool (`go run`) |
| `mkcert` | `sudo apt install mkcert libnss3-tools`, or the binary from [mkcert releases](https://github.com/FiloSottile/mkcert/releases) | `sudo dnf install nss-tools` + the release binary | Local TLS certificate; `nss-tools` lets browsers trust it |
| `uv` | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | same | Runs the UI; downloads Python 3.11+ if needed |
| A container engine | Docker **or** Podman, see below | | Runs the stack |

**Docker (not tested):** install [Docker Engine](https://docs.docker.com/engine/install/)
24+ with the `docker-compose-plugin` package (Compose v2.24+). Add your user to
the `docker` group (`sudo usermod -aG docker "$USER"`, then log out and in) so
the bootstrap can run `docker` without `sudo`.

**Podman (not tested on Linux):** install Podman 4+ and a Compose v2 provider
(`docker-compose` v2.24+; `podman compose` delegates to it). Traefik mounts
`/var/run/docker.sock`, so that path must reach the Podman API socket of the
user who runs the stack. For rootless Podman:

```bash
systemctl --user enable --now podman.socket
sudo ln -sf "/run/user/$(id -u)/podman/podman.sock" /var/run/docker.sock   # only if Docker is not installed
```

SELinux (Fedora/RHEL) is handled automatically when `ENGINE=podman` is set.

### One-time setup

```bash
# Trust the mkcert local CA (system store + browsers). Asks for your password.
mkcert -install

# Clone the UI together with its citius-server and citius-python-sdk submodules.
git clone --recurse-submodules git@github.com:agile-crypto/citius-ui.git
cd citius-ui
```

If you already cloned without `--recurse-submodules`, run
`git submodule update --init`.

### Start the stack and the UI

```bash
# 1. Zitadel + containerized citius-server, demo users provisioned.
#    Podman:
( cd citius-server && ENGINE=podman make zitadel-up-server )
#    Docker:
( cd citius-server && make zitadel-up-server )

# 2. Optional preflight: the emitted config points at a reachable, trusted stack.
#    Needs openssl, which is preinstalled on macOS and most Linux distributions.
citius-server/bootstrap/zitadel/smoke-test.sh

# 3. The UI, configured from the stack's emitted config.
./start-citius-ui.sh
```

The first start pulls images and builds `citius-server`, which takes a few
minutes. Then open <http://127.0.0.1:7861/login> and sign in as one of the
demo users `citius-ciso`, `citius-producer` or `citius-consumer`. Their
passwords are `CITIUS_DEMO_CISO_PASSWORD`, `CITIUS_DEMO_PRODUCER_PASSWORD` and
`CITIUS_DEMO_CONSUMER_PASSWORD` in `citius-server/bootstrap/zitadel/.env`.

### Stop

Stop the UI with `Ctrl+C`, then stop the stack (add `ENGINE=podman` for
Podman; data and generated config are kept for the next start):

```bash
( cd citius-server && ENGINE=podman make zitadel-down )
```

`CITIUS_SERVER=1 make zitadel-reset` wipes the data volumes and provisions a
fresh stack with the containerized server; `make zitadel-nuke` also deletes
`.env`, so the next start regenerates every secret. See
[Local test stack](#local-test-stack-zitadel--citius-server) below and
`citius-server/bootstrap/zitadel/README.md` for details and troubleshooting.

## What the prototype explores


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

## Run without the stack (mock)

The mock needs only `uv` and the submodules; it does not connect to Citius or
Zitadel:

```bash
uv sync --extra dev
uv run citius-ui-mock
```

Then open <http://127.0.0.1:7860>. If that port is already occupied, set
`CITIUS_UI_PORT`, for example `CITIUS_UI_PORT=7862 uv run citius-ui-mock`.

### FastAPI host with server-side sessions

The `citius-ui` entry point mounts the Gradio Workbench inside FastAPI behind an
opaque, HTTP-only session cookie. Against the local stack, users sign in through
the hosted login at `/login` (see [Hosted login](#hosted-login-authorization-code--pkce));
a development sign-in at `/` seeds one of the demo personas per browser session.

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

The UI never provisions identities: the Zitadel setup in the `citius-server`
submodule generates `citius-server/bootstrap/zitadel/citius-ui-auth.json`.
`CITIUS_OIDC_CONFIG_PATH` defaults to that path relative to the repository root;
set it explicitly when running from another directory or against another
`citius-server` checkout.

## Local test stack (Zitadel + citius-server)

The `citius-server` submodule owns a one-command local stack. It brings up
**Zitadel and a containerized `citius-server` together**, provisions the
CISO/producer/consumer demo users, and emits the non-secret config this UI
consumes. The UI never starts Zitadel or the server itself — it only reads the
emitted config. [Getting started](#getting-started) has the commands and
prerequisites; `citius-server/bootstrap/zitadel/README.md` covers the full
lifecycle.

That emits two non-secret files under `citius-server/bootstrap/zitadel/`:

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
# Uses the ./citius-server submodule.
./start-citius-ui.sh

# Or point it at another citius-server checkout:
CITIUS_SERVER_DIR=/path/to/citius-server ./start-citius-ui.sh
```

The script requires `jq` and `uv`, validates that the stack config and CA exist,
warns if the listen port would not match the registered OIDC redirect URI, and
prints the resolved settings on startup.

To wire it manually instead, read the emitted config from the submodule:

```bash
Z="$PWD/citius-server/bootstrap/zitadel"
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

Tear down or reset from the `citius-server` directory (prefix each command with
`ENGINE=podman` when using Podman):

| Command | Effect |
|---|---|
| `make zitadel-down` | Stop containers, preserve data and emitted config. |
| `CITIUS_SERVER=1 make zitadel-reset` | Stop, wipe data volumes and generated artefacts, then start again with the containerized server. |
| `make zitadel-nuke` | Stop, wipe data volumes, generated artefacts and `.env`; the next start regenerates every secret. |

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
