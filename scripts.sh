#!/usr/bin/env bash
# scripts.sh — start, stop and reset the local Citius stack and UI.
#
# Called by the Makefile targets `start`, `stop` and `reset`:
#   start   check prerequisites, start Zitadel + the containerized citius-server
#           (make zitadel-up-server), run the smoke test when openssl is
#           available, print the addresses and demo users, then run the UI in
#           the foreground (Ctrl+C stops the UI).
#   stop    stop the stack (make zitadel-down), keeping its data.
#   reset   wipe the stack (make zitadel-nuke): data volumes, generated config
#           and .env. The next start regenerates every secret.
#
# Environment:
#   ENGINE             docker or podman. When unset, it is detected: Docker when
#                      `docker compose version` works (and docker is not backed
#                      by Podman), then Podman when `podman compose version` works.
#   CITIUS_SERVER_DIR  citius-server checkout to use instead of the submodule.
#
# Works with the bash 3.2 that ships with macOS.

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="${CITIUS_SERVER_DIR:-$ROOT_DIR/citius-server}"
readonly SDK_DIR="$ROOT_DIR/citius-python-sdk"
readonly OS="$(uname -s)"

# ---------------------------------------------------------------------------
# Output: only the WARN / ERROR keywords are colored, and only on a terminal.
# ---------------------------------------------------------------------------
if [[ -t 2 && -z "${NO_COLOR:-}" ]]; then
  readonly WARN_TAG=$'\033[33mWARN\033[0m' ERROR_TAG=$'\033[31mERROR\033[0m'
else
  readonly WARN_TAG="WARN" ERROR_TAG="ERROR"
fi

info()  { printf '%s\n' "$*" >&2; }
warn()  { printf '%s %s\n' "$WARN_TAG" "$*" >&2; }
error() { printf '%s %s\n' "$ERROR_TAG" "$*" >&2; }

# Problems are collected so that one run reports everything that is missing.
PROBLEMS=()
problem() { PROBLEMS+=("$1"); }

report_problems_and_exit_if_any() {
  (( ${#PROBLEMS[@]} == 0 )) && return 0
  local p
  for p in "${PROBLEMS[@]}"; do error "$p"; done
  info ""
  info "See \"Getting started\" in $ROOT_DIR/README.md for the full prerequisites."
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

# install_hint TOOL prints how to install TOOL on this OS.
install_hint() {
  case "$OS:$1" in
    Darwin:go)     echo "brew install go" ;;
    Darwin:mkcert) echo "brew install mkcert (and brew install nss for Firefox), then mkcert -install" ;;
    Darwin:uv)     echo "brew install uv" ;;
    Darwin:openssl) echo "brew install openssl" ;;
    Darwin:git|Darwin:curl) echo "xcode-select --install" ;;
    Darwin:*)      echo "brew install $1" ;;
    *:go)          echo "see https://go.dev/doc/install (distro packages are usually too old)" ;;
    *:mkcert)      echo "sudo apt install mkcert libnss3-tools, or the binary from https://github.com/FiloSottile/mkcert/releases; then mkcert -install" ;;
    *:uv)          echo "curl -LsSf https://astral.sh/uv/install.sh | sh" ;;
    *)             echo "sudo apt install $1 (Debian/Ubuntu) or sudo dnf install $1 (Fedora/RHEL)" ;;
  esac
}

# version_at_least HAVE WANT compares dotted versions (major.minor only).
version_at_least() {
  local have_major have_minor want_major want_minor
  IFS=. read -r have_major have_minor _ <<<"$1."
  IFS=. read -r want_major want_minor _ <<<"$2."
  have_minor="${have_minor:-0}"; want_minor="${want_minor:-0}"
  [[ "$have_major" =~ ^[0-9]+$ && "$have_minor" =~ ^[0-9]+$ ]] || return 0  # unparsable: do not block
  (( have_major > want_major || (have_major == want_major && have_minor >= want_minor) ))
}

# ---------------------------------------------------------------------------
# Container engine
# ---------------------------------------------------------------------------
compose_works() { "$1" compose version >/dev/null 2>&1; }

# docker_is_podman succeeds when the docker CLI talks to a Podman API socket.
docker_is_podman() {
  docker version --format '{{range .Server.Components}}{{.Name}} {{end}}' 2>/dev/null | grep -qi podman
}

engine_not_running_hint() {
  case "$1:$OS" in
    podman:Darwin) echo "start the Podman machine: podman machine start (or podman machine init first if none exists)" ;;
    podman:*)      echo "check that Podman works for your user: podman info" ;;
    docker:Darwin) echo "start Docker Desktop" ;;
    docker:*)      echo "start the Docker daemon (sudo systemctl start docker) and make sure your user is in the docker group" ;;
  esac
}

compose_hint() {
  case "$1:$OS" in
    docker:Darwin) echo "Docker Desktop ships Compose v2; reinstall it, or brew install docker-compose and add /opt/homebrew/lib/docker/cli-plugins to cliPluginsExtraDirs in ~/.docker/config.json" ;;
    docker:*)      echo "install the Compose v2 plugin: sudo apt install docker-compose-plugin (or sudo dnf install docker-compose-plugin)" ;;
    podman:Darwin) echo "install a compose provider for podman compose: brew install docker-compose (v2.24+)" ;;
    podman:*)      echo "install a compose provider for podman compose: docker-compose v2.24+ (https://docs.docker.com/compose/install/standalone/)" ;;
  esac
}

# detect_engine sets ENGINE, or records problems explaining what is missing.
detect_engine() {
  if [[ -n "${ENGINE:-}" ]]; then
    ENGINE="$(printf '%s' "$ENGINE" | tr '[:upper:]' '[:lower:]')"
    case "$ENGINE" in
      docker|podman) ;;
      *) problem "unsupported ENGINE=$ENGINE (expected docker or podman)"; ENGINE=""; return ;;
    esac
    if ! have "$ENGINE"; then
      problem "ENGINE=$ENGINE but $ENGINE is not installed (or unset ENGINE to detect the engine)"
      ENGINE=""; return
    fi
    if ! compose_works "$ENGINE"; then
      problem "'$ENGINE compose version' fails: $(compose_hint "$ENGINE")"
      ENGINE=""; return
    fi
    if [[ "$ENGINE" == "docker" ]] && docker_is_podman; then
      warn "the docker CLI talks to Podman, but ENGINE=docker skips the Podman settings; use ENGINE=podman if the stack does not come up"
    fi
    info "Container engine: $ENGINE (from ENGINE)"
    return
  fi

  if have docker && compose_works docker && ! docker_is_podman; then
    ENGINE=docker
  elif have podman && compose_works podman; then
    ENGINE=podman
  elif have docker && compose_works docker; then
    # docker is backed by Podman but `podman compose` is unusable: running with
    # ENGINE=docker would skip the Podman overlay and fail later.
    problem "the docker CLI talks to Podman, so the stack needs ENGINE=podman, but 'podman compose version' fails: $(compose_hint podman)"
  elif have docker && have podman; then
    problem "docker and podman are installed, but neither 'docker compose version' nor 'podman compose version' works. Docker: $(compose_hint docker). Podman: $(compose_hint podman)"
  elif have docker; then
    problem "docker is installed but 'docker compose version' fails: $(compose_hint docker)"
  elif have podman; then
    problem "podman is installed but 'podman compose version' fails: $(compose_hint podman)"
  else
    problem "no container engine found: install Docker or Podman (see \"Getting started\" in README.md)"
  fi

  if [[ -n "${ENGINE:-}" ]]; then
    info "Container engine: $ENGINE (detected)"
  else
    ENGINE=""
  fi
}

# check_engine_running records a problem when the selected engine cannot run
# containers (Docker daemon stopped, Podman machine not started).
check_engine_running() {
  [[ -n "${ENGINE:-}" ]] || return 0
  "$ENGINE" info >/dev/null 2>&1 || problem "$ENGINE is installed but not running: $(engine_not_running_hint "$ENGINE")"

  local version
  version="$("$ENGINE" compose version --short 2>/dev/null | tail -n 1 | sed 's/^v//')"
  if [[ -n "$version" ]] && ! version_at_least "$version" "2.24"; then
    problem "$ENGINE compose $version is too old (v2.24+ needed for !override and up --wait): $(compose_hint "$ENGINE")"
  fi
}

# ---------------------------------------------------------------------------
# Other prerequisites
# ---------------------------------------------------------------------------
check_submodules() {
  if [[ ! -f "$SERVER_DIR/bootstrap/zitadel/bootstrap.sh" ]]; then
    if [[ -n "${CITIUS_SERVER_DIR:-}" ]]; then
      problem "CITIUS_SERVER_DIR=$CITIUS_SERVER_DIR is not a citius-server checkout (no bootstrap/zitadel/bootstrap.sh)"
    else
      problem "the citius-server submodule is missing or not checked out: run 'git submodule update --init citius-server' in $ROOT_DIR (reset it with 'git submodule deinit -f citius-server && git submodule update --init citius-server')"
    fi
  fi
  if [[ ! -f "$SDK_DIR/pyproject.toml" ]]; then
    problem "the citius-python-sdk submodule is missing or not checked out: run 'git submodule update --init citius-python-sdk' in $ROOT_DIR"
  fi
}

check_tools() {
  local tool
  for tool in git curl jq go mkcert uv; do
    have "$tool" || problem "$tool is not installed: $(install_hint "$tool")"
  done

  if have go; then
    local go_version
    go_version="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [[ -n "$go_version" ]] && ! version_at_least "$go_version" "1.26"; then
      warn "Go $go_version found; Go 1.26+ is expected. Go may download a newer toolchain, or upgrade: $(install_hint go)"
    fi
  fi

  if have mkcert; then check_mkcert_ca; fi
}

# check_mkcert_ca records a problem when the mkcert root CA does not exist or
# is not trusted by the system (setup-auth verifies Zitadel's certificate).
check_mkcert_ca() {
  local caroot ca
  caroot="$(mkcert -CAROOT 2>/dev/null || true)"
  ca="$caroot/rootCA.pem"
  if [[ -z "$caroot" || ! -s "$ca" ]]; then
    problem "the mkcert local CA does not exist: run 'mkcert -install'"
    return
  fi
  case "$OS" in
    Darwin)
      security verify-cert -c "$ca" >/dev/null 2>&1 \
        || problem "the mkcert local CA is not trusted by macOS: run 'mkcert -install'"
      ;;
    *)
      local anchor found=0
      for anchor in /usr/local/share/ca-certificates/mkcert* \
                    /etc/pki/ca-trust/source/anchors/mkcert* \
                    /etc/ca-certificates/trust-source/anchors/mkcert*; do
        if [[ -e "$anchor" ]]; then found=1; break; fi
      done
      (( found )) || problem "the mkcert local CA is not in the system trust store: run 'mkcert -install'"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
# env_value FILE VAR prints VAR's value from a dotenv FILE, without sourcing it.
env_value() {
  local line
  line="$(grep -E "^$2=" "$1" 2>/dev/null | tail -n 1 || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  printf '%s' "$line"
}

print_summary() {
  local z="$SERVER_DIR/bootstrap/zitadel"
  local stack="$z/citius-stack.json" ui_auth="$z/citius-ui-auth.json"
  local env_file="$z/.env" acl="$z/acl.yaml"

  local endpoint server_name issuer redirect ui_url
  endpoint="$(jq -r '.citius_server.endpoint // empty' "$stack")"
  server_name="$(jq -r '.citius_server.tls_server_name // empty' "$stack")"
  issuer="$(jq -r '.zitadel.issuer // empty' "$stack")"
  redirect="$(jq -r '.web_app.redirect_uris[0] // empty' "$ui_auth")"
  ui_url="${redirect%/auth/callback}"
  ui_url="${ui_url:-http://127.0.0.1:7861}"

  info ""
  info "Citius stack is up"
  info ""
  info "  citius-server (gRPC, TLS):  $endpoint  (TLS server name: $server_name)"
  info "  Zitadel issuer:             $issuer"
  info "  Citius UI (open this):      $ui_url/login"
  info ""

  # Human demo users: username -> password_env from acl.yaml, the password from
  # .env, and the login name from citius-ui-auth.json when it is recorded there.
  local rows=() user var login password
  local w_user=8 w_login=10 w_password=8
  while read -r user var; do
    [[ -n "$user" && -n "$var" ]] || continue
    login="$(jq -r --arg u "$user" '.demo_users[$u].login_name // empty' "$ui_auth" 2>/dev/null || true)"
    login="${login:-$user}"
    password="$(env_value "$env_file" "$var")"
    password="${password:-<unset: $var in $env_file>}"
    rows+=("$user"$'\t'"$login"$'\t'"$password")
    if (( ${#user} > w_user )); then w_user=${#user}; fi
    if (( ${#login} > w_login )); then w_login=${#login}; fi
    if (( ${#password} > w_password )); then w_password=${#password}; fi
  done < <(awk '
    /^  - username:/        { user = $3 }
    /^    password_env:/    { print user, $2 }
  ' "$acl")

  if (( ${#rows[@]} == 0 )); then
    warn "no demo users with a password found in $acl"
    return
  fi

  # Show the login name column only when a login name differs from its username.
  local show_login=0 row
  for row in "${rows[@]}"; do
    IFS=$'\t' read -r user login password <<<"$row"
    if [[ "$login" != "$user" ]]; then show_login=1; fi
  done

  local dash_user dash_login dash_password sep header
  dash_user="$(printf '%*s' "$w_user" '' | tr ' ' -)"
  dash_login="$(printf '%*s' "$w_login" '' | tr ' ' -)"
  dash_password="$(printf '%*s' "$w_password" '' | tr ' ' -)"
  if (( show_login )); then
    sep="+-$dash_user-+-$dash_login-+-$dash_password-+"
    header="$(printf '| %-*s | %-*s | %-*s |' "$w_user" "Username" "$w_login" "Login name" "$w_password" "Password")"
  else
    sep="+-$dash_user-+-$dash_password-+"
    header="$(printf '| %-*s | %-*s |' "$w_user" "Username" "$w_password" "Password")"
  fi

  info "  Demo users (sign in at $ui_url/login)"
  info "  $sep"
  info "  $header"
  info "  $sep"
  for row in "${rows[@]}"; do
    IFS=$'\t' read -r user login password <<<"$row"
    if (( show_login )); then
      info "$(printf '  | %-*s | %-*s | %-*s |' "$w_user" "$user" "$w_login" "$login" "$w_password" "$password")"
    else
      info "$(printf '  | %-*s | %-*s |' "$w_user" "$user" "$w_password" "$password")"
    fi
  done
  info "  $sep"
  info ""
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
server_make() {
  ENGINE="$ENGINE" make -C "$SERVER_DIR" --no-print-directory "$@"
}

cmd_start() {
  info "Checking prerequisites"
  check_submodules
  detect_engine
  check_engine_running
  check_tools
  report_problems_and_exit_if_any

  local smoke=1
  if ! have openssl; then
    smoke=0
    warn "smoke test skipped because openssl is not available; install it to have it run: $(install_hint openssl)"
  fi

  info ""
  info "Starting Zitadel and citius-server with $ENGINE (the first start pulls images and builds the server)"
  server_make zitadel-up-server

  if (( smoke )); then
    info ""
    info "Running the smoke test"
    if ! "$SERVER_DIR/bootstrap/zitadel/smoke-test.sh"; then
      error "the smoke test failed; see the output above. The UI is started anyway."
    fi
  fi

  print_summary

  info "Starting the UI (Ctrl+C stops the UI; 'make stop' stops the stack)"
  CITIUS_SERVER_DIR="$SERVER_DIR" exec "$ROOT_DIR/start-citius-ui.sh"
}

# stack_command TARGET runs a citius-server make target that only needs the
# container engine (stop / reset).
stack_command() {
  check_submodules
  detect_engine
  check_engine_running
  report_problems_and_exit_if_any
  server_make "$1"
}

cmd_stop() {
  info "Stopping the stack (data is kept); stop the UI with Ctrl+C in its terminal"
  stack_command zitadel-down
}

cmd_reset() {
  info "Resetting the stack: wiping data volumes, generated config and .env"
  stack_command zitadel-nuke
  info "Done. 'make start' provisions a fresh stack with new secrets."
}

cmd_check() {
  check_submodules
  detect_engine
  check_engine_running
  check_tools
  have openssl || warn "openssl is not available: the smoke test will be skipped ($(install_hint openssl))"
  report_problems_and_exit_if_any
  info "All prerequisites found"
}

case "${1:-}" in
  check) cmd_check ;;
  start) cmd_start ;;
  stop)  cmd_stop ;;
  reset) cmd_reset ;;
  *)     error "usage: $0 check|start|stop|reset"; exit 2 ;;
esac
