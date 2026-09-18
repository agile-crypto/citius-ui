#!/usr/bin/env bash
# start-citius-ui.sh — launch the Citius Console UI against a local stack.
#
# Derives all connection settings from the non-secret config emitted by the
# citius-server bootstrap (`CITIUS_SERVER=1 make zitadel-up`):
#   - citius-stack.json  → gRPC endpoint, TLS CA, TLS server name
#   - citius-ui-auth.json → OIDC issuer/client + the registered redirect URI,
#                           from which the UI listen port is derived so the
#                           hosted-login callback matches.
#
# citius-server, citius-ui, and the SDKs are INDEPENDENT repositories. Point
# CITIUS_SERVER_DIR at your citius-server checkout (defaults to the sibling
# ../citius-server only when it exists).
#
# Usage:
#   ./start-citius-ui.sh
#   CITIUS_SERVER_DIR=/path/to/citius-server ./start-citius-ui.sh
#   CITIUS_UI_PORT=7861 ./start-citius-ui.sh      # override derived port
#
# Env overrides: CITIUS_SERVER_DIR, CITIUS_UI_HOST, CITIUS_UI_PORT,
#                CITIUS_SESSION_COOKIE_SECURE.
set -euo pipefail

log()  { printf '\033[1;34m[start-ui]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[start-ui]\033[0m %s\n' "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq is required (install jq and retry)"
command -v uv >/dev/null 2>&1 || die "uv is required (https://docs.astral.sh/uv/)"

# Resolve this script's directory so it works regardless of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Locate the citius-server checkout (independent repo).
default_server_dir="$(cd "$SCRIPT_DIR/../citius-server" 2>/dev/null && pwd || true)"
CITIUS_SERVER_DIR="${CITIUS_SERVER_DIR:-$default_server_dir}"
[[ -n "$CITIUS_SERVER_DIR" ]] || die "set CITIUS_SERVER_DIR to your citius-server checkout"
[[ -d "$CITIUS_SERVER_DIR" ]] || die "CITIUS_SERVER_DIR does not exist: $CITIUS_SERVER_DIR"

Z="$CITIUS_SERVER_DIR/bootstrap/zitadel"
stack="$Z/citius-stack.json"
ui_auth="$Z/citius-ui-auth.json"

[[ -f "$stack" ]]   || die "missing $stack — run 'CITIUS_SERVER=1 make zitadel-up' in $CITIUS_SERVER_DIR first"
[[ -f "$ui_auth" ]] || die "missing $ui_auth — run the citius-server bootstrap first"

endpoint="$(jq -r '.citius_server.endpoint // empty' "$stack")"
tls_ca="$(jq -r '.citius_server.tls_ca // empty' "$stack")"
tls_server_name="$(jq -r '.citius_server.tls_server_name // empty' "$stack")"
tls_enabled="$(jq -r '.citius_server.tls_enabled // true' "$stack")"

[[ -n "$endpoint" ]] || die "citius_server.endpoint missing in $stack"
if [[ -n "$tls_ca" && ! -f "$tls_ca" ]]; then
  die "TLS CA referenced by $stack does not exist: $tls_ca"
fi

# Derive the UI listen host/port from the registered OIDC redirect URI so the
# hosted-login callback resolves. Falls back to 7861 when parsing fails.
redirect_uri="$(jq -r '.web_app.redirect_uris[0] // empty' "$ui_auth")"
derived_host="127.0.0.1"
derived_port="7861"
if [[ "$redirect_uri" =~ ^https?://([^:/]+):?([0-9]*)/ ]]; then
  derived_host="${BASH_REMATCH[1]}"
  [[ -n "${BASH_REMATCH[2]}" ]] && derived_port="${BASH_REMATCH[2]}"
fi

export CITIUS_UI_HOST="${CITIUS_UI_HOST:-$derived_host}"
export CITIUS_UI_PORT="${CITIUS_UI_PORT:-$derived_port}"
# Local dev over http://127.0.0.1 cannot use Secure cookies.
export CITIUS_SESSION_COOKIE_SECURE="${CITIUS_SESSION_COOKIE_SECURE:-false}"
export CITIUS_ENDPOINT="$endpoint"
export CITIUS_TLS_ENABLED="$tls_enabled"
export CITIUS_OIDC_CONFIG_PATH="$ui_auth"
if [[ -n "$tls_ca" ]]; then
  export CITIUS_TLS_CA="$tls_ca"
  # Trust the same local CA when the UI fetches the Zitadel JWKS / exchanges
  # the auth code over TLS.
  export CITIUS_OIDC_CA_CERT="$tls_ca"
fi
[[ -n "$tls_server_name" ]] && export CITIUS_TLS_SERVER_NAME="$tls_server_name"

if [[ "$redirect_uri" != "http://${CITIUS_UI_HOST}:${CITIUS_UI_PORT}/auth/callback" ]]; then
  log "WARNING: listening on ${CITIUS_UI_HOST}:${CITIUS_UI_PORT} but the registered"
  log "         redirect URI is ${redirect_uri}. Hosted login will fail unless they match."
fi

log "citius-server: $CITIUS_SERVER_DIR"
log "endpoint=$CITIUS_ENDPOINT tls=$CITIUS_TLS_ENABLED server_name=${CITIUS_TLS_SERVER_NAME:-<none>}"
log "oidc_config=$CITIUS_OIDC_CONFIG_PATH ca=${CITIUS_TLS_CA:-<system trust>}"
log "listening on http://${CITIUS_UI_HOST}:${CITIUS_UI_PORT}  (hosted login: /login, dev sign-in: /)"

cd "$SCRIPT_DIR"
exec uv run citius-ui
