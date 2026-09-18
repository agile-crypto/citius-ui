# Phase 7 — Browser end-to-end login runbook

This runbook verifies the production-style Zitadel Authorization Code + PKCE
login against a **live** Zitadel for the three demo personas. It complements the
automated unit tests (`tests/test_oidc.py`, `tests/test_id_token.py`,
`tests/test_sessions.py`, `tests/test_main.py`) which cover PKCE construction,
ID-token signature/issuer/audience/nonce/expiry validation, refresh scheduling,
and the callback wiring against mocked endpoints.

The final password step uses each persona's secret password and therefore must
be completed by a human at the Zitadel hosted-login screen. Do not paste demo
passwords into scripts, logs, or chat.

## Prerequisites

1. The unified local stack is up (see `README.md` → "Local test stack"):

   ```bash
   export CITIUS_SERVER_DIR=/path/to/citius-server
   ( cd "$CITIUS_SERVER_DIR" && CITIUS_SERVER=1 make zitadel-up )
   "$CITIUS_SERVER_DIR"/bootstrap/zitadel/smoke-test.sh
   ```

2. The demo user passwords are set in `"$CITIUS_SERVER_DIR"/bootstrap/zitadel/.env`
   (auto-generated on a clean `up`, or supplied via the documented env vars).
   Retrieve a persona password for manual entry with, e.g.:

   ```bash
   grep '^CITIUS_DEMO_CISO_PASSWORD=' "$CITIUS_SERVER_DIR"/bootstrap/zitadel/.env
   ```

3. The UI must listen on the port that matches the OIDC redirect URI registered
   in `citius-ui-auth.json` (`web_app.redirect_uris[0]`, e.g.
   `http://127.0.0.1:7861/auth/callback`). The simplest way is the launcher,
   which derives the port and all TLS/OIDC settings from the emitted config:

   ```bash
   CITIUS_SERVER_DIR="$CITIUS_SERVER_DIR" ./start-citius-ui.sh
   ```

   Or wire it manually:

   ```bash
   Z="$CITIUS_SERVER_DIR/bootstrap/zitadel"
   stack="$Z/citius-stack.json"
   CITIUS_UI_HOST=127.0.0.1 CITIUS_UI_PORT=7861 \
   CITIUS_SESSION_COOKIE_SECURE=false \
   CITIUS_ENDPOINT="$(jq -r .citius_server.endpoint "$stack")" \
   CITIUS_TLS_ENABLED=true \
   CITIUS_TLS_CA="$(jq -r .citius_server.tls_ca "$stack")" \
   CITIUS_TLS_SERVER_NAME="$(jq -r .citius_server.tls_server_name "$stack")" \
   CITIUS_OIDC_CONFIG_PATH="$Z/citius-ui-auth.json" \
   CITIUS_OIDC_CA_CERT="$(jq -r .citius_server.tls_ca "$stack")" \
   uv run citius-ui
   ```

   `CITIUS_OIDC_CA_CERT` lets the UI trust the local mkcert CA when exchanging
   the auth code and fetching the Zitadel JWKS to verify ID-token signatures. It
   defaults to `CITIUS_TLS_CA` when unset; without a CA the callback returns 401.

## Per-persona verification

Run each persona in a **separate browser profile** (or private window) so
cookies, sessions, and histories stay isolated. One browser session holds
exactly one identity; switching users requires logout.

| Persona | Login name | Password env var |
|---|---|---|
| CISO | `citius-ciso` | `CITIUS_DEMO_CISO_PASSWORD` |
| Producer | `citius-producer` | `CITIUS_DEMO_PRODUCER_PASSWORD` |
| Consumer | `citius-consumer` | `CITIUS_DEMO_CONSUMER_PASSWORD` |

Steps (repeat per persona):

1. Open `http://127.0.0.1:7861/login`. The UI generates PKCE + state + nonce and
   redirects the browser to the Zitadel hosted login
   (`https://<issuer>/ui/v2/login/...`).
2. Enter the persona login name and continue. Zitadel resolves the provisioned
   user and shows the password screen.
3. Enter the persona password **manually** and continue.
4. Zitadel redirects back to `/auth/callback?code=...&state=...`. The UI:
   - validates `state` against the pending login,
   - exchanges the code for tokens using the PKCE verifier (no client secret),
   - verifies the ID token's signature (JWKS), issuer, audience, nonce, and
     expiry,
   - creates a server-side session and sets an opaque, HTTP-only cookie.
5. The browser lands on `/`. Confirm the identity page and `GET /identity` show
   the persona's subject/display name and **no raw tokens**.
6. Open `/workbench` and confirm the persona can exercise its allowed RPCs and
   receives `PERMISSION_DENIED` for excluded ones:
   - CISO: create/read a `demo-*` policy and key; excluded from sign/verify.
   - Producer: create key, sign, encrypt under `demo-*`; denied verify/decrypt.
   - Consumer: verify/decrypt a copied bundle; denied sign/encrypt/key-create.
   - Producer/Consumer: denied on `demo-restricted-*` even for a granted method.
7. Log out via the workbench "Log out" control. Confirm the session cookie is
   cleared and, when an ID token is present, the browser is redirected through
   Zitadel end-session logout.

## Isolation checks

- Log in as all three personas in three profiles concurrently; confirm each
  `/identity` reports only its own subject and each history is separate.
- After logout, confirm the prior access/refresh token is not reused and cannot
  be substituted into another browser session.

## What the automated tests already cover (no live Zitadel needed)

- PKCE S256 challenge, authorization URL, and `offline_access` gating.
- `exchange_code`/`refresh_tokens` request shape and error mapping.
- ID-token validation: valid token → identity; rejects bad nonce, wrong issuer,
  wrong audience, expired token, and wrong signature.
- Callback wiring: valid ID token creates an identity-bearing session; invalid
  ID token returns 401 and sets no cookie.
- Proactive refresh: refresh near expiry, skip when fresh, serialize concurrent
  refreshes, and fall back to the current token on refresh failure.
- Federated logout URL construction.

## Verified against the live stack (2026-09-18)

- `GET /login` redirected the browser to the real Zitadel hosted login with a
  valid PKCE `requestId`.
- Zitadel resolved the provisioned `citius-ciso` user (organization id present)
  and presented the password screen — proving the OIDC Web app, redirect URI,
  and demo user provisioning are consistent end to end.
- The UI's JWKS-based validation path fetched and parsed the live issuer's
  signing keys over TLS using the emitted CA.
- The password submission and post-callback session assertions are completed
  manually as described above.
