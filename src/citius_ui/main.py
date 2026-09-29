"""FastAPI host mounting Gradio behind a server-side session.

Development sign-in seeds a persona identity and, optionally, a pasted bearer
token. Production interactive login through hosted Authorization Code with PKCE
replaces this dev sign-in in a later phase. Tokens live only in the server-side
session store and are never written to the browser or logs.
"""

from __future__ import annotations

import html
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated
from urllib.parse import urlencode, urlsplit

import gradio as gr
import httpx
from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from citius_ui.auth.demo_personas import DEMO_PERSONAS, get_persona
from citius_ui.auth.oidc import (
    OIDCConfig,
    OIDCError,
    PkceChallenge,
    authorization_url,
    create_pkce_challenge,
    end_session_url,
    exchange_code,
    extract_grants,
    fetch_userinfo,
    load_oidc_config,
    refine_identity,
    refresh_tokens,
    validate_id_token,
)
from citius_ui.auth.sessions import RefreshedTokens, Session, SessionStore
from citius_ui.config import AppConfig
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.workbench.app import build_workbench

_PENDING_LOGIN_TTL_SECONDS = 600.0
_log = logging.getLogger("citius_ui.auth")

# The only paths open without a session: signing in and out, the probes a
# container platform calls, and /identity, which answers 401 itself. Every
# other path, including any added later, needs a session.
_PUBLIC_PATHS = frozenset(
    {"/", "/dev-login", "/login", "/auth/callback", "/logout", "/healthz", "/readyz", "/identity"}
)
_MAX_NEXT_LENGTH = 2048


def safe_next(value: str | None) -> str | None:
    """``value`` if it is a path on this site, else None.

    The return address after sign-in comes from the URL, so it must never
    lead to another site: no scheme, no host, no protocol-relative ``//``,
    no backslash (browsers read ``/\\host`` as a host), no control characters.
    """
    if not value or len(value) > _MAX_NEXT_LENGTH:
        return None
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return None
    return value


def _wants_page(request: Request) -> bool:
    """Whether a person is opening a page, rather than a script or the page calling the server."""
    return request.method in ("GET", "HEAD") and "text/html" in request.headers.get("accept", "")


def _set_session_cookie(response: Response, config: AppConfig, session_id: str) -> None:
    response.set_cookie(
        key=config.session_cookie_name,
        value=session_id,
        httponly=True,
        secure=config.session_cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response, config: AppConfig) -> None:
    response.delete_cookie(key=config.session_cookie_name, path="/")


def build_app(config: AppConfig | None = None, *, store: SessionStore | None = None) -> FastAPI:
    config = config or AppConfig.from_env()
    sessions = store or SessionStore()
    history = MemoryHistoryStore(limit=config.history_limit)
    app = FastAPI(title="Citius Console")
    app.state.config = config
    app.state.sessions = sessions
    app.state.history = history

    oidc_config: OIDCConfig | None = None
    try:
        oidc_config = load_oidc_config(config.oidc_config_path)
    except (OSError, ValueError) as exc:
        oidc_config = None
        _log.warning(
            "Hosted OIDC login disabled: could not load %s (%s). "
            "/login will return 503; only development sign-in is available.",
            config.oidc_config_path,
            exc,
        )
    if oidc_config is not None:
        ca = config.effective_oidc_ca
        if ca is None:
            _log.warning(
                "OIDC configured for issuer %s but no CA is set "
                "(CITIUS_OIDC_CA_CERT / CITIUS_TLS_CA). If the issuer uses a "
                "local mkcert certificate, the token exchange and JWKS fetch "
                "will fail TLS verification and /auth/callback will return 401.",
                oidc_config.issuer,
            )
        else:
            _log.info(
                "Hosted OIDC login enabled: issuer=%s redirect_uri=%s ca=%s",
                oidc_config.issuer,
                oidc_config.redirect_uri,
                ca,
            )
    pending_logins: dict[str, tuple[PkceChallenge, float, str | None]] = {}

    def _oidc_http_client() -> httpx.AsyncClient:
        """HTTP client for OIDC token/refresh calls, trusting the issuer CA.

        The token and refresh endpoints are served by Zitadel over TLS. In local
        development that certificate is signed by the mkcert root, which is not
        in the system trust store, so the configured OIDC CA is used to verify
        it. When no CA is configured, httpx falls back to the system trust store.
        """
        ca = config.effective_oidc_ca
        verify: str | bool = str(ca) if ca else True
        return httpx.AsyncClient(timeout=10.0, verify=verify)

    def _prune_pending() -> None:
        cutoff = time.monotonic() - _PENDING_LOGIN_TTL_SECONDS
        for state in [state for state, (_, created, _) in pending_logins.items() if created < cutoff]:
            pending_logins.pop(state, None)

    def current_session(request: Request) -> Session | None:
        return sessions.get(request.cookies.get(config.session_cookie_name))

    @app.middleware("http")
    async def require_session(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Send a person without a session to sign-in, and refuse everyone else.

        Sessions live in this process, so after a restart the browser's cookie
        names none: it is cleared, and the page asked for becomes the return
        address. Pages are never cached, so the back button cannot show one
        that looks signed in when it is not.
        """
        path = request.url.path
        if path not in _PUBLIC_PATHS and current_session(request) is None:
            denied: Response
            if _wants_page(request):
                target = f"{path}?{request.url.query}" if request.url.query else path
                destination = "/"
                if safe_next(target):
                    destination = f"/?{urlencode({'next': target})}"
                denied = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
            else:
                denied = JSONResponse({"error": "not signed in"}, status_code=status.HTTP_401_UNAUTHORIZED)
            if request.cookies.get(config.session_cookie_name):
                _clear_session_cookie(denied, config)
            return denied
        response = await call_next(request)
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict[str, object]:
        return {
            "status": "ready",
            "endpoint": config.citius_endpoint,
            "tls": config.citius_tls_enabled,
        }

    def _start_hosted_login(next_path: str | None = None) -> RedirectResponse:
        assert oidc_config is not None
        _prune_pending()
        pkce = create_pkce_challenge()
        pending_logins[pkce.state] = (pkce, time.monotonic(), next_path)
        return RedirectResponse(
            url=authorization_url(oidc_config, pkce),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/")
    async def index(request: Request) -> Response:
        next_path = safe_next(request.query_params.get("next"))
        session = current_session(request)
        if session is not None:
            if next_path is not None:
                return RedirectResponse(url=next_path, status_code=status.HTTP_303_SEE_OTHER)
            return HTMLResponse(_identity_page(session))
        if oidc_config is not None:
            return _start_hosted_login(next_path)
        return HTMLResponse(_login_page(next_path))

    @app.get("/dev-login", response_class=HTMLResponse)
    async def dev_login_page(request: Request) -> HTMLResponse:
        return HTMLResponse(_login_page(safe_next(request.query_params.get("next"))))

    @app.post("/dev-login")
    async def dev_login(
        persona: Annotated[str, Form()],
        access_token: Annotated[str, Form()] = "",
        next_path: Annotated[str, Form(alias="next")] = "",
    ) -> Response:
        definition = get_persona(persona.strip())
        if definition is None:
            return JSONResponse(
                {"error": f"unknown persona {persona[:64]!r}"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        access_token = access_token.strip()
        if len(access_token) > 16384:
            return JSONResponse(
                {"error": "access token is too long"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        session = sessions.create(
            subject=definition.username,
            display_name=definition.display_name,
            access_token=access_token,
            endpoint=config.citius_endpoint,
            permissions=definition.permissions,
            key_allow=definition.key_allow,
            key_deny=definition.key_deny,
        )
        response = RedirectResponse(url=safe_next(next_path) or "/", status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookie(response, config, session.id)
        return response

    @app.get("/login")
    async def login(request: Request) -> Response:
        if oidc_config is None:
            return JSONResponse(
                {"error": "OIDC is not configured; use development sign-in"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return _start_hosted_login(safe_next(request.query_params.get("next")))

    @app.get("/auth/callback")
    async def auth_callback(request: Request) -> Response:
        if oidc_config is None:
            return JSONResponse(
                {"error": "OIDC is not configured"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return JSONResponse({"error": "missing code or state"}, status_code=status.HTTP_400_BAD_REQUEST)
        entry = pending_logins.pop(state, None)
        if entry is None:
            return JSONResponse({"error": "invalid or expired state"}, status_code=status.HTTP_400_BAD_REQUEST)
        pkce, _, next_path = entry
        try:
            async with _oidc_http_client() as client:
                tokens = await exchange_code(client, oidc_config, code=code, code_verifier=pkce.verifier)
        except OIDCError as exc:
            _log.warning("OIDC token exchange failed: %s", exc)
            return JSONResponse(
                {"error": "token exchange failed", "detail": str(exc)},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        try:
            identity = validate_id_token(
                tokens.id_token,
                oidc_config,
                nonce=pkce.nonce,
                ca_cert=str(config.effective_oidc_ca) if config.effective_oidc_ca else None,
            )
        except OIDCError as exc:
            # Signature, issuer, audience, nonce, or expiry validation failed.
            _log.warning("OIDC ID-token validation failed: %s", exc)
            return JSONResponse(
                {"error": "id token validation failed", "detail": str(exc)},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        # The Citius token action attaches permissions and key-access patterns
        # on the pre-userinfo trigger, so userinfo is the authoritative claim
        # source; ID-token claims are the fallback when the fetch fails.
        claims: dict[str, object] = dict(identity.claims)
        try:
            async with _oidc_http_client() as client:
                claims.update(await fetch_userinfo(client, oidc_config, access_token=tokens.access_token))
        except OIDCError as exc:
            _log.warning("OIDC userinfo fetch failed; deriving grants from ID-token claims only: %s", exc)
        # Zitadel commonly returns profile claims (name, preferred_username)
        # only via userinfo, not the ID token, so the display name is refined
        # from the same merged claims rather than the ID-token-only identity.
        identity = refine_identity(identity, claims)
        grants = extract_grants(claims)
        if not grants.permissions:
            _log.warning(
                "No Citius permissions found in userinfo or ID-token claims for subject %s; "
                "the workbench will show no granted permissions. Check that the Zitadel "
                "token action is wired to the pre-userinfo trigger and the user has role grants.",
                identity.subject,
            )
        session = sessions.create(
            subject=identity.subject,
            display_name=identity.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            ttl_seconds=tokens.expires_in,
            endpoint=config.citius_endpoint,
            permissions=grants.permissions,
            key_allow=grants.key_allow,
            key_deny=grants.key_deny,
        )
        response = RedirectResponse(url=next_path or "/", status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookie(response, config, session.id)
        return response

    @app.get("/identity")
    async def identity(request: Request) -> JSONResponse:
        session = current_session(request)
        if session is None:
            return JSONResponse({"authenticated": False}, status_code=status.HTTP_401_UNAUTHORIZED)
        return JSONResponse(session.public_view())

    @app.api_route("/logout", methods=["GET", "POST"])
    async def logout(request: Request) -> Response:
        session = current_session(request)
        id_token = session.id_token if session else ""
        sessions.delete(request.cookies.get(config.session_cookie_name))
        destination = "/"
        if oidc_config is not None and id_token:
            destination = end_session_url(oidc_config, id_token=id_token)
        response = RedirectResponse(url=destination, status_code=status.HTTP_303_SEE_OTHER)
        _clear_session_cookie(response, config)
        return response

    def auth_dependency(request: gr.Request) -> str | None:
        cookie = request.cookies.get(config.session_cookie_name)
        session = sessions.get(cookie)
        return session.subject if session else None

    token_provider_factory = sessions.token_provider
    if oidc_config is not None and oidc_config.enable_refresh_tokens:

        async def _refresher(refresh_token: str) -> RefreshedTokens:
            async with _oidc_http_client() as client:
                tokens = await refresh_tokens(client, oidc_config, refresh_token=refresh_token)
            return RefreshedTokens(
                access_token=tokens.access_token,
                refresh_token=tokens.refresh_token,
                expires_in=tokens.expires_in,
            )

        def token_provider_factory(session_id: str):  # type: ignore[misc]
            return sessions.refreshing_token_provider(session_id, refresher=_refresher)

    workbench = build_workbench(config, sessions, history, token_provider_factory=token_provider_factory)
    gr.mount_gradio_app(app, workbench, path="/workbench", auth_dependency=auth_dependency)
    return app


# Light palette on :root with a prefers-color-scheme override, so these plain
# HTML pages follow the OS mode like the Gradio workbench does.
_PAGE_STYLE = """
<style>
  :root {
    color-scheme: light dark;
    --page-bg: #eef2fb; --page-ink: #17233b;
    --card-bg: #ffffff; --card-shadow: rgba(0, 0, 0, .08);
    --banner-bg: #a4c2f4; --banner-ink: #17233b; --banner-sub: #263a5d;
    --field-border: #c3cbe0; --field-bg: #ffffff; --field-ink: #17233b;
    --action: #3b52c4; --accent: #6d83f2; --secondary: #7a869a; --muted: #5b6b8c;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --page-bg: #141927; --page-ink: #dbe2f5;
      --card-bg: #1c2336; --card-shadow: rgba(0, 0, 0, .45);
      --banner-bg: #2b3a63; --banner-ink: #e6ecfb; --banner-sub: #aebbe2;
      --field-border: #3a4666; --field-bg: #232c44; --field-ink: #dbe2f5;
      --action: #9db1f5; --accent: #5b74e8; --secondary: #5c6880; --muted: #8d9bc2;
    }
  }
  body { font-family: 'IBM Plex Sans', Arial, sans-serif; background: var(--page-bg);
         margin: 0; padding: 40px 16px; color: var(--page-ink); }
  .card { max-width: 560px; margin: 0 auto; background: var(--card-bg); border-radius: 12px;
          box-shadow: 0 6px 20px var(--card-shadow); overflow: hidden; }
  .banner { background: var(--banner-bg); padding: 28px 32px; }
  .banner h1 { margin: 0 0 6px; font-size: 1.9rem; color: var(--banner-ink); }
  .banner p { margin: 0; color: var(--banner-sub); }
  .body { padding: 24px 32px; }
  label { display: block; margin: 14px 0 6px; font-weight: 600; }
  select, input { width: 100%; padding: 10px; border: 1px solid var(--field-border);
                  background: var(--field-bg); color: var(--field-ink);
                  border-radius: 8px; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 20px; padding: 10px 18px; border: 0; border-radius: 8px;
           background: var(--accent); color: #fff; font-size: 1rem; cursor: pointer; }
  button.secondary { background: var(--secondary); }
  a.action { display: inline-block; margin: 8px 0; color: var(--action); font-weight: 600; }
  ul { padding-left: 20px; } li { margin: 2px 0; }
  .muted { color: var(--muted); font-size: .9rem; }
</style>
"""


def _login_page(next_path: str | None = None) -> str:
    options = "".join(
        f'<option value="{html.escape(key, quote=True)}">{html.escape(persona.display_name)}</option>'
        for key, persona in DEMO_PERSONAS.items()
    )
    # Where to go after signing in; safe_next has already vetted it.
    return_to = f'<input type="hidden" name="next" value="{html.escape(next_path, quote=True)}" />' if next_path else ""
    return f"""<!doctype html><html><head><title>Citius Console</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <div class="banner"><h1>Citius Console</h1>
    <p>Development sign-in. One identity per browser session.</p></div>
  <div class="body">
    <form method="post" action="/dev-login">{return_to}
      <label for="persona">Persona</label>
      <select id="persona" name="persona">{options}</select>
      <label for="access_token">Access token (optional, local development)</label>
      <input id="access_token" type="password" name="access_token" autocomplete="off" />
      <p class="muted">Tokens are held server-side only and never written to the browser.</p>
      <button type="submit">Sign in</button>
    </form>
  </div>
</div>
</body></html>"""


def _identity_page(session: Session) -> str:
    view = session.public_view()
    # Identity fields originate from external ID-token claims; escape them all.
    permissions = "".join(f"<li>{html.escape(str(perm))}</li>" for perm in view["permissions"])
    if not permissions:
        permissions = '<li class="muted">None granted to this identity.</li>'
    display_name = html.escape(str(view["display_name"]))
    subject = html.escape(str(view["subject"]))
    endpoint = html.escape(str(view["endpoint"] or ""))
    return f"""<!doctype html><html><head><title>Citius Console</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <div class="banner"><h1>Signed in as {display_name}</h1>
    <p>{subject} · endpoint {endpoint}</p></div>
  <div class="body">
    <p><strong>Granted permissions</strong></p>
    <ul>{permissions}</ul>
    <p><a class="action" href="/workbench">Open the Workbench →</a></p>
    <form method="post" action="/logout"><button class="secondary" type="submit">Log out</button></form>
  </div>
</div>
</body></html>"""


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:    %(name)s: %(message)s")
    config = AppConfig.from_env()
    uvicorn.run(build_app(config), host=config.ui_host, port=config.ui_port)


if __name__ == "__main__":
    main()
