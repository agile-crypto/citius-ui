"""FastAPI host mounting Gradio behind a server-side session.

Development sign-in seeds a persona identity and, optionally, a pasted bearer
token. Production interactive login through hosted Authorization Code with PKCE
replaces this dev sign-in in a later phase. Tokens live only in the server-side
session store and are never written to the browser or logs.
"""

from __future__ import annotations

import time
from typing import Annotated

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
    load_oidc_config,
)
from citius_ui.auth.sessions import Session, SessionStore
from citius_ui.config import AppConfig
from citius_ui.history.memory_store import MemoryHistoryStore
from citius_ui.workbench.app import build_workbench

_PENDING_LOGIN_TTL_SECONDS = 600.0


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
    except (OSError, ValueError):
        oidc_config = None
    pending_logins: dict[str, tuple[PkceChallenge, float]] = {}

    def _prune_pending() -> None:
        cutoff = time.monotonic() - _PENDING_LOGIN_TTL_SECONDS
        for state in [state for state, (_, created) in pending_logins.items() if created < cutoff]:
            pending_logins.pop(state, None)

    def current_session(request: Request) -> Session | None:
        return sessions.get(request.cookies.get(config.session_cookie_name))

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

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        session = current_session(request)
        if session is None:
            return HTMLResponse(_login_page())
        return HTMLResponse(_identity_page(session))

    @app.post("/dev-login")
    async def dev_login(
        persona: Annotated[str, Form()],
        access_token: Annotated[str, Form()] = "",
    ) -> Response:
        definition = get_persona(persona)
        if definition is None:
            return JSONResponse(
                {"error": f"unknown persona {persona!r}"},
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        session = sessions.create(
            subject=definition.username,
            display_name=definition.display_name,
            access_token=access_token.strip(),
            endpoint=config.citius_endpoint,
            permissions=definition.permissions,
            key_allow=definition.key_allow,
            key_deny=definition.key_deny,
        )
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        _set_session_cookie(response, config, session.id)
        return response

    @app.get("/login")
    async def login() -> Response:
        if oidc_config is None:
            return JSONResponse(
                {"error": "OIDC is not configured; use development sign-in"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        _prune_pending()
        pkce = create_pkce_challenge()
        pending_logins[pkce.state] = (pkce, time.monotonic())
        return RedirectResponse(
            url=authorization_url(oidc_config, pkce),
            status_code=status.HTTP_303_SEE_OTHER,
        )

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
        pkce, _ = entry
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                tokens = await exchange_code(client, oidc_config, code=code, code_verifier=pkce.verifier)
        except OIDCError:
            return JSONResponse({"error": "token exchange failed"}, status_code=status.HTTP_401_UNAUTHORIZED)
        session = sessions.create(
            subject="",
            display_name="",
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            id_token=tokens.id_token,
            ttl_seconds=tokens.expires_in,
            endpoint=config.citius_endpoint,
        )
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
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

    workbench = build_workbench(config, sessions, history)
    gr.mount_gradio_app(app, workbench, path="/workbench", auth_dependency=auth_dependency)
    return app


_PAGE_STYLE = """
<style>
  :root { color-scheme: light; }
  body { font-family: 'IBM Plex Sans', Arial, sans-serif; background: #eef2fb;
         margin: 0; padding: 40px 16px; color: #17233b; }
  .card { max-width: 560px; margin: 0 auto; background: #ffffff; border-radius: 12px;
          box-shadow: 0 6px 20px rgba(0,0,0,.08); overflow: hidden; }
  .banner { background: #a4c2f4; padding: 28px 32px; }
  .banner h1 { margin: 0 0 6px; font-size: 1.9rem; }
  .banner p { margin: 0; color: #263a5d; }
  .body { padding: 24px 32px; }
  label { display: block; margin: 14px 0 6px; font-weight: 600; }
  select, input { width: 100%; padding: 10px; border: 1px solid #c3cbe0;
                  border-radius: 8px; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 20px; padding: 10px 18px; border: 0; border-radius: 8px;
           background: #6d83f2; color: #fff; font-size: 1rem; cursor: pointer; }
  button.secondary { background: #7a869a; }
  a.action { display: inline-block; margin: 8px 0; color: #3b52c4; font-weight: 600; }
  ul { padding-left: 20px; } li { margin: 2px 0; }
  .muted { color: #5b6b8c; font-size: .9rem; }
</style>
"""


def _login_page() -> str:
    options = "".join(
        f'<option value="{key}">{persona.display_name}</option>' for key, persona in DEMO_PERSONAS.items()
    )
    return f"""<!doctype html><html><head><title>Citius Console</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <div class="banner"><h1>Citius Console</h1>
    <p>Development sign-in. One identity per browser session.</p></div>
  <div class="body">
    <form method="post" action="/dev-login">
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
    permissions = "".join(f"<li>{perm}</li>" for perm in view["permissions"])
    return f"""<!doctype html><html><head><title>Citius Console</title>{_PAGE_STYLE}</head>
<body>
<div class="card">
  <div class="banner"><h1>Signed in as {view["display_name"]}</h1>
    <p>{view["subject"]} · endpoint {view["endpoint"]}</p></div>
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

    config = AppConfig.from_env()
    uvicorn.run(build_app(config), host=config.ui_host, port=config.ui_port)


if __name__ == "__main__":
    main()
