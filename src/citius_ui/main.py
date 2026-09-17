"""FastAPI host mounting Gradio behind a server-side session.

Development sign-in seeds a persona identity and, optionally, a pasted bearer
token. Production interactive login through hosted Authorization Code with PKCE
replaces this dev sign-in in a later phase. Tokens live only in the server-side
session store and are never written to the browser or logs.
"""

from __future__ import annotations

from typing import Annotated

import gradio as gr
from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from citius_ui.auth.demo_personas import DEMO_PERSONAS, get_persona
from citius_ui.auth.sessions import Session, SessionStore
from citius_ui.config import AppConfig


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
    app = FastAPI(title="Citius Console")
    app.state.config = config
    app.state.sessions = sessions

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

    @app.get("/identity")
    async def identity(request: Request) -> JSONResponse:
        session = current_session(request)
        if session is None:
            return JSONResponse({"authenticated": False}, status_code=status.HTTP_401_UNAUTHORIZED)
        return JSONResponse(session.public_view())

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        sessions.delete(request.cookies.get(config.session_cookie_name))
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        _clear_session_cookie(response, config)
        return response

    def auth_dependency(request: gr.Request) -> str | None:
        cookie = request.cookies.get(config.session_cookie_name)
        session = sessions.get(cookie)
        return session.subject if session else None

    workbench = _build_workbench_placeholder()
    gr.mount_gradio_app(app, workbench, path="/workbench", auth_dependency=auth_dependency)
    return app


def _login_page() -> str:
    options = "".join(
        f'<option value="{key}">{persona.display_name}</option>' for key, persona in DEMO_PERSONAS.items()
    )
    return f"""<!doctype html><html><head><title>Citius Console</title></head>
<body>
<h1>Citius Console</h1>
<p>Development sign-in. One identity per browser session.</p>
<form method="post" action="/dev-login">
  <label>Persona
    <select name="persona">{options}</select>
  </label>
  <label>Access token (optional, local development)
    <input type="password" name="access_token" autocomplete="off" />
  </label>
  <button type="submit">Sign in</button>
</form>
</body></html>"""


def _identity_page(session: Session) -> str:
    view = session.public_view()
    permissions = "".join(f"<li>{perm}</li>" for perm in view["permissions"])
    return f"""<!doctype html><html><head><title>Citius Console</title></head>
<body>
<h1>Signed in as {view["display_name"]}</h1>
<p>Subject: {view["subject"]}</p>
<p>Endpoint: {view["endpoint"]}</p>
<ul>{permissions}</ul>
<p><a href="/workbench">Open the Workbench</a></p>
<form method="post" action="/logout"><button type="submit">Log out</button></form>
</body></html>"""


def _build_workbench_placeholder() -> gr.Blocks:
    with gr.Blocks(title="Citius Workbench") as blocks:
        gr.Markdown("# Citius API Workbench\nAuthenticated session active.")
    return blocks


def main() -> None:
    import uvicorn

    config = AppConfig.from_env()
    uvicorn.run(build_app(config), host=config.ui_host, port=config.ui_port)


if __name__ == "__main__":
    main()
