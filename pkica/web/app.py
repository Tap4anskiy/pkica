from __future__ import annotations

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from pkica.services.auth_service import SESSION_COOKIE, verify_session_cookie
from pkica.web.routes import router

WEB_DIR = Path(__file__).resolve().parent

app = FastAPI(title="pkica web")
app.include_router(router)
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")


def is_public_path(path: str) -> bool:
    return (
        path == "/"
        or path == "/trust"
        or path.startswith("/trust/download/")
        or path == "/admin/login"
        or path.startswith("/static/")
    )


@app.middleware("http")
async def admin_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/admin") and not is_public_path(path):
        if not verify_session_cookie(request.cookies.get(SESSION_COOKIE)):
            login_url = "/admin/login"
            if request.method in {"GET", "HEAD"}:
                login_url = f"{login_url}?next={path}"
            return RedirectResponse(login_url, status_code=303)
    return await call_next(request)


def main() -> None:
    uvicorn.run("pkica.web.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
