from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from pkica.web.routes import router

WEB_DIR = Path(__file__).resolve().parent

app = FastAPI(title="pkica web")
app.include_router(router)
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")


def main() -> None:
    uvicorn.run("pkica.web.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
