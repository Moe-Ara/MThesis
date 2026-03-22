from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .routes import router
from ..application.container import build_container


def create_app() -> FastAPI:
    base_dir = Path(__file__).resolve().parents[1]
    data_dir = base_dir / "data"

    app = FastAPI(title="Reasoning SIEM", version="1.0.0")
    app.state.services = build_container(data_dir)
    app.state.templates = Jinja2Templates(directory=str(base_dir / "ui" / "templates"))

    app.mount(
        "/static",
        StaticFiles(directory=str(base_dir / "ui" / "static")),
        name="static",
    )
    app.include_router(router)
    return app


app = create_app()


