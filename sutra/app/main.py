"""The Sutra web application: FastAPI app factory, middleware and error handling."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import migrate
from .analysis import AnalysisStore
from .catalog import sync_catalog
from .config import Settings
from .db import make_engine, make_sessionmaker
from .jobs import Conflict, Forbidden
from .routes import admin, auth, data, jobs, views

STATIC = Path(__file__).resolve().parent.parent / "web" / "static"

# Scripts only from this origin. Inline style attributes are used by the views, so styles allow 'unsafe-inline'.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        migrate.upgrade(settings.database_url)
        with app.state.sessionmaker() as db:
            sync_catalog(db)
            app.state.analysis.load_current(db)
        yield
        app.state.engine.dispose()

    app = FastAPI(title="Sutra", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.sessionmaker = make_sessionmaker(app.state.engine)
    app.state.analysis = AnalysisStore()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # Refuse cross-site state changes even before a session exists (login CSRF).
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("origin")
            if origin and urlsplit(origin).netloc != request.headers.get("host"):
                return JSONResponse({"error": "Cross-origin request refused."}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Holds only the OIDC state and nonce during a sign-in redirect; sessions live in the database.
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="sutra_oidc",
                       max_age=600, same_site="lax", https_only=settings.cookie_secure)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(Forbidden)
    async def forbidden(_request: Request, exc: Forbidden):
        return JSONResponse({"error": str(exc)}, status_code=403)

    @app.exception_handler(Conflict)
    async def conflict(_request: Request, exc: Conflict):
        return JSONResponse({"error": str(exc)}, status_code=409)

    @app.exception_handler(LookupError)
    async def not_found(_request: Request, exc: LookupError):
        return JSONResponse({"error": str(exc).strip("'\"")}, status_code=404)

    @app.exception_handler(ValueError)
    async def bad_request(_request: Request, exc: ValueError):
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(RequestValidationError)
    async def invalid(_request: Request, exc: RequestValidationError):
        first = exc.errors()[0] if exc.errors() else {}
        field = ".".join(str(x) for x in first.get("loc", [])[1:])
        return JSONResponse({"error": f"{field}: {first.get('msg', 'invalid')}" if field else "Invalid request."},
                            status_code=422)

    for router in (auth.router, views.router, jobs.router, data.router, admin.router, admin.audit_router):
        app.include_router(router)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def api_not_found(rest: str):
        return JSONResponse({"error": "Not found."}, status_code=404)

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    return app
