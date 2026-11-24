"""Tamiz web application (FastAPI).

Start with ``uvicorn tamiz.main:app`` (the container does this). Startup runs
database migrations, bootstraps the first administrator when configured and
prints the one-time setup code otherwise.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, config, db
from .core import auth
from .routes import io, rules, system, targets
from .routes.common import ApiError

log = logging.getLogger("tamiz")
STATIC = Path(__file__).parent / "static"

PUBLIC_API = {"/api/auth/status", "/api/auth/login", "/api/auth/setup", "/api/auth/logout",
              "/api/health"}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = config.get()
    logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    version = db.migrate()
    with db.db() as conn:
        with db.tx(conn):
            if auth.bootstrap_admin(conn):
                log.info("created administrator %s from TAMIZ_ADMIN_USER", cfg.admin_user)
            code = auth.ensure_setup_code(conn)
    log.info("Tamiz %s ready (schema %s, auth %s)", __version__, version, cfg.auth_mode)
    if code:
        log.warning("No administrator yet. Open Tamiz and use this setup code: %s", code)
    if cfg.auth_mode == "none":
        log.warning("TAMIZ_AUTH_MODE=none: anyone who can reach Tamiz is an administrator")
    yield


app = FastAPI(title="Tamiz", version=__version__, lifespan=lifespan, docs_url="/api/docs",
              redoc_url=None, openapi_url="/api/openapi.json")


@app.middleware("http")
async def authenticate(request: Request, call_next):
    request.state.principal = None
    path = request.url.path
    if path.startswith("/api/"):
        cfg = config.get()
        principal = None
        via_cookie = False
        with db.db() as conn:
            authz = request.headers.get("authorization", "")
            if authz.lower().startswith("bearer "):
                principal = auth.token_user(conn, authz[7:].strip())
            elif cfg.auth_mode == "local":
                token = request.cookies.get(auth.COOKIE)
                if token:
                    principal = auth.session_user(conn, token)
                    via_cookie = True
            elif cfg.auth_mode == "proxy":
                ip = auth.peer_ip(request)
                user = request.headers.get(cfg.proxy_user_header, "")
                if user and auth.trusted_proxy(ip):
                    principal = auth.proxy_user(conn, user, request.headers.get(cfg.proxy_groups_header, ""))
                    via_cookie = True
                elif user:
                    auth.warn_untrusted_proxy(ip, cfg.proxy_user_header)
            elif cfg.auth_mode == "none":
                name = (request.headers.get("x-actor") or "anonymous").strip()[:64] or "anonymous"
                principal = auth.Principal(None, name, name, "admin", "none")
                via_cookie = True
        request.state.principal = principal
        if principal is None and path not in PUBLIC_API and not path.startswith("/api/docs") \
                and path != "/api/openapi.json":
            return JSONResponse({"error": "not_authenticated", "message": "log in first",
                                 "params": {}, "issues": []}, status_code=401)
        if request.method in UNSAFE and (via_cookie or path in ("/api/auth/login", "/api/auth/setup")) \
                and request.headers.get("x-tamiz") != "1":
            return JSONResponse({"error": "csrf", "message": "missing X-Tamiz header",
                                 "params": {}, "issues": []}, status_code=403)
    response = await call_next(request)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    elif path.startswith("/static/"):
        # Revalidate on every load (StaticFiles answers 304 by ETag), so after
        # an upgrade the browser never keeps running the old JavaScript.
        response.headers["Cache-Control"] = "no-cache"
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if not path.startswith("/api/docs"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    return response


@app.exception_handler(ApiError)
async def api_error(request: Request, exc: ApiError):
    return JSONResponse(exc.body(), status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse({"error": "invalid_request", "message": "malformed request",
                         "params": {}, "issues": [{"field": ".".join(str(x) for x in e["loc"]),
                                                   "code": e["type"], "level": "error", "params": {}}
                                                  for e in exc.errors()]}, status_code=422)


@app.exception_handler(Exception)
async def unexpected(request: Request, exc: Exception):
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse({"error": "internal_error", "message": str(exc)[:300], "params": {},
                         "issues": []}, status_code=500)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__}


app.include_router(system.router)
app.include_router(targets.router)
app.include_router(rules.router)
app.include_router(io.router)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})
