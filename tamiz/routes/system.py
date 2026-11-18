"""Auth, users, API tokens, settings, catalog, dashboard and history."""
from __future__ import annotations

import hmac
import sqlite3
from datetime import date

from fastapi import APIRouter, Body, Depends, Query, Request, Response

from .. import __version__, config, db, presets
from ..core import auth, lint, settings as settings_mod, store
from ..core.ids import IdPolicy
from ..seclang import catalog
from ..seclang.model import Exclusion
from .common import ApiError, actor, admin, get_conn, principal, viewer

router = APIRouter(prefix="/api")


def _client_ip(request: Request) -> str:
    return auth.client_ip(request)


def _cookie_secure(request: Request) -> bool:
    mode = config.get().cookie_secure
    if mode in ("true", "false"):
        return mode == "true"
    proto = request.headers.get("x-forwarded-proto", "")
    if proto and auth.trusted_proxy(auth.peer_ip(request)):
        return proto == "https"
    return request.url.scheme == "https"


# -------------------------------------------------------------------- auth --

@router.get("/auth/status")
def auth_status(request: Request, conn: sqlite3.Connection = Depends(get_conn)):
    p = getattr(request.state, "principal", None)
    return {"mode": config.get().auth_mode, "setup_needed": auth.setup_needed(conn),
            "user": p.public() if p else None, "version": __version__}


@router.post("/auth/login")
def login(request: Request, response: Response, body: dict = Body(...),
          conn: sqlite3.Connection = Depends(get_conn)):
    if config.get().auth_mode != "local":
        raise ApiError(400, "login_disabled")
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    ip = _client_ip(request)
    if auth.throttle.blocked(ip, username):
        raise ApiError(429, "too_many_attempts", "too many failed attempts; wait 15 minutes")
    r = conn.execute("SELECT * FROM users WHERE username=? AND source='local'", (username,)).fetchone()
    if not auth.verify_password(password, r["password_hash"] if r else None) or (r and r["disabled"]):
        auth.throttle.fail(ip, username)
        with db.tx(conn):
            db.log_history(conn, username or "?", "login_failed", "user", None, f"from {ip}", {"ip": ip},
                           ok=False)
        raise ApiError(401, "bad_credentials", "wrong user or password")
    auth.throttle.reset(ip, username)
    with db.tx(conn):
        token = auth.create_session(conn, r["id"], ip, request.headers.get("user-agent", ""))
        db.log_history(conn, r["username"], "login", "user", r["id"], f"from {ip}", {"ip": ip})
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict",
                        secure=_cookie_secure(request), path="/",
                        max_age=config.get().session_hours * 3600)
    return {"user": auth.Principal(r["id"], r["username"], r["display_name"] or r["username"],
                                   r["role"], "session").public()}


@router.post("/auth/logout")
def logout(request: Request, response: Response, conn: sqlite3.Connection = Depends(get_conn)):
    token = request.cookies.get(auth.COOKIE)
    if token:
        with db.tx(conn):
            auth.drop_session(conn, token)
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@router.post("/auth/setup")
def setup(request: Request, response: Response, body: dict = Body(...),
          conn: sqlite3.Connection = Depends(get_conn)):
    if not auth.setup_needed(conn):
        raise ApiError(400, "setup_done")
    code = db.meta_get(conn, "setup_code")
    given = str(body.get("code") or "").strip()
    ip = _client_ip(request)
    if auth.throttle.blocked(ip, "@setup"):
        raise ApiError(429, "too_many_attempts")
    if not code or not hmac.compare_digest(given.encode(), code.encode()):
        auth.throttle.fail(ip, "@setup")
        raise ApiError(403, "bad_setup_code", "the setup code does not match the one in the log")
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    if not username or len(username) > 64:
        raise ApiError(422, "invalid_username")
    problem = auth.password_problem(password)
    if problem:
        raise ApiError(422, problem)
    with db.tx(conn):
        # Checked again inside the write lock: two setups at once create one admin.
        if not auth.setup_needed(conn) or db.meta_get(conn, "setup_code") != code:
            raise ApiError(400, "setup_done")
        cur = conn.execute("INSERT INTO users(username, display_name, password_hash, role, created_at) "
                           "VALUES (?,?,?,?,?)", (username, str(body.get("display_name") or username),
                                                  auth.hash_password(password), "admin", db.now()))
        db.meta_set(conn, "setup_code", None)
        token = auth.create_session(conn, cur.lastrowid, ip, request.headers.get("user-agent", ""))
        db.log_history(conn, username, "setup", "user", cur.lastrowid, "first administrator created")
    response.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict",
                        secure=_cookie_secure(request), path="/",
                        max_age=config.get().session_hours * 3600)
    return {"ok": True}


@router.post("/auth/password")
def change_password(body: dict = Body(...), p=Depends(principal),
                    conn: sqlite3.Connection = Depends(get_conn)):
    if p.id is None or config.get().auth_mode != "local":
        raise ApiError(400, "password_not_local")
    r = conn.execute("SELECT * FROM users WHERE id=?", (p.id,)).fetchone()
    if not auth.verify_password(str(body.get("current") or ""), r["password_hash"]):
        raise ApiError(403, "bad_credentials")
    new = str(body.get("new") or "")
    problem = auth.password_problem(new)
    if problem:
        raise ApiError(422, problem)
    with db.tx(conn):
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (auth.hash_password(new), p.id))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (p.id,))
        db.log_history(conn, p.username, "password_changed", "user", p.id)
    return {"ok": True}


# ------------------------------------------------------------------- users --

def _user_public(r) -> dict:
    return {"id": r["id"], "username": r["username"], "display_name": r["display_name"],
            "role": r["role"], "source": r["source"], "disabled": bool(r["disabled"]),
            "created_at": r["created_at"], "last_login_at": r["last_login_at"]}


@router.get("/users")
def list_users(p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    return [_user_public(r) for r in conn.execute("SELECT * FROM users ORDER BY username")]


@router.post("/users")
def create_user(body: dict = Body(...), p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    username = str(body.get("username") or "").strip()
    role = str(body.get("role") or "viewer")
    if not username or len(username) > 64:
        raise ApiError(422, "invalid_username")
    if role not in auth.ROLES:
        raise ApiError(422, "invalid_role")
    password = str(body.get("password") or "")
    problem = auth.password_problem(password)
    if problem:
        raise ApiError(422, problem)
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise ApiError(409, "username_taken")
    with db.tx(conn):
        cur = conn.execute("INSERT INTO users(username, display_name, password_hash, role, created_at) "
                           "VALUES (?,?,?,?,?)", (username, str(body.get("display_name") or username),
                                                  auth.hash_password(password), role, db.now()))
        db.log_history(conn, actor(p), "user_created", "user", cur.lastrowid, f"{username} ({role})",
                       {"name": username, "role": role})
    return {"id": cur.lastrowid}


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: dict = Body(...), p=Depends(admin),
                conn: sqlite3.Connection = Depends(get_conn)):
    r = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not r:
        raise ApiError(404, "not_found")
    role = str(body.get("role") or r["role"])
    if role not in auth.ROLES:
        raise ApiError(422, "invalid_role")
    disabled = bool(body.get("disabled", bool(r["disabled"])))
    if r["id"] == p.id and (role != "admin" or disabled):
        raise ApiError(409, "cannot_demote_self")
    with db.tx(conn):
        conn.execute("UPDATE users SET role=?, disabled=?, display_name=? WHERE id=?",
                     (role, int(disabled), str(body.get("display_name") or r["display_name"]), user_id))
        if body.get("password"):
            problem = auth.password_problem(str(body["password"]))
            if problem:
                raise ApiError(422, problem)
            conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                         (auth.hash_password(str(body["password"])), user_id))
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        if disabled:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]
        if admins == 0:
            raise ApiError(409, "last_admin")
        db.log_history(conn, actor(p), "user_updated", "user", user_id,
                       f"{r['username']}: {role}{' (disabled)' if disabled else ''}",
                       {"name": r["username"], "role": role, "disabled": disabled})
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    if user_id == p.id:
        raise ApiError(409, "cannot_delete_self")
    with db.tx(conn):
        r = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        if not r:
            raise ApiError(404, "not_found")
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        if conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0] == 0 \
                and config.get().auth_mode == "local":
            raise ApiError(409, "last_admin")
        db.log_history(conn, actor(p), "user_deleted", "user", user_id, r["username"], {"name": r["username"]})
    return {"ok": True}


# ------------------------------------------------------------------ tokens --

@router.get("/tokens")
def list_tokens(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    if p.id is None:
        return []
    return db.rows(conn.execute("SELECT id, name, prefix, created_at, last_used_at, expires_at "
                                "FROM api_tokens WHERE user_id=? ORDER BY id", (p.id,)))


@router.post("/tokens")
def create_token(body: dict = Body(...), p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    if p.id is None:
        raise ApiError(400, "tokens_need_user")
    name = str(body.get("name") or "").strip()
    if not name:
        raise ApiError(422, "name_required")
    days = body.get("days")
    with db.tx(conn):
        token, tid = auth.create_token(conn, p.id, name, int(days) if days else None)
        db.log_history(conn, actor(p), "token_created", "token", tid, name, {"name": name})
    return {"id": tid, "token": token}


@router.delete("/tokens/{token_id}")
def delete_token(token_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    with db.tx(conn):
        cur = conn.execute("DELETE FROM api_tokens WHERE id=? AND user_id=?", (token_id, p.id))
        if cur.rowcount == 0:
            raise ApiError(404, "not_found")
        db.log_history(conn, actor(p), "token_deleted", "token", token_id)
    return {"ok": True}


# ---------------------------------------------------------------- settings --

@router.get("/settings")
def get_settings(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    return settings_mod.get_all(conn)


@router.put("/settings")
def put_settings(body: dict = Body(...), p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    with db.tx(conn):
        merged, errors = settings_mod.validate(conn, body)
        if errors:
            raise ApiError(422, "invalid_settings", issues=errors)
        settings_mod.save(conn, merged)
        db.log_history(conn, actor(p), "settings_changed", "settings", None, "", body)
    return merged


@router.get("/meta")
def meta(p=Depends(viewer)):
    return {
        "version": __version__,
        "presets": presets.public(),
        "operators": catalog.OPERATORS,
        "variables": catalog.COMMON_VARIABLES,
        "engine_modes": list(catalog.ENGINE_MODES),
        "auth_mode": config.get().auth_mode,
    }


# --------------------------------------------------------------- dashboard --

@router.get("/dashboard")
def dashboard(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    targets = store.list_targets(conn)
    groups = store.list_groups(conn)
    s = settings_mod.get_all(conn)
    policy = IdPolicy.from_conn(conn)
    blocks = {g["id"]: g["blocks"] for g in groups}
    findings = []
    counts = {"error": 0, "warning": 0, "info": 0}
    exclusions = store.list_exclusions(conn)
    for e in exclusions:
        ex = Exclusion.from_dict(e)
        issues = lint.lint(ex, policy, blocks.get(e["group_id"]), s["require_reason"],
                           s["expiry_warning_days"], date.today())
        for i in issues:
            counts[i.level] += 1
            if i.level in ("error", "warning"):
                findings.append({"exclusion_id": e["id"], "rule_id": e["rule_id"], "code": i.code,
                                 "level": i.level, "params": i.params, "group_id": e["group_id"]})
    pending_reviews = db.rows(conn.execute(
        "SELECT r.*, t.name AS target_name FROM reviews r JOIN targets t ON t.id=r.target_id "
        "WHERE r.status='pending' ORDER BY r.id DESC"))
    recent = db.rows(conn.execute("SELECT * FROM history ORDER BY id DESC LIMIT 12"))
    for r in recent:
        r["detail"] = db.jload(r["detail"], {})
    return {
        "targets": [{"id": t["id"], "name": t["name"], "environment": t["environment"],
                     "transport": t["transport"], "enabled": t["enabled"],
                     "last_check_at": t["last_check_at"], "last_check_error": t["last_check_error"],
                     "last_status": t["last_status"], "group_ids": t["group_ids"]} for t in targets],
        "counts": {"targets": len(targets), "groups": len(groups), "exclusions": len(exclusions),
                   "enabled": sum(1 for e in exclusions if e["enabled"])},
        "lint": counts,
        "findings": findings[:50],
        "reviews": pending_reviews,
        "recent": recent,
    }


# ----------------------------------------------------------------- history --

@router.get("/history")
def history(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn),
            entity: str | None = None, entity_id: int | None = None, action: str | None = None,
            q: str | None = None, before: int | None = None, limit: int = Query(50, le=200)):
    sql = "SELECT * FROM history WHERE 1=1"
    args: list = []
    if entity:
        sql += " AND entity=?"
        args.append(entity)
    if entity_id is not None:
        sql += " AND entity_id=?"
        args.append(entity_id)
    if action:
        sql += " AND action=?"
        args.append(action)
    if q:
        sql += " AND (summary LIKE ? OR actor LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    if before:
        sql += " AND id < ?"
        args.append(before)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    out = db.rows(conn.execute(sql, args))
    for r in out:
        r["detail"] = db.jload(r["detail"], {})
    return out


@router.get("/applies/{apply_id}")
def apply_detail(apply_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    r = db.row(conn.execute("SELECT * FROM applies WHERE id=?", (apply_id,)).fetchone())
    if not r:
        raise ApiError(404, "not_found")
    r["steps"] = db.jload(r["steps"], [])
    r["summary_params"] = db.jload(r.get("summary_params"), {})
    r["snapshots"] = db.rows(conn.execute(
        "SELECT id, path, existed, length(content) AS size FROM snapshots WHERE apply_id=?", (apply_id,)))
    return r


@router.get("/snapshots/{snapshot_id}")
def snapshot(snapshot_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    r = db.row(conn.execute("SELECT * FROM snapshots WHERE id=?", (snapshot_id,)).fetchone())
    if not r:
        raise ApiError(404, "not_found")
    from ..transports.base import printable
    r["content"] = printable(r["content"])
    return r
