"""Targets (WAF instances) and every operation that reaches them."""
from __future__ import annotations

import re
import sqlite3

from fastapi import APIRouter, Body, Depends
from fastapi.responses import Response

from .. import config, db, presets
from ..core import auditlog, deploy, importer, layout as layout_mod, plan as plan_mod, secrets, store
from ..core.ids import IdSpaceExhausted
from ..transports import KINDS, TransportError
from ..transports.base import printable
from ..transports.docker import DockerTransport
from .common import ApiError, actor, admin, editor, get_conn, viewer

router = APIRouter(prefix="/api/targets")

SECRET_KEYS = ("password", "private_key", "passphrase", "sudo_password", "jump_password",
               "jump_private_key", "jump_passphrase")
CMD_KEYS = ("validate", "reload", "discover", "command_prefix")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]_]{1,255}$")
NAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,64}$")


def _transport_error(e: TransportError) -> ApiError:
    status = 409 if e.code in ("host_key_mismatch",) else 502
    return ApiError(status, e.code, e.message, **e.params)


def _deploy_error(e: deploy.DeployError) -> ApiError:
    status = {"busy": 409, "plan_changed": 409, "review_required": 409, "review_not_approved": 409,
              "review_plan_mismatch": 409}.get(e.code, 400)
    return ApiError(status, e.code, e.message, **e.params)


def _clean(body: dict, existing: dict | None) -> tuple[dict, dict | None, list[dict]]:
    """Validate a target form. Returns (columns, new secret or None, errors)."""
    errors: list[dict] = []
    cur = existing or {}

    def err(field: str, code: str, **params):
        errors.append({"field": field, "code": code, "level": "error", "params": params})

    name = str(body.get("name", cur.get("name", ""))).strip()
    if not NAME_RE.match(name):
        err("name", "invalid_name")
    transport = str(body.get("transport", cur.get("transport", "ssh")))
    if transport not in KINDS:
        err("transport", "invalid_choice")
    platform = str(body.get("platform", cur.get("platform", "custom")))
    if platform not in presets.PRESETS:
        err("platform", "invalid_choice")

    conn_in = dict(cur.get("conn") or {})
    conn_in.update(body.get("conn") or {})
    c: dict = {}
    if transport == "ssh":
        c["host"] = str(conn_in.get("host") or "").strip()
        if not HOST_RE.match(c["host"]):
            err("conn.host", "invalid_host")
        try:
            c["port"] = int(conn_in.get("port") or 22)
            if not 0 < c["port"] < 65536:
                raise ValueError
        except (TypeError, ValueError):
            err("conn.port", "invalid_port")
        c["username"] = str(conn_in.get("username") or "").strip()
        if not re.match(r"^[A-Za-z0-9._\-]{1,64}$", c["username"]):
            err("conn.username", "invalid_username")
        c["key_file"] = str(conn_in.get("key_file") or "").strip()
        keys_dir = str(config.get().keys_dir).rstrip("/") + "/"
        if c["key_file"] and (".." in c["key_file"] or c["key_file"].startswith("/") and
                              not c["key_file"].startswith(keys_dir)):
            err("conn.key_file", "key_outside_keys_dir")
        jump = conn_in.get("jump") or {}
        if jump.get("host"):
            c["jump"] = {"host": str(jump["host"]).strip(), "port": int(jump.get("port") or 22),
                         "username": str(jump.get("username") or "").strip(),
                         "key_file": str(jump.get("key_file") or "").strip()}
            if not HOST_RE.match(c["jump"]["host"]):
                err("conn.jump.host", "invalid_host")
    elif transport == "docker":
        c["container"] = str(conn_in.get("container") or "").strip()
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$", c["container"]):
            err("conn.container", "invalid_container")
        c["exec_user"] = str(conn_in.get("exec_user") or "").strip()
        c["docker_host"] = str(conn_in.get("docker_host") or "").strip()
        for k in ("tls_ca", "tls_cert", "tls_key"):
            if conn_in.get(k):
                c[k] = str(conn_in[k]).strip()

    lay = dict(cur.get("layout") or {})
    lay.update(body.get("layout") or {})
    lay = {"mode": lay.get("mode") or "per_group", "before": str(lay.get("before") or "").strip(),
           "after": str(lay.get("after") or "").strip(), "mkdirs": bool(lay.get("mkdirs"))}
    for e in layout_mod.validate_layout(lay, transport):
        errors.append({**e, "level": "error", "params": {}})

    cmds = dict(cur.get("commands") or {})
    cmds.update(body.get("commands") or {})
    clean_cmds: dict = {}
    for k in CMD_KEYS:
        v = str(cmds.get(k) or "").strip()
        if "\n" in v or "\r" in v or len(v) > 500:
            err(f"commands.{k}", "invalid_command")
        clean_cmds[k] = v
    clean_cmds["sudo_mode"] = cmds.get("sudo_mode") or "none"
    if clean_cmds["sudo_mode"] not in ("none", "commands", "all"):
        err("commands.sudo_mode", "invalid_choice")
    clean_cmds["include_base"] = cmds.get("include_base") or presets.get(platform).get("include_base", "file")
    clean_cmds["server_root"] = str(cmds.get("server_root") or "").strip()
    try:
        clean_cmds["timeout"] = max(5, min(600, int(cmds.get("timeout") or 60)))
    except (TypeError, ValueError):
        err("commands.timeout", "not_a_number")

    logs = dict(cur.get("logs") or {})
    logs.update(body.get("logs") or {})
    clean_logs = {}
    for k in ("audit_log", "error_log"):
        v = str(logs.get(k) or "").strip()
        if v and not (v.startswith("/") or (v == "@stdout" and transport == "docker")):
            err(f"logs.{k}", "invalid_path")
        if any(ch in v for ch in "\t\n\r"):
            err(f"logs.{k}", "invalid_path")
        clean_logs[k] = v

    def path_list(key: str) -> list[str]:
        raw = body.get(key, cur.get(key, []))
        if isinstance(raw, str):
            raw = raw.splitlines()
        out = []
        for v in raw or []:
            v = str(v).strip()
            if not v:
                continue
            if not v.startswith("/") or any(ch in v for ch in "\t\n\r") or "/../" in v + "/":
                err(key, "invalid_path", value=v)
            out.append(v)
        return out[:50]

    cols = {
        "name": name,
        "description": str(body.get("description", cur.get("description", ""))).strip()[:500],
        "environment": str(body.get("environment", cur.get("environment", ""))).strip()[:40],
        "platform": platform, "transport": transport,
        "conn": db.jdump(c), "layout": db.jdump(lay), "commands": db.jdump(clean_cmds),
        "logs": db.jdump(clean_logs),
        "entry_files": db.jdump(path_list("entry_files")),
        "import_paths": db.jdump(path_list("import_paths")),
        "require_review": int(bool(body.get("require_review", cur.get("require_review", False)))),
        "enabled": int(bool(body.get("enabled", cur.get("enabled", True)))),
    }

    secret_in = body.get("secret")
    new_secret = None
    if isinstance(secret_in, dict):
        try:
            old = secrets.decrypt(cur.get("secret")) if cur.get("secret") else {}
        except secrets.SecretUnreadable:
            old = {}   # unreadable with the current key: whatever is typed now replaces it
        for k in SECRET_KEYS:
            if k in secret_in:
                v = secret_in[k]
                if v in (None, ""):
                    old.pop(k, None)
                else:
                    old[k] = str(v)
        new_secret = old
    return cols, new_secret, errors


def _public(t: dict) -> dict:
    t = dict(t)
    t.pop("secret", None)
    if t.get("host_key"):
        from ..transports.ssh import fingerprint
        hk = t["host_key"]
        if hk.startswith("{"):
            t["host_key_fingerprint"] = {k: fingerprint(v) for k, v in db.jload(hk, {}).items()}
        else:
            t["host_key_fingerprint"] = {"target": fingerprint(hk)}
    t["include_snippet"] = presets.get(t["platform"]).get("include_snippet", "")
    return t


@router.get("")
def list_targets(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    return [_public(t) for t in store.list_targets(conn)]


@router.get("/{target_id}")
def get_target(target_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        t = store.get_target(conn, target_id, with_secret=True)
    except store.NotFound:
        raise ApiError(404, "not_found")
    try:
        secret_keys = sorted(secrets.decrypt(t.get("secret")).keys()) if t.get("secret") else []
        t["secret_unreadable"] = False
    except secrets.SecretUnreadable:
        secret_keys, t["secret_unreadable"] = [], True
    t = _public(t)
    t["secret_keys"] = secret_keys
    t["managed_files"] = db.rows(conn.execute(
        "SELECT path, mode, group_slug, placement, last_applied_at, remote_state, remote_checked_at "
        "FROM managed_files WHERE target_id=? ORDER BY path", (target_id,)))
    t["retirements"] = db.rows(conn.execute(
        "SELECT id, path, status, created_at, created_by FROM retirements WHERE target_id=? "
        "ORDER BY id DESC LIMIT 20", (target_id,)))
    t["applies"] = db.rows(conn.execute(
        "SELECT id, actor, started_at, finished_at, status, summary, summary_code, summary_params, reload "
        "FROM applies "
        "WHERE target_id=? ORDER BY id DESC LIMIT 15", (target_id,)))
    for a in t["applies"]:
        a["summary_params"] = db.jload(a["summary_params"], {})
    t["reviews"] = db.rows(conn.execute(
        "SELECT * FROM reviews WHERE target_id=? ORDER BY id DESC LIMIT 10", (target_id,)))
    return t


@router.post("")
def create_target(body: dict = Body(...), p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    cols, secret, errors = _clean(body, None)
    if errors:
        raise ApiError(422, "invalid_target", issues=errors)
    if conn.execute("SELECT 1 FROM targets WHERE name=?", (cols["name"],)).fetchone():
        raise ApiError(422, "invalid_target",
                       issues=[{"field": "name", "code": "name_taken", "level": "error", "params": {}}])
    ts = db.now()
    cols.update(created_at=ts, updated_at=ts, secret=secrets.encrypt(secret or {}))
    with db.tx(conn):
        keys = ", ".join(cols)
        cur = conn.execute(f"INSERT INTO targets({keys}) VALUES ({', '.join('?' for _ in cols)})",
                           tuple(cols.values()))
        tid = cur.lastrowid
        if body.get("group_ids") is not None:
            store.set_target_groups(conn, tid, [int(x) for x in body["group_ids"]])
        db.log_history(conn, actor(p), "target_created", "target", tid, cols["name"], {"name": cols["name"]})
    return get_target(tid, p, conn)


@router.put("/{target_id}")
def update_target(target_id: int, body: dict = Body(...), p=Depends(admin),
                  conn: sqlite3.Connection = Depends(get_conn)):
    try:
        cur_t = store.get_target(conn, target_id, with_secret=True)
    except store.NotFound:
        raise ApiError(404, "not_found")
    cols, secret, errors = _clean(body, cur_t)
    if errors:
        raise ApiError(422, "invalid_target", issues=errors)
    clash = conn.execute("SELECT 1 FROM targets WHERE name=? AND id<>?", (cols["name"], target_id)).fetchone()
    if clash:
        raise ApiError(422, "invalid_target",
                       issues=[{"field": "name", "code": "name_taken", "level": "error", "params": {}}])
    cols["updated_at"] = db.now()
    if secret is not None:
        cols["secret"] = secrets.encrypt(secret)
    old_conn = cur_t.get("conn") or {}
    new_conn = db.jload(cols["conn"], {})
    if old_conn.get("host") != new_conn.get("host") or old_conn.get("port") != new_conn.get("port"):
        cols["host_key"] = None   # different server: pin its key again
    with db.tx(conn):
        sets = ", ".join(f"{k}=?" for k in cols)
        conn.execute(f"UPDATE targets SET {sets} WHERE id=?", (*cols.values(), target_id))
        if body.get("group_ids") is not None:
            store.set_target_groups(conn, target_id, [int(x) for x in body["group_ids"]])
        db.log_history(conn, actor(p), "target_updated", "target", target_id, cols["name"], {"name": cols["name"]})
    return get_target(target_id, p, conn)


@router.put("/{target_id}/groups")
def set_groups(target_id: int, body: dict = Body(...), p=Depends(editor),
               conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            store.set_target_groups(conn, target_id, [int(x) for x in body.get("group_ids") or []])
            db.log_history(conn, actor(p), "target_groups", "target", target_id,
                           f"groups: {body.get('group_ids')}")
    except store.NotFound:
        raise ApiError(404, "not_found")
    return {"ok": True}


@router.delete("/{target_id}")
def delete_target(target_id: int, p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        t = store.get_target(conn, target_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    with db.tx(conn):
        conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        db.log_history(conn, actor(p), "target_deleted", "target", target_id,
                       f"{t['name']} (files on the server were left in place)", {"name": t["name"]})
    return {"ok": True}


@router.post("/{target_id}/host-key/reset")
def reset_host_key(target_id: int, p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    with db.tx(conn):
        conn.execute("UPDATE targets SET host_key=NULL WHERE id=?", (target_id,))
        db.log_history(conn, actor(p), "host_key_reset", "target", target_id)
    return {"ok": True}


# -------------------------------------------------------------- operations --

@router.post("/{target_id}/check")
def check(target_id: int, body: dict = Body(default={}), p=Depends(viewer),
          conn: sqlite3.Connection = Depends(get_conn)):
    try:
        plan = deploy.check(conn, target_id, set(body.get("force") or []))
    except store.NotFound:
        raise ApiError(404, "not_found")
    except TransportError as e:
        raise _transport_error(e)
    out = plan.public()
    for op in out["ops"]:
        op["diff"] = printable(op["diff"])
    return out


@router.post("/{target_id}/apply")
def apply(target_id: int, body: dict = Body(...), p=Depends(editor),
          conn: sqlite3.Connection = Depends(get_conn)):
    plan_hash = str(body.get("plan_hash") or "")
    if not plan_hash:
        raise ApiError(422, "plan_hash_required")
    try:
        return deploy.apply(conn, target_id, actor(p), plan_hash, bool(body.get("reload", True)),
                            set(body.get("force") or []), body.get("review_id"))
    except deploy.DeployError as e:
        raise _deploy_error(e)
    except store.NotFound:
        raise ApiError(404, "not_found")


@router.post("/{target_id}/mark-deployed")
def mark_deployed(target_id: int, body: dict = Body(...), p=Depends(editor),
                  conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            return deploy.mark_deployed(conn, target_id, actor(p), str(body.get("plan_hash") or ""))
    except deploy.DeployError as e:
        raise _deploy_error(e)


@router.get("/{target_id}/bundle")
def bundle(target_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        data, name = deploy.bundle(conn, target_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/{target_id}/diagnose")
def diagnose(target_id: int, p=Depends(admin), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        return deploy.diagnose(conn, target_id)
    except store.NotFound:
        raise ApiError(404, "not_found")


@router.get("/{target_id}/load-order")
def load_order(target_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        return deploy.load_order(conn, target_id)
    except TransportError as e:
        raise _transport_error(e)


@router.post("/{target_id}/run/{which}")
def run(target_id: int, which: str, p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    if which not in ("validate", "reload"):
        raise ApiError(404, "not_found")
    try:
        return deploy.run_named(conn, target_id, which, actor(p))
    except deploy.DeployError as e:
        raise _deploy_error(e)
    except TransportError as e:
        raise _transport_error(e)


# ----------------------------------------------------------------- reviews --

@router.post("/{target_id}/reviews")
def request_review(target_id: int, body: dict = Body(...), p=Depends(editor),
                   conn: sqlite3.Connection = Depends(get_conn)):
    plan_hash = str(body.get("plan_hash") or "")
    if not plan_hash:
        raise ApiError(422, "plan_hash_required")
    with db.tx(conn):
        conn.execute("UPDATE reviews SET status='stale' WHERE target_id=? AND status='pending'", (target_id,))
        cur = conn.execute("INSERT INTO reviews(target_id, plan_hash, plan_summary, requested_by, "
                           "requested_at, note) VALUES (?,?,?,?,?,?)",
                           (target_id, plan_hash, str(body.get("summary") or "")[:500], actor(p),
                            db.now(), str(body.get("note") or "")[:1000]))
        db.log_history(conn, actor(p), "review_requested", "target", target_id,
                       str(body.get("note") or "")[:200], {"review_id": cur.lastrowid})
    return {"id": cur.lastrowid}


@router.post("/{target_id}/reviews/{review_id}/{decision}")
def decide_review(target_id: int, review_id: int, decision: str, body: dict = Body(default={}),
                  p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    if decision not in ("approve", "reject"):
        raise ApiError(404, "not_found")
    from ..core import settings as settings_mod
    r = conn.execute("SELECT * FROM reviews WHERE id=? AND target_id=?", (review_id, target_id)).fetchone()
    if not r or r["status"] != "pending":
        raise ApiError(409, "review_not_pending")
    if r["requested_by"] == actor(p) and not settings_mod.get_all(conn)["review_self_approve"]:
        raise ApiError(403, "cannot_review_own")
    status = "approved" if decision == "approve" else "rejected"
    with db.tx(conn):
        conn.execute("UPDATE reviews SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                     (status, actor(p), db.now(), str(body.get("note") or "")[:1000], review_id))
        db.log_history(conn, actor(p), f"review_{status}", "target", target_id, "",
                       {"review_id": review_id})
    return {"status": status}


# ------------------------------------------------------------ logs, import --

@router.post("/{target_id}/analyze")
def analyze(target_id: int, body: dict = Body(default={}), p=Depends(editor),
            conn: sqlite3.Connection = Depends(get_conn)):
    source = body.get("source") or "audit_log"
    if source not in ("audit_log", "error_log"):
        raise ApiError(422, "invalid_choice")
    size = max(64 * 1024, min(int(body.get("bytes") or 5 * 1024 * 1024), 20 * 1024 * 1024))
    try:
        target, t = deploy.open_target(conn, target_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    path = ((target.get("logs") or {}).get(source) or "").strip()
    if not path:
        raise ApiError(422, "no_log_configured")
    try:
        with t:
            deploy.persist_host_key(conn, target, t)
            if path == "@stdout":
                if not isinstance(t, DockerTransport):
                    raise ApiError(422, "invalid_choice")
                data = t.container_logs(int(body.get("lines") or 20000))
            else:
                data = t.tail(path, size)
    except TransportError as e:
        raise _transport_error(e)
    result = auditlog.analyze(data.decode("utf-8", "replace"), store.list_exclusions(conn))
    result["source"] = {"target_id": target_id, "path": path, "bytes": len(data)}
    return result


def _import_candidates(conn, target_id: int) -> tuple[dict, list[str]]:
    target, t = deploy.open_target(conn, target_id)
    with t:
        deploy.persist_host_key(conn, target, t)
        patterns = target.get("import_paths") or []
        files: list[str] = []
        if patterns:
            for pat, matches in t.glob(patterns).items():
                files.extend(matches)
        managed = layout_mod.managed_paths(conn, target)
        files = [f for f in dict.fromkeys(files) if f not in managed]
    return target, files


@router.get("/{target_id}/import")
def import_files(target_id: int, p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        target, files = _import_candidates(conn, target_id)
    except TransportError as e:
        raise _transport_error(e)
    return {"files": files, "patterns": target.get("import_paths") or []}


@router.post("/{target_id}/import/scan")
def import_scan(target_id: int, body: dict = Body(...), p=Depends(editor),
                conn: sqlite3.Connection = Depends(get_conn)):
    path = str(body.get("path") or "")
    try:
        target, files = _import_candidates(conn, target_id)
        if path not in files:
            raise ApiError(403, "path_not_importable")
        target, t = deploy.open_target(conn, target_id)
        with t:
            fr = t.read_file(path)
    except TransportError as e:
        raise _transport_error(e)
    if fr.status != "ok":
        raise ApiError(422, "file_" + fr.status)
    result = importer.scan_text(conn, fr.content or "", path)
    for prop in result["proposals"]:
        prop["text"] = printable(prop["text"])
        prop["cut_text"] = printable(prop["cut_text"])
    result["can_retire"] = t.remote
    return result


@router.post("/{target_id}/import/commit")
def import_commit(target_id: int, body: dict = Body(...), p=Depends(editor),
                  conn: sqlite3.Connection = Depends(get_conn)):
    path = str(body.get("path") or "")
    try:
        target, files = _import_candidates(conn, target_id)
        if path not in files:
            raise ApiError(403, "path_not_importable")
        target, t = deploy.open_target(conn, target_id)
        with t:
            fr = t.read_file(path)
    except TransportError as e:
        raise _transport_error(e)
    if fr.status != "ok":
        raise ApiError(422, "file_" + fr.status)
    if plan_mod.sha(fr.content) != body.get("file_hash"):
        raise ApiError(409, "file_changed", "the file changed on the server since it was scanned")
    try:
        with db.tx(conn):
            retire = {"target_id": target_id, "path": path} if body.get("retire") else None
            return importer.commit(conn, actor(p), fr.content or "", body.get("items") or [],
                                   bool(body.get("renumber", True)), retire)
    except importer.ImportError_ as e:
        raise ApiError(409, e.code, **e.params)
    except store.Conflict as e:
        raise ApiError(422, e.code, **e.params)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")


@router.delete("/{target_id}/retirements/{retirement_id}")
def cancel_retirement(target_id: int, retirement_id: int, p=Depends(editor),
                      conn: sqlite3.Connection = Depends(get_conn)):
    with db.tx(conn):
        cur = conn.execute("UPDATE retirements SET status='cancelled' WHERE id=? AND target_id=? "
                           "AND status='pending'", (retirement_id, target_id))
        if cur.rowcount == 0:
            raise ApiError(404, "not_found")
        db.log_history(conn, actor(p), "retirement_cancelled", "target", target_id, "",
                       {"retirement_id": retirement_id})
    return {"ok": True}

