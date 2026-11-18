"""Groups, exclusions, import and the log analyzer."""
from __future__ import annotations

import sqlite3
from datetime import date

from fastapi import APIRouter, Body, Depends

from .. import db
from ..core import auditlog, importer, lint, reorg, settings as settings_mod, store
from ..core.ids import IdPolicy, IdSpaceExhausted, group_blocks
from ..seclang import render
from ..seclang.model import Exclusion, validate
from .common import ApiError, actor, editor, get_conn, issues_json, viewer

router = APIRouter(prefix="/api")

MAX_TEXT = 20 * 1024 * 1024


def _conflict(e: store.Conflict, status: int = 409) -> ApiError:
    return ApiError(status, e.code, **e.params)


# ------------------------------------------------------------------ groups --

@router.get("/groups")
def list_groups(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    return store.list_groups(conn)


@router.post("/groups")
def create_group(body: dict = Body(...), p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            gid = store.create_group(conn, str(body.get("name") or ""), body.get("slug") or None,
                                     str(body.get("description") or ""))
            if body.get("target_ids") is not None:
                store.set_group_targets(conn, gid, [int(x) for x in body["target_ids"]])
            g = store.get_group(conn, gid)
            db.log_history(conn, actor(p), "group_created", "group", gid,
                           f"{g['name']} ({g['id_ranges']})", {"name": g["name"], "ranges": g["id_ranges"]})
    except store.Conflict as e:
        raise _conflict(e, 422)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")
    return g


@router.patch("/groups/{group_id}")
def update_group(group_id: int, body: dict = Body(...), p=Depends(editor),
                 conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            g = store.get_group(conn, group_id)
            store.update_group(conn, group_id, str(body.get("name", g["name"])),
                               str(body.get("slug", g["slug"])),
                               str(body.get("description", g["description"])))
            if body.get("target_ids") is not None:
                store.set_group_targets(conn, group_id, [int(x) for x in body["target_ids"]])
            db.log_history(conn, actor(p), "group_updated", "group", group_id, g["name"], {"name": g["name"]})
            return store.get_group(conn, group_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    except store.Conflict as e:
        raise _conflict(e, 422)


@router.delete("/groups/{group_id}")
def delete_group(group_id: int, p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            g = store.get_group(conn, group_id)
            store.delete_group(conn, group_id)
            db.log_history(conn, actor(p), "group_deleted", "group", group_id, g["name"], {"name": g["name"]})
    except store.NotFound:
        raise ApiError(404, "not_found")
    except store.Conflict as e:
        raise _conflict(e)
    return {"ok": True}


@router.get("/groups/{group_id}/renumber")
def renumber_plan(group_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    return reorg.plan(conn, group_id)


@router.post("/groups/{group_id}/renumber")
def renumber(group_id: int, p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            return reorg.apply(conn, group_id, actor(p))
    except importer.ImportError_ as e:
        raise ApiError(409, e.code, **e.params)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")


# -------------------------------------------------------------- exclusions --

def _lint_for(conn, ex: Exclusion) -> list[dict]:
    s = settings_mod.get_all(conn)
    blocks = group_blocks(conn, ex.group_id) if ex.group_id else None
    return issues_json(lint.lint(ex, IdPolicy.from_conn(conn), blocks, s["require_reason"],
                                 s["expiry_warning_days"], date.today()))


@router.get("/exclusions")
def list_exclusions(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn),
                    group_id: int | None = None):
    out = store.list_exclusions(conn, group_id)
    s = settings_mod.get_all(conn)
    policy = IdPolicy.from_conn(conn)
    blocks = {g["id"]: g["blocks"] for g in store.list_groups(conn)}
    for e in out:
        ex = Exclusion.from_dict(e)
        e["lint"] = issues_json(lint.lint(ex, policy, blocks.get(e["group_id"]), s["require_reason"],
                                          s["expiry_warning_days"], date.today()))
    return out


@router.get("/exclusions/{exclusion_id}")
def get_exclusion(exclusion_id: int, p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        e = store.get_exclusion(conn, exclusion_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    ex = Exclusion.from_dict(e)
    style = settings_mod.get_all(conn)["render_style"]
    e["rendered"] = render.render_exclusion(ex, style)
    e["lint"] = _lint_for(conn, ex)
    e["history"] = db.rows(conn.execute(
        "SELECT * FROM history WHERE entity='exclusion' AND entity_id=? ORDER BY id DESC LIMIT 20",
        (exclusion_id,)))
    return e


def _from_body(body: dict) -> Exclusion:
    ex = Exclusion.from_dict(body)
    if ex.scope != "raw":
        ex.raw_text = None
    if not ex.reason:
        ex.reason = ""
    return ex


@router.post("/exclusions/preview")
def preview(body: dict = Body(...), p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    """Render and check an exclusion without saving it (used live by the form)."""
    ex = _from_body(body)
    if ex.id is not None:
        try:
            prev = store.get_exclusion(conn, ex.id)
            if prev["group_id"] == ex.group_id:
                ex.rule_id = prev["rule_id"]
        except store.NotFound:
            pass
    if ex.scope == "conditional" and ex.rule_id is None and not ex.verbatim:
        ex.rule_id = 0
    errors = validate(ex)
    style = settings_mod.get_all(conn)["render_style"]
    text = ""
    if not any(i.level == "error" for i in errors):
        try:
            text = render.render_exclusion(ex, style)
            if ex.rule_id == 0:
                text = text.replace("id:0,", "id:(new),").replace("id:0\"", "id:(new)\"")
        except Exception:
            text = ""
    return {"rendered": text, "errors": issues_json(errors),
            "lint": _lint_for(conn, ex) if ex.group_id else [],
            "placement": ex.effective_placement(),
            "phase": ex.effective_phase() if ex.scope == "conditional" else None}


def _save(conn, ex: Exclusion, p, action: str) -> dict:
    errors = [i for i in validate(ex) if i.level == "error"]
    if errors:
        raise ApiError(422, "invalid_exclusion", issues=issues_json(errors))
    s = settings_mod.get_all(conn)
    if s["require_reason"] and not ex.reason.strip():
        raise ApiError(422, "invalid_exclusion",
                       issues=[{"field": "reason", "code": "required", "level": "error", "params": {}}])
    try:
        with db.tx(conn):
            eid = store.save_exclusion(conn, ex, actor(p))
            saved = store.get_exclusion(conn, eid)
            db.log_history(conn, actor(p), action, "exclusion", eid,
                           _describe(saved), {"exclusion": _compact(saved)})
    except store.NotFound as e:
        raise ApiError(404, "not_found", what=str(e))
    except store.Conflict as e:
        raise _conflict(e, 422)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")
    return saved


def _compact(e: dict) -> dict:
    keys = ("scope", "action", "selector_type", "selectors", "variables", "engine_mode", "conditions",
            "placement", "rule_id", "group_id")
    out = {k: e.get(k) for k in keys}
    if e.get("raw_text"):
        out["raw_text"] = e["raw_text"][:300]
    return out


def _describe(e: dict) -> str:
    if e["scope"] == "raw":
        return f"#{e['id']} raw ({e['placement']})"
    sel = ",".join(e["selectors"][:3]) + ("…" if len(e["selectors"]) > 3 else "")
    where = ""
    if e["conditions"]:
        c = e["conditions"][0]
        where = f" on {c['variable']} {c['operator']} {c['value']}"[:80]
    rid = f" [{e['rule_id']}]" if e["rule_id"] else ""
    return f"#{e['id']}{rid} {e['action']} {sel}{where}"


@router.post("/exclusions")
def create_exclusion(body: dict = Body(...), p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    ex = _from_body(body)
    ex.id = None
    ex.verbatim = False
    ex.source_text = None
    ex.origin = body.get("origin") if body.get("origin") in ("ui", "analyzer", "api") else "ui"
    return _save(conn, ex, p, "exclusion_created")


@router.put("/exclusions/{exclusion_id}")
def update_exclusion(exclusion_id: int, body: dict = Body(...), p=Depends(editor),
                     conn: sqlite3.Connection = Depends(get_conn)):
    try:
        prev = store.get_exclusion(conn, exclusion_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    ex = _from_body(body)
    ex.id = exclusion_id
    ex.origin = prev["origin"]
    # An imported rule keeps its original text until its structure changes;
    # then it is rendered by Tamiz (canonical form). Metadata edits (reason,
    # expiry ...) never rewrite the rule.
    if prev["verbatim"]:
        before = Exclusion.from_dict(prev)
        structural = ("scope", "action", "selector_type", "selectors", "variables", "engine_mode",
                      "conditions", "phase", "log", "extra_actions")
        same = all(getattr(before, k) == getattr(ex, k) for k in structural)
        if same or body.get("keep_verbatim"):
            for k in structural:
                setattr(ex, k, getattr(before, k))
            ex.verbatim = True
            ex.source_text = prev["source_text"]
        else:
            ex.verbatim = False
            ex.source_text = None
    return _save(conn, ex, p, "exclusion_updated")


@router.patch("/exclusions/{exclusion_id}")
def patch_exclusion(exclusion_id: int, body: dict = Body(...), p=Depends(editor),
                    conn: sqlite3.Connection = Depends(get_conn)):
    """Small changes that never touch the rule itself: enable, reason, expiry, group."""
    try:
        prev = store.get_exclusion(conn, exclusion_id)
    except store.NotFound:
        raise ApiError(404, "not_found")
    ex = Exclusion.from_dict(prev)
    for k in ("enabled", "reason", "reference", "expires_at", "group_id"):
        if k in body:
            setattr(ex, k, body[k] if k != "enabled" else bool(body[k]))
    if ex.group_id is not None:
        ex.group_id = int(ex.group_id)
    return _save(conn, ex, p, "exclusion_updated")


@router.delete("/exclusions/{exclusion_id}")
def delete_exclusion(exclusion_id: int, p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    try:
        with db.tx(conn):
            d = store.delete_exclusion(conn, exclusion_id)
            db.log_history(conn, actor(p), "exclusion_deleted", "exclusion", exclusion_id, _describe(d),
                           {"exclusion": _compact(d), "full": d})
    except store.NotFound:
        raise ApiError(404, "not_found")
    return {"ok": True}


# ------------------------------------------------------------------ import --

@router.post("/import/scan")
def import_scan(body: dict = Body(...), p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    text = str(body.get("text") or "")
    if len(text) > MAX_TEXT:
        raise ApiError(413, "too_large")
    return importer.scan_text(conn, text, body.get("path") or None)


@router.post("/import/commit")
def import_commit(body: dict = Body(...), p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    text = str(body.get("text") or "")
    if len(text) > MAX_TEXT:
        raise ApiError(413, "too_large")
    choices = body.get("items") or []
    if not choices:
        raise ApiError(422, "nothing_selected")
    try:
        with db.tx(conn):
            return importer.commit(conn, actor(p), text, choices, bool(body.get("renumber", True)))
    except importer.ImportError_ as e:
        raise ApiError(409, e.code, **e.params)
    except store.Conflict as e:
        raise _conflict(e, 422)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")


# ---------------------------------------------------------------- analyzer --

@router.post("/analyze")
def analyze_text(body: dict = Body(...), p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    text = str(body.get("text") or "")
    if len(text) > MAX_TEXT:
        raise ApiError(413, "too_large")
    return auditlog.analyze(text, store.list_exclusions(conn))
