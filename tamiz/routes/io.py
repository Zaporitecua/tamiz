"""Workspace export and import (groups and exclusions as JSON).

The export is for backups, for moving exclusions between Tamiz instances and
for keeping them in Git. It never contains credentials. Importing merges:
groups are matched by slug, exclusions by fingerprint, and nothing existing
is modified.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from .. import __version__, db
from ..core import store
from ..core.ids import IdSpaceExhausted
from ..seclang.model import Exclusion
from .common import ApiError, actor, editor, get_conn, viewer

router = APIRouter(prefix="/api/io")

EXPORT_FIELDS = ("scope", "action", "selector_type", "selectors", "variables", "engine_mode",
                 "conditions", "phase", "log", "extra_actions", "rule_id", "raw_text", "placement",
                 "source_text", "verbatim", "reason", "reference", "expires_at", "enabled")


@router.get("/export")
def export(p=Depends(viewer), conn: sqlite3.Connection = Depends(get_conn)):
    groups = []
    for g in store.list_groups(conn):
        exclusions = [{k: e[k] for k in EXPORT_FIELDS} for e in store.list_exclusions(conn, g["id"])]
        groups.append({"slug": g["slug"], "name": g["name"], "description": g["description"],
                       "id_ranges": g["id_ranges"], "exclusions": exclusions})
    data = {"format": "tamiz-workspace", "version": 1, "tamiz": __version__,
            "exported_at": db.now(), "groups": groups}
    return JSONResponse(data, headers={"Content-Disposition": 'attachment; filename="tamiz-export.json"'})


@router.post("/import")
def import_workspace(body: dict = Body(...), p=Depends(editor), conn: sqlite3.Connection = Depends(get_conn)):
    if body.get("format") != "tamiz-workspace":
        raise ApiError(422, "not_a_tamiz_export")
    keep_ids = bool(body.get("keep_ids", False))
    created, skipped, groups_created = 0, 0, 0
    try:
        with db.tx(conn):
            fingerprints = {r["fingerprint"] for r in conn.execute("SELECT fingerprint FROM exclusions")}
            for g in body.get("groups") or []:
                existing = store.group_by_slug(conn, str(g.get("slug") or ""))
                if existing:
                    gid = existing["id"]
                else:
                    gid = store.create_group(conn, str(g.get("name") or g.get("slug")),
                                             str(g.get("slug") or "") or None, str(g.get("description") or ""))
                    groups_created += 1
                for e in g.get("exclusions") or []:
                    ex = Exclusion.from_dict(e)
                    ex.group_id = gid
                    ex.origin = "import"
                    if store.fingerprint(ex) in fingerprints:
                        skipped += 1
                        continue
                    if not keep_ids and ex.scope == "conditional" and not ex.verbatim:
                        ex.rule_id = None
                    store.save_exclusion(conn, ex, actor(p), keep_rule_id=keep_ids)
                    fingerprints.add(store.fingerprint(ex))
                    created += 1
            db.log_history(conn, actor(p), "workspace_import", "", None,
                           f"{created} exclusions, {groups_created} groups ({skipped} duplicates skipped)")
    except store.Conflict as e:
        raise ApiError(409, e.code, **e.params)
    except IdSpaceExhausted:
        raise ApiError(409, "id_space_exhausted")
    return {"created": created, "skipped": skipped, "groups_created": groups_created}
