"""Data access for groups, exclusions and targets.

Every function takes an open connection; callers decide the transaction
boundaries (see ``db.tx``). Functions here never talk to servers.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3

from .. import db
from ..seclang import parser as seclang_parser
from ..seclang import render
from ..seclang.model import Exclusion
from . import ids

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


class NotFound(LookupError):
    pass


class Conflict(ValueError):
    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


def slugify(name: str) -> str:
    import unicodedata
    s = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s[:48] or "group"


# ------------------------------------------------------------------ groups --

def list_groups(conn: sqlite3.Connection) -> list[dict]:
    policy = ids.IdPolicy.from_conn(conn)
    groups = db.rows(conn.execute("SELECT * FROM groups ORDER BY slug"))
    counts = {r["group_id"]: dict(r) for r in conn.execute(
        "SELECT group_id, COUNT(*) total, SUM(enabled) enabled, "
        "SUM(CASE WHEN rule_id IS NOT NULL THEN 1 ELSE 0 END) with_id "
        "FROM exclusions GROUP BY group_id")}
    targets: dict[int, list[int]] = {}
    for r in conn.execute("SELECT group_id, target_id FROM target_groups"):
        targets.setdefault(r["group_id"], []).append(r["target_id"])
    for g in groups:
        blocks = ids.group_blocks(conn, g["id"])
        g["blocks"] = blocks
        g["id_ranges"] = ids.format_ranges(policy, blocks)
        capacity = sum(max(0, hi - lo + 1) for lo, hi in (policy.block_range(b) for b in blocks))
        c = counts.get(g["id"], {})
        g["exclusion_count"] = c.get("total", 0) or 0
        g["enabled_count"] = c.get("enabled", 0) or 0
        g["ids_used"] = c.get("with_id", 0) or 0
        g["ids_capacity"] = capacity
        g["target_ids"] = sorted(targets.get(g["id"], []))
    return groups


def get_group(conn: sqlite3.Connection, group_id: int) -> dict:
    for g in list_groups(conn):
        if g["id"] == group_id:
            return g
    raise NotFound("group")


def group_by_slug(conn: sqlite3.Connection, slug: str) -> dict | None:
    for g in list_groups(conn):
        if g["slug"] == slug:
            return g
    return None


def create_group(conn: sqlite3.Connection, name: str, slug: str | None = None,
                 description: str = "") -> int:
    name = name.strip()
    if not name:
        raise Conflict("name_required")
    slug = (slug or slugify(name)).strip().lower()
    if not SLUG_RE.match(slug) or slug.startswith("tamiz-keep"):
        raise Conflict("invalid_slug")
    if conn.execute("SELECT 1 FROM groups WHERE slug=?", (slug,)).fetchone():
        raise Conflict("slug_taken", slug=slug)
    ts = db.now()
    cur = conn.execute("INSERT INTO groups(slug, name, description, created_at, updated_at) "
                       "VALUES (?,?,?,?,?)", (slug, name, description.strip(), ts, ts))
    gid = cur.lastrowid
    ids.allocate_block(conn, ids.IdPolicy.from_conn(conn), gid)
    return gid


def update_group(conn: sqlite3.Connection, group_id: int, name: str, slug: str,
                 description: str) -> None:
    current = conn.execute("SELECT * FROM groups WHERE id=?", (group_id,)).fetchone()
    if not current:
        raise NotFound("group")
    slug = slug.strip().lower()
    if not SLUG_RE.match(slug) or slug.startswith("tamiz-keep"):
        raise Conflict("invalid_slug")
    clash = conn.execute("SELECT id FROM groups WHERE slug=? AND id<>?", (slug, group_id)).fetchone()
    if clash:
        raise Conflict("slug_taken", slug=slug)
    if not name.strip():
        raise Conflict("name_required")
    conn.execute("UPDATE groups SET name=?, slug=?, description=?, updated_at=? WHERE id=?",
                 (name.strip(), slug, description.strip(), db.now(), group_id))


def delete_group(conn: sqlite3.Connection, group_id: int) -> None:
    n = conn.execute("SELECT COUNT(*) FROM exclusions WHERE group_id=?", (group_id,)).fetchone()[0]
    if n:
        raise Conflict("group_not_empty", count=n)
    conn.execute("DELETE FROM groups WHERE id=?", (group_id,))


def set_group_targets(conn: sqlite3.Connection, group_id: int, target_ids: list[int]) -> None:
    conn.execute("DELETE FROM target_groups WHERE group_id=?", (group_id,))
    for tid in sorted(set(target_ids)):
        if not conn.execute("SELECT 1 FROM targets WHERE id=?", (tid,)).fetchone():
            raise NotFound("target")
        conn.execute("INSERT INTO target_groups(target_id, group_id) VALUES (?,?)", (tid, group_id))


def set_target_groups(conn: sqlite3.Connection, target_id: int, group_ids: list[int]) -> None:
    conn.execute("DELETE FROM target_groups WHERE target_id=?", (target_id,))
    for gid in sorted(set(group_ids)):
        if not conn.execute("SELECT 1 FROM groups WHERE id=?", (gid,)).fetchone():
            raise NotFound("group")
        conn.execute("INSERT INTO target_groups(target_id, group_id) VALUES (?,?)", (target_id, gid))


# -------------------------------------------------------------- exclusions --

JSON_FIELDS = ("selectors", "variables", "conditions", "extra_actions")


def exclusion_from_row(r: sqlite3.Row | dict) -> Exclusion:
    d = dict(r)
    for f in JSON_FIELDS:
        d[f] = db.jload(d.get(f), [])
    return Exclusion.from_dict(d)


def exclusion_dict(r: sqlite3.Row | dict) -> dict:
    d = dict(r)
    for f in JSON_FIELDS + ("raw_ids",):
        d[f] = db.jload(d.get(f), [])
    for f in ("log", "verbatim", "enabled"):
        d[f] = bool(d.get(f))
    ex = Exclusion.from_dict(d)
    d["placement"] = ex.effective_placement()
    d["effective_phase"] = ex.effective_phase() if ex.scope == "conditional" else None
    return d


def list_exclusions(conn: sqlite3.Connection, group_id: int | None = None) -> list[dict]:
    if group_id is None:
        rs = conn.execute("SELECT * FROM exclusions ORDER BY group_id, COALESCE(rule_id, 1e12), id")
    else:
        rs = conn.execute("SELECT * FROM exclusions WHERE group_id=? "
                          "ORDER BY COALESCE(rule_id, 1e12), id", (group_id,))
    return [exclusion_dict(r) for r in rs]


def get_exclusion(conn: sqlite3.Connection, exclusion_id: int) -> dict:
    r = conn.execute("SELECT * FROM exclusions WHERE id=?", (exclusion_id,)).fetchone()
    if not r:
        raise NotFound("exclusion")
    return exclusion_dict(r)


def raw_ids_of(ex: Exclusion) -> list[int]:
    """Rule IDs declared inside raw or verbatim text."""
    text = ex.raw_text if ex.scope == "raw" else (ex.source_text if ex.verbatim else None)
    if not text:
        return []
    found: list[int] = []
    for item in seclang_parser.parse_config(text).items:
        found.extend(item.ids)
    return found


def fingerprint(ex: Exclusion) -> str:
    text = render.render_directives(ex, "compact")
    norm = re.sub(r"\bid\s*:\s*'?\d+'?", "id:N", text)
    norm = re.sub(r"\s+", " ", norm).strip()
    return hashlib.sha256(norm.encode()).hexdigest()[:24]


def check_id_collisions(conn: sqlite3.Connection, ex: Exclusion, own_ids: list[int]) -> None:
    used = ids.used_rule_ids(conn, skip_exclusion=ex.id)
    clash = sorted(set(own_ids) & used)
    if clash:
        raise Conflict("rule_id_in_use", ids=clash[:10])
    if len(set(own_ids)) != len(own_ids):
        raise Conflict("rule_id_duplicated_in_text")


def save_exclusion(conn: sqlite3.Connection, ex: Exclusion, actor: str,
                   keep_rule_id: bool = False) -> int:
    """Insert or update. Allocates a rule ID for conditional exclusions.

    ``keep_rule_id`` is used by imports that keep the original IDs.
    """
    if not conn.execute("SELECT 1 FROM groups WHERE id=?", (ex.group_id,)).fetchone():
        raise NotFound("group")
    policy = ids.IdPolicy.from_conn(conn)
    previous = None
    if ex.id is not None:
        previous = conn.execute("SELECT * FROM exclusions WHERE id=?", (ex.id,)).fetchone()
        if not previous:
            raise NotFound("exclusion")

    if ex.scope == "conditional" and not ex.verbatim:
        same_group = previous is not None and previous["group_id"] == ex.group_id
        if keep_rule_id and ex.rule_id is not None:
            pass                                    # import keeping original IDs
        elif same_group and previous["rule_id"] is not None:
            ex.rule_id = previous["rule_id"]        # editing never changes the ID
        else:
            ex.rule_id = ids.next_rule_id(conn, policy, ex.group_id, skip_exclusion=ex.id)
    elif ex.scope == "conditional" and ex.verbatim:
        parsed = raw_ids_of(ex)
        ex.rule_id = parsed[0] if parsed else ex.rule_id
    else:
        ex.rule_id = None

    own = raw_ids_of(ex) if ex.scope == "raw" else []
    check_id_collisions(conn, ex, own + ([ex.rule_id] if ex.rule_id is not None else []))

    ts = db.now()
    values = {
        "group_id": ex.group_id, "scope": ex.scope, "action": ex.action if ex.scope != "raw" else None,
        "selector_type": ex.selector_type if ex.scope != "raw" else None,
        "selectors": db.jdump(ex.selectors), "variables": db.jdump(ex.variables),
        "engine_mode": ex.engine_mode, "conditions": db.jdump([c.__dict__ for c in ex.conditions]),
        "phase": ex.phase, "log": int(ex.log), "extra_actions": db.jdump(ex.extra_actions),
        "rule_id": ex.rule_id, "raw_text": ex.raw_text if ex.scope == "raw" else None,
        "placement": ex.placement if ex.scope == "raw" else None,
        "raw_ids": db.jdump(own), "source_text": ex.source_text, "verbatim": int(ex.verbatim),
        "reason": ex.reason.strip(), "reference": ex.reference.strip(),
        "expires_at": ex.expires_at or None, "enabled": int(ex.enabled), "origin": ex.origin,
        "fingerprint": fingerprint(ex), "updated_at": ts, "updated_by": actor,
    }
    if previous is None:
        values.update(created_at=ts, created_by=actor)
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = conn.execute(f"INSERT INTO exclusions({cols}) VALUES ({marks})", tuple(values.values()))
        ex.id = cur.lastrowid
    else:
        sets = ", ".join(f"{k}=?" for k in values)
        conn.execute(f"UPDATE exclusions SET {sets} WHERE id=?", (*values.values(), ex.id))
    return ex.id


def delete_exclusion(conn: sqlite3.Connection, exclusion_id: int) -> dict:
    d = get_exclusion(conn, exclusion_id)
    conn.execute("DELETE FROM exclusions WHERE id=?", (exclusion_id,))
    return d


def group_exclusions(conn: sqlite3.Connection, group_id: int, enabled_only: bool = True) -> list[Exclusion]:
    q = "SELECT * FROM exclusions WHERE group_id=?" + (" AND enabled=1" if enabled_only else "")
    return [exclusion_from_row(r) for r in conn.execute(q, (group_id,))]


# ----------------------------------------------------------------- targets --

TARGET_JSON = {"conn": {}, "layout": {}, "commands": {}, "logs": {}, "entry_files": [],
               "import_paths": []}


def target_dict(r: sqlite3.Row | dict, with_secret: bool = False) -> dict:
    d = dict(r)
    for k, default in TARGET_JSON.items():
        d[k] = db.jload(d.get(k), default)
    d["require_review"] = bool(d.get("require_review"))
    d["enabled"] = bool(d.get("enabled"))
    d["has_secret"] = bool(d.get("secret"))
    d["last_status"] = db.jload(d.get("last_status"), None)
    if not with_secret:
        d.pop("secret", None)
    return d


def list_targets(conn: sqlite3.Connection) -> list[dict]:
    targets = [target_dict(r) for r in conn.execute("SELECT * FROM targets ORDER BY name")]
    links: dict[int, list[int]] = {}
    for r in conn.execute("SELECT target_id, group_id FROM target_groups"):
        links.setdefault(r["target_id"], []).append(r["group_id"])
    for t in targets:
        t["group_ids"] = sorted(links.get(t["id"], []))
    return targets


def get_target(conn: sqlite3.Connection, target_id: int, with_secret: bool = False) -> dict:
    r = conn.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
    if not r:
        raise NotFound("target")
    t = target_dict(r, with_secret)
    t["group_ids"] = [x["group_id"] for x in conn.execute(
        "SELECT group_id FROM target_groups WHERE target_id=? ORDER BY group_id", (target_id,))]
    return t


def target_groups_for(conn: sqlite3.Connection, target_id: int) -> list[dict]:
    wanted = {r["group_id"] for r in conn.execute(
        "SELECT group_id FROM target_groups WHERE target_id=?", (target_id,))}
    return [g for g in list_groups(conn) if g["id"] in wanted]
