"""Import existing exclusions from a server file or pasted text.

Import is a two-step operation:

1. ``scan``: parse the text and propose one item per directive (or chain).
   Nothing is written anywhere.
2. ``commit``: the user picks items and groups; Tamiz creates exclusions.
   Structured items keep their original text (``verbatim``) so their meaning
   cannot change; items Tamiz cannot model become ``raw`` exclusions.

Optionally the original rules are *retired* from the source file. Retiring
does not happen here: it creates a retirement record that the next apply on
that target executes, in the same transaction that writes Tamiz's copy, so
the same rule ID is never loaded twice. The cut is done by exact text match
and refuses to run if the file changed since the scan.

Import never modifies existing exclusions: scanning a file again must not
change the group, or anything else, of the rules Tamiz already has.
"""
from __future__ import annotations

import posixpath
import re
import sqlite3

from .. import db
from ..seclang import parser
from ..seclang.lexer import split_lines
from ..seclang.model import Exclusion
from . import ids, store
from .plan import sha


class ImportError_(ValueError):
    def __init__(self, code: str, **params):
        super().__init__(code)
        self.code = code
        self.params = params


def _guess_group(ex: Exclusion | None, path: str | None) -> str:
    if ex is not None:
        for c in ex.conditions:
            base = c.variable.split(":", 1)[0].upper()
            if base in ("REQUEST_URI", "REQUEST_FILENAME") and c.operator in ("beginsWith", "streq") \
                    and not c.negate:
                seg = [s for s in c.value.split("/") if s]
                if seg:
                    return store.slugify(seg[0])
            if c.variable.upper() == "REQUEST_HEADERS:HOST" and c.operator in ("streq", "endsWith"):
                return store.slugify(c.value.lstrip(".").split(".")[0])
    return "imported"


def _cut_text(lines: list[str], item: parser.Item) -> str:
    first = item.comment_start if item.comment_start is not None else item.start
    return "\n".join(lines[first:item.end + 1])


def scan_text(conn: sqlite3.Connection, text: str, path: str | None = None) -> dict:
    result = parser.parse_config(text)
    lines = split_lines(text)
    existing = {r["fingerprint"]: r["id"] for r in conn.execute(
        "SELECT id, fingerprint FROM exclusions WHERE fingerprint IS NOT NULL")}
    used = ids.used_rule_ids(conn)
    name = posixpath.basename(path or "").upper()
    proposals = []
    for item in result.items:
        if item.kind not in ("exclusion", "other"):
            continue
        ex = item.exclusion
        if ex is not None:
            ex.source_text = item.text
            ex.verbatim = True
            placement = ex.effective_placement()
            fp = store.fingerprint(ex)
        else:
            low = item.directive.lower()
            after = low.startswith("secruleremove") or low.startswith("secruleupdate") \
                or "999" in name or "AFTER" in name
            placement = "after" if after else "before"
            fp = store.fingerprint(Exclusion(scope="raw", raw_text=item.text, placement=placement))
        proposals.append({
            "key": str(item.start + 1),
            "kind": item.kind,
            "structured": ex is not None,
            "raw_reason": item.raw_reason,
            "directive": item.directive,
            "text": item.text,
            "line": item.start + 1,
            "end_line": item.end + 1,
            "comment": item.comment,
            "ids": item.ids,
            "id_conflicts": sorted(set(item.ids) & used),
            "exclusion": ex.to_dict() if ex else None,
            "placement": placement,
            "group_hint": _guess_group(ex, path),
            "duplicate_of": existing.get(fp),
            "selected": item.kind == "exclusion" and existing.get(fp) is None,
            "cut_text": _cut_text(lines, item),
        })
    return {"path": path, "file_hash": sha(text), "proposals": proposals,
            "errors": result.errors, "warnings": result.warnings,
            "lines": len(lines)}


ID_TOKEN_RE = r"(\bid\s*:\s*'?){old}('?)(?!\d)"


def _replace_id(text: str, old: int, new: int) -> str:
    pattern = re.compile(ID_TOKEN_RE.format(old=old))
    out, n = pattern.subn(lambda m: f"{m.group(1)}{new}{m.group(2)}", text, count=1)
    if n != 1:
        raise ImportError_("cannot_renumber", rule=old)
    return out


def commit(conn: sqlite3.Connection, actor: str, text: str, choices: list[dict],
           renumber: bool, retire: dict | None = None) -> dict:
    """Create exclusions from chosen scan items.

    ``choices``: [{"key", "group_id"?, "new_group"?, "as_raw"?, "placement"?, "reason"?}]
    ``retire``: {"target_id", "path"} to schedule removal from the source file.
    """
    scan = scan_text(conn, text, retire["path"] if retire else None)
    by_key = {p["key"]: p for p in scan["proposals"]}
    policy = ids.IdPolicy.from_conn(conn)
    created: list[int] = []
    groups_created: dict[str, int] = {}
    group_ids: set[int] = set()
    spans: list[dict] = []
    for choice in choices:
        p = by_key.get(str(choice.get("key")))
        if p is None:
            raise ImportError_("unknown_item", key=choice.get("key"))
        gid = choice.get("group_id")
        if not gid:
            new_name = (choice.get("new_group") or p["group_hint"] or "imported").strip()
            slug = store.slugify(new_name)
            g = store.group_by_slug(conn, slug)
            if g is None and slug in groups_created:
                gid = groups_created[slug]
            elif g is None:
                gid = store.create_group(conn, new_name, slug)
                groups_created[slug] = gid
            else:
                gid = g["id"]
        group_ids.add(int(gid))
        reason = (choice.get("reason") if choice.get("reason") is not None else p["comment"]) or ""
        if p["structured"] and not choice.get("as_raw"):
            ex = Exclusion.from_dict(p["exclusion"])
            ex.id = None
            ex.group_id = int(gid)
            ex.verbatim = True
            ex.source_text = p["text"]
            if ex.scope == "conditional" and renumber and ex.rule_id is not None:
                new_id = ids.next_rule_id(conn, policy, int(gid))
                ex.source_text = _replace_id(ex.source_text, ex.rule_id, new_id)
                ex.rule_id = new_id
        else:
            ex = Exclusion(scope="raw", raw_text=p["text"],
                           placement=choice.get("placement") or p["placement"])
            ex.group_id = int(gid)
        ex.reason = reason[:500]
        ex.origin = "import"
        try:
            store.save_exclusion(conn, ex, actor, keep_rule_id=True)
        except store.Conflict as e:
            raise ImportError_(e.code, key=p["key"], line=p["line"], **e.params)
        created.append(ex.id)
        spans.append({"text": p["cut_text"], "line": p["line"]})

    retirement_id = None
    if retire and created:
        tid = int(retire["target_id"])
        cur = conn.execute("INSERT INTO retirements(target_id, path, file_hash, spans, created_at, "
                           "created_by) VALUES (?,?,?,?,?,?)",
                           (tid, retire["path"], scan["file_hash"], db.jdump(spans), db.now(), actor))
        retirement_id = cur.lastrowid
        # The rules are leaving this file, so their groups must be deployed here.
        for gid in group_ids:
            conn.execute("INSERT OR IGNORE INTO target_groups(target_id, group_id) VALUES (?,?)",
                         (tid, gid))
    db.log_history(conn, actor, "import", "exclusion", None,
                   f"{len(created)} exclusions imported" + (f" from {retire['path']}" if retire else ""),
                   {"created": created, "groups_created": list(groups_created),
                    "retirement_id": retirement_id})
    return {"created": created, "groups_created": groups_created, "retirement_id": retirement_id}
