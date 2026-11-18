"""Compare what a target should have with what it has, file by file.

For every managed unit (a whole file, or a block inside a shared file) the
plan decides one state:

``in_sync``   the server already has exactly the rendered content.
``create``    the unit does not exist on the server yet.
``update``    the server has what Tamiz wrote last time; the database changed.
``delete``    the unit is no longer wanted and the server still has what
              Tamiz wrote last time.
``drift``     the server has something Tamiz did not write (edited by hand).
              Blocked unless the user forces it for that file.
``foreign``   a file Tamiz never wrote exists where a managed file should go.
              Blocked unless forced ("take over").

Hand edits are never overwritten silently. Since the rendered content has no
timestamps, comparing hashes is exact; a date in the header would make every
file look modified on every check.

Legacy rules imported from a server can be scheduled for "retirement": their
exact text is cut from the original file in the same apply that writes the
Tamiz-managed copy, so the rule IDs never exist twice.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field

from .. import db
from ..seclang import blocks as blocks_mod
from ..seclang.lexer import lex, split_lines
from ..transports.base import FileRead, printable
from . import layout as layout_mod


def sha(text: str | None) -> str | None:
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


RETIRED_STUB = (
    "# The rules that were in this file now live in files managed by Tamiz.\n"
    "# This file is kept, empty, so that explicit Include lines keep working.\n"
)


@dataclass
class UnitState:
    group: str
    group_name: str
    placement: str
    mode: str
    state: str
    count: int = 0
    note: str = ""
    content: str | None = None      # rendered content; not sent to the browser


@dataclass
class FileOp:
    path: str
    action: str                       # none | create | update | delete | blocked
    mode: str                         # file | block | legacy
    old: str | None = None
    new: str | None = None
    units: list[UnitState] = field(default_factory=list)
    retirements: list[int] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    remote_status: str = "ok"
    forced: bool = False

    def diff(self) -> str:
        a = split_lines(printable(self.old) or "")
        b = split_lines(printable(self.new) or "")
        return "\n".join(difflib.unified_diff(a, b, self.path, self.path, lineterm="", n=3))

    def public(self) -> dict:
        d = {
            "path": self.path, "action": self.action, "mode": self.mode,
            "units": [{k: v for k, v in asdict(u).items() if k != "content"} for u in self.units],
            "retirements": self.retirements,
            "blocked": self.blocked, "remote_status": self.remote_status, "forced": self.forced,
            "old_hash": sha(self.old), "new_hash": sha(self.new),
            "diff": self.diff() if self.action not in ("none",) else "",
        }
        return d


@dataclass
class Plan:
    target_id: int
    ops: list[FileOp]
    warnings: list[dict]

    @property
    def changes(self) -> list[FileOp]:
        return [o for o in self.ops if o.action != "none"]

    @property
    def blocked(self) -> bool:
        return any(o.action == "blocked" for o in self.ops)

    @property
    def hash(self) -> str:
        data = [(o.path, o.action, sha(o.old), sha(o.new)) for o in sorted(self.ops, key=lambda o: o.path)]
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()[:32]

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for o in self.ops:
            counts[o.action] = counts.get(o.action, 0) + 1
        unit_states: dict[str, int] = {}
        for o in self.ops:
            for u in o.units:
                unit_states[u.state] = unit_states.get(u.state, 0) + 1
        if self.blocked:
            status = "blocked"
        elif self.changes:
            status = "pending"
        else:
            status = "in_sync"
        return {"status": status, "files": counts, "units": unit_states,
                "changes": len(self.changes), "hash": self.hash}

    def public(self) -> dict:
        return {"target_id": self.target_id, "summary": self.summary(),
                "ops": [o.public() for o in self.ops], "warnings": self.warnings}


# ------------------------------------------------------------- retirements --

def cut_spans(content: str, spans: list[dict]) -> str:
    """Remove exact statement texts from ``content``.

    Each span records the exact text of the statement (and the comment lines
    attached to it). The text must appear exactly once outside Tamiz blocks,
    otherwise the retirement is stale and ``ValueError`` is raised.
    """
    lines = split_lines(content)
    remove: set[int] = set()
    for span in spans:
        target = split_lines(span["text"])
        n = len(target)
        hits = [i for i in range(len(lines) - n + 1) if lines[i:i + n] == target
                and not any(j in remove for j in range(i, i + n))]
        if len(hits) != 1:
            raise ValueError("retirement_stale")
        remove.update(range(hits[0], hits[0] + n))
    kept = [ln for i, ln in enumerate(lines) if i not in remove]
    # Collapse runs of blank lines left behind by the cut.
    out: list[str] = []
    for ln in kept:
        if ln.strip() == "" and out and out[-1].strip() == "":
            continue
        out.append(ln)
    while out and out[-1].strip() == "":
        out.pop()
    text = "\n".join(out) + ("\n" if out else "")
    if not any(s.kind == "directive" for s in lex(text)) and not blocks_mod.find_blocks(text):
        return RETIRED_STUB
    return text


# -------------------------------------------------------------------- plan --

def recorded_units(conn: sqlite3.Connection, target_id: int) -> list[dict]:
    return db.rows(conn.execute("SELECT * FROM managed_files WHERE target_id=?", (target_id,)))


def pending_retirements(conn: sqlite3.Connection, target_id: int) -> list[dict]:
    rs = db.rows(conn.execute("SELECT * FROM retirements WHERE target_id=? AND status='pending' "
                              "ORDER BY id", (target_id,)))
    for r in rs:
        r["spans"] = db.jload(r["spans"], [])
    return rs


def paths_involved(conn: sqlite3.Connection, target: dict) -> list[str]:
    paths = layout_mod.managed_paths(conn, target)
    paths |= {r["path"] for r in pending_retirements(conn, target["id"])}
    return sorted(paths)


def exported_reads(conn: sqlite3.Connection, target: dict, paths: list[str]) -> dict[str, FileRead]:
    """For export targets: the last content marked as deployed."""
    reads: dict[str, FileRead] = {}
    rec = recorded_units(conn, target["id"])
    for p in paths:
        units = [r for r in rec if r["path"] == p and r["last_applied_content"] is not None]
        if not units:
            reads[p] = FileRead(p, "missing")
        elif units[0]["mode"] == "file":
            reads[p] = FileRead(p, "ok", units[0]["last_applied_content"])
        else:
            units.sort(key=lambda r: r["group_slug"])
            text = blocks_mod.apply_blocks("", [(u["group_slug"], u["last_applied_content"]) for u in units])
            reads[p] = FileRead(p, "ok", text)
    return reads


def compute(conn: sqlite3.Connection, target: dict, reads: dict[str, FileRead],
            force: set[str] | None = None) -> Plan:
    force = force or set()
    desired = layout_mod.desired_units(conn, target)
    recorded = recorded_units(conn, target["id"])
    retirements = pending_retirements(conn, target["id"])
    warnings: list[dict] = []

    paths = sorted({u.path for u in desired} | {r["path"] for r in recorded}
                   | {r["path"] for r in retirements})
    seen_paths: dict[str, str] = {}
    for u in desired:
        key = seen_paths.setdefault(u.path, u.group_slug)
        if key != u.group_slug and u.mode == "file":
            warnings.append({"code": "path_collision", "path": u.path})

    ops: list[FileOp] = []
    for path in paths:
        read = reads.get(path) or FileRead(path, "missing")
        d_units = [u for u in desired if u.path == path]
        r_units = [r for r in recorded if r["path"] == path]
        rets = [r for r in retirements if r["path"] == path]
        modes = {u.mode for u in d_units} | {r["mode"] for r in r_units}
        mode = modes.pop() if len(modes) == 1 else ("legacy" if not modes else "mixed")
        op = FileOp(path, "none", mode, old=read.content, remote_status=read.status,
                    forced=path in force)
        if read.status in ("unreadable", "notfile"):
            op.blocked.append(read.status)
        if mode == "mixed":
            op.blocked.append("mixed_modes")
        if not op.blocked:
            try:
                if mode == "file":
                    _plan_file(op, d_units, r_units)
                elif mode == "block":
                    _plan_blocks(op, d_units, r_units, warnings)
                if rets:
                    base = op.new if op.new is not None else op.old
                    if base is None:
                        op.blocked.append("retirement_file_missing")
                    else:
                        if mode == "file" and d_units:
                            op.blocked.append("retirement_on_managed_file")
                        else:
                            spans = [s for r in rets for s in r["spans"]]
                            op.new = cut_spans(base, spans)
                            op.retirements = [r["id"] for r in rets]
                            if mode == "legacy":
                                op.units.append(UnitState("", "", "", "legacy", "retire",
                                                          len(spans)))
            except blocks_mod.BlockError as e:
                op.blocked.append(f"markers:{e.code}:{e.line + 1}")
            except ValueError as e:
                op.blocked.append(str(e))
        _decide(op)
        ops.append(op)
    return Plan(target["id"], ops, warnings)


def _decide(op: FileOp) -> None:
    unforced = [b for b in op.blocked if not (op.forced and b in ("drift", "foreign"))]
    if unforced:
        op.action = "blocked"
        return
    if op.new is None and op.old is None:
        op.action = "none"
    elif op.new is None:
        op.action = "delete"
    elif op.old is None:
        op.action = "create"
    elif op.new == op.old:
        op.action = "none"
    else:
        op.action = "update"


def _unit_state(desired: str | None, current: str | None, last_hash: str | None) -> str:
    if desired is not None:
        if current == desired:
            return "in_sync"
        if current is None:
            return "create"
        if last_hash is not None and sha(current) == last_hash:
            return "update"
        return "drift" if last_hash is not None else "foreign"
    if current is None:
        return "gone"
    if last_hash is not None and sha(current) == last_hash:
        return "delete"
    return "drift"


def _plan_file(op: FileOp, d_units, r_units) -> None:
    d = d_units[0] if d_units else None
    r = r_units[0] if r_units else None
    current = op.old
    last = r["last_applied_hash"] if r else None
    state = _unit_state(d.content if d else None, current, last)
    if state == "foreign" and current is not None and "Managed by Tamiz" in current[:300]:
        state = "drift"   # written by Tamiz before (another database, a restore ...)
    elif state == "foreign" and current is not None and not current.strip():
        state = "update"  # an empty file (e.g. touched so an Include glob matches): nothing to lose
    unit = UnitState(d.group_slug if d else r["group_slug"], d.group_name if d else "",
                     d.placement if d else r["placement"], "file", state, d.count if d else 0,
                     content=d.content if d else None)
    op.units.append(unit)
    if state in ("drift", "foreign"):
        op.blocked.append(state)
    if d is not None:
        op.new = d.content
    elif state in ("delete", "drift"):
        op.new = None
    else:
        op.new = current


def _plan_blocks(op: FileOp, d_units, r_units, warnings) -> None:
    current = op.old
    existing = blocks_mod.find_blocks(current) if current is not None else {}
    d_by = {u.group_slug: u for u in d_units}
    r_by = {r["group_slug"]: r for r in r_units}
    changes: list[tuple[str, str | None]] = []
    order = sorted(d_units, key=lambda u: (u.order, u.group_slug))
    slugs = [u.group_slug for u in order] + sorted(s for s in r_by if s not in d_by)
    for slug in slugs:
        d = d_by.get(slug)
        r = r_by.get(slug)
        cur = existing[slug].text if slug in existing else None
        state = _unit_state(d.content if d else None, cur, r["last_applied_hash"] if r else None)
        if state == "foreign":
            state = "drift"   # a block with our markers that this database did not write
        op.units.append(UnitState(slug, d.group_name if d else "", d.placement if d else r["placement"],
                                  "block", state, d.count if d else 0,
                                  content=d.content if d else None))
        if state == "drift":
            op.blocked.append("drift")
        if state in ("create", "update") or (state == "drift" and d is not None):
            changes.append((slug, d.content))
        elif state in ("delete",) or (state == "drift" and d is None):
            changes.append((slug, None))
    for slug in existing:
        if slug not in d_by and slug not in r_by:
            warnings.append({"code": "unknown_block", "path": op.path, "group": slug})
    if current is None and not d_units:
        op.new = None
        return
    op.new = blocks_mod.apply_blocks(current or "", changes) if changes else current
    if op.new == "" and current is None:
        op.new = None


def record_check(conn: sqlite3.Connection, target: dict, plan: Plan | None, error: str | None) -> None:
    """Remember the result of a check for the dashboard (no server access)."""
    ts = db.now()
    status = plan.summary() if plan is not None else {"status": "error"}
    conn.execute("UPDATE targets SET last_check_at=?, last_check_error=?, last_status=? WHERE id=?",
                 (ts, error, db.jdump(status), target["id"]))
    if plan is None:
        return
    for op in plan.ops:
        for u in op.units:
            if not u.group:
                continue
            conn.execute("UPDATE managed_files SET remote_state=?, remote_checked_at=? "
                         "WHERE target_id=? AND path=? AND group_slug=?",
                         (u.state, ts, target["id"], op.path, u.group))
