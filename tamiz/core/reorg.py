"""Renumber the rule IDs of a group so they sit in the group's own blocks.

Imported rules keep the IDs they had, which can be scattered or even fall in
ranges reserved for other organisations. Renumbering assigns consecutive IDs
from the start of the group's blocks, in the current order, and frees blocks
that are no longer needed.

The plan lists only the IDs that actually change, so the rules that keep
their ID do not hide the ones that move. Applying
the plan only changes the database; the targets then show pending changes and
are deployed with a normal apply, which validates and can roll back.
"""
from __future__ import annotations

import sqlite3

from .. import db
from .ids import IdPolicy, allocate_block, group_blocks
from .importer import _replace_id


def plan(conn: sqlite3.Connection, group_id: int) -> dict:
    policy = IdPolicy.from_conn(conn)
    blocks = group_blocks(conn, group_id)
    rows = db.rows(conn.execute(
        "SELECT id, rule_id, verbatim, reason FROM exclusions "
        "WHERE group_id=? AND scope='conditional' AND rule_id IS NOT NULL ORDER BY rule_id, id",
        (group_id,)))
    # IDs owned by raw rules (any group) and conditional rules of other groups
    # stay where they are.
    fixed: set[int] = set()
    for r in conn.execute("SELECT group_id, rule_id, raw_ids FROM exclusions"):
        fixed.update(db.jload(r["raw_ids"], []))
        if r["group_id"] != group_id and r["rule_id"] is not None:
            fixed.add(r["rule_id"])
    slots: list[int] = []
    for b in blocks:
        lo, hi = policy.block_range(b)
        slots.extend(i for i in range(lo, hi + 1) if i not in fixed)
    extra_blocks = 0
    while len(slots) < len(rows):
        # Not enough room: the plan needs one more block (allocated on apply).
        extra_blocks += 1
        slots.extend([-1] * policy.size)
    changes = []
    for r, new in zip(rows, slots):
        if new != r["rule_id"]:
            changes.append({"exclusion_id": r["id"], "old": r["rule_id"], "new": new,
                            "reason": r["reason"]})
    used_blocks = {policy.block_of(s) for s in slots[:len(rows)] if s > 0}
    free = [b for b in blocks if b not in used_blocks and b != blocks[0]]
    return {"group_id": group_id, "changes": changes, "extra_blocks": extra_blocks,
            "blocks_to_release": free, "total": len(rows)}


def apply(conn: sqlite3.Connection, group_id: int, actor: str) -> dict:
    p = plan(conn, group_id)
    policy = IdPolicy.from_conn(conn)
    if p["extra_blocks"]:
        for _ in range(p["extra_blocks"]):
            allocate_block(conn, policy, group_id)
        p = plan(conn, group_id)
    changes = p["changes"]
    # Two passes so that swapping IDs never violates the UNIQUE constraint.
    for c in changes:
        conn.execute("UPDATE exclusions SET rule_id=? WHERE id=?", (-c["exclusion_id"], c["exclusion_id"]))
    ts = db.now()
    for c in changes:
        r = conn.execute("SELECT verbatim, source_text FROM exclusions WHERE id=?",
                         (c["exclusion_id"],)).fetchone()
        source = r["source_text"]
        if r["verbatim"] and source:
            source = _replace_id(source, c["old"], c["new"])
        conn.execute("UPDATE exclusions SET rule_id=?, source_text=?, updated_at=?, updated_by=? "
                     "WHERE id=?", (c["new"], source, ts, actor, c["exclusion_id"]))
    for b in p["blocks_to_release"]:
        conn.execute("DELETE FROM group_blocks WHERE group_id=? AND block=?", (group_id, b))
    db.log_history(conn, actor, "renumber", "group", group_id,
                   f"{len(changes)} rule IDs changed", {"changes": changes})
    return {"changed": len(changes), "released_blocks": p["blocks_to_release"]}
