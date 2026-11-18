"""Rule ID allocation.

The configured range (by default 10,000-99,999, inside the 1-99,999 range the
ModSecurity project reserves for local use) is cut into aligned blocks of
``block_size`` IDs. Block *b* covers ``b*size .. (b+1)*size-1``. With the
defaults, block 12 is 12000-12999, so an ID tells at a glance which group it
belongs to.

Each group receives one block when it is created. When it fills up, the next
free block is attached to the group automatically ("continuation block").
IDs are unique across the whole workspace, so an exclusion keeps the same ID
on every target it is deployed to.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .. import db
from . import settings as settings_mod


class IdSpaceExhausted(RuntimeError):
    pass


@dataclass
class IdPolicy:
    start: int
    end: int
    size: int

    @classmethod
    def from_conn(cls, conn: sqlite3.Connection) -> "IdPolicy":
        s = settings_mod.get_all(conn)
        return cls(s["id_range_start"], s["id_range_end"], s["block_size"])

    def block_range(self, block: int) -> tuple[int, int]:
        lo = max(block * self.size, self.start, 1)
        hi = min((block + 1) * self.size - 1, self.end)
        return lo, hi

    def valid_block(self, block: int) -> bool:
        lo, hi = self.block_range(block)
        return lo <= hi

    def all_blocks(self) -> range:
        return range(self.start // self.size, self.end // self.size + 1)

    def block_of(self, rule_id: int) -> int:
        return rule_id // self.size


def used_rule_ids(conn: sqlite3.Connection, skip_exclusion: int | None = None) -> set[int]:
    used: set[int] = set()
    for r in conn.execute("SELECT id, rule_id, raw_ids FROM exclusions"):
        if skip_exclusion is not None and r["id"] == skip_exclusion:
            continue
        if r["rule_id"] is not None:
            used.add(r["rule_id"])
        used.update(db.jload(r["raw_ids"], []))
    return used


def group_blocks(conn: sqlite3.Connection, group_id: int) -> list[int]:
    return [r["block"] for r in conn.execute(
        "SELECT block FROM group_blocks WHERE group_id=? ORDER BY position", (group_id,))]


def allocate_block(conn: sqlite3.Connection, policy: IdPolicy, group_id: int) -> int:
    taken = {r["block"] for r in conn.execute("SELECT block FROM group_blocks")}
    used = used_rule_ids(conn)
    for b in policy.all_blocks():
        if b in taken or not policy.valid_block(b):
            continue
        lo, hi = policy.block_range(b)
        # Skip blocks that already contain IDs from imported or raw rules.
        if any(lo <= u <= hi for u in used):
            continue
        pos = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM group_blocks WHERE group_id=?",
                           (group_id,)).fetchone()[0]
        conn.execute("INSERT INTO group_blocks(group_id, block, position) VALUES (?,?,?)",
                     (group_id, b, pos))
        return b
    raise IdSpaceExhausted("no free block left in the configured ID range")


def next_rule_id(conn: sqlite3.Connection, policy: IdPolicy, group_id: int,
                 skip_exclusion: int | None = None, reserved: set[int] | None = None) -> int:
    """Next free ID in the group's blocks; attaches a new block when full.

    Prefers the ID after the highest one in use, so a deleted exclusion's ID
    is not handed out again right away (logs keep pointing at the old rule).
    Holes are reused only when the end of the block has been reached.
    """
    used = used_rule_ids(conn, skip_exclusion) | (reserved or set())
    for b in group_blocks(conn, group_id):
        lo, hi = policy.block_range(b)
        if lo > hi:
            continue
        in_block = [u for u in used if lo <= u <= hi]
        nxt = (max(in_block) + 1) if in_block else lo
        if nxt <= hi:
            return nxt
        for candidate in range(lo, hi + 1):
            if candidate not in used:
                return candidate
    b = allocate_block(conn, policy, group_id)
    return policy.block_range(b)[0]


def format_ranges(policy: IdPolicy, blocks: list[int]) -> str:
    parts = []
    for b in blocks:
        lo, hi = policy.block_range(b)
        if lo <= hi:
            parts.append(f"{lo}-{hi}")
    return ", ".join(parts)


def in_group_blocks(policy: IdPolicy, blocks: list[int], rule_id: int) -> bool:
    for b in blocks:
        lo, hi = policy.block_range(b)
        if lo <= rule_id <= hi:
            return True
    return False
