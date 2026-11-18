"""Workspace settings stored in the database and editable from the UI."""
from __future__ import annotations

import sqlite3

from .. import db

DEFAULTS: dict = {
    # Rule IDs for generated rules come from this range, split in blocks.
    # Each group gets one block (and more when it fills up).
    "id_range_start": 10_000,
    "id_range_end": 99_999,
    "block_size": 1_000,
    # "crs": one action per line, like the CRS itself.
    # "compact": all actions on one line.
    "render_style": "crs",
    # Every exclusion must say why it exists.
    "require_reason": False,
    # Reload the WAF after a successful apply by default.
    "default_reload": True,
    # Days before an exclusion's expiry date when the dashboard starts warning.
    "expiry_warning_days": 14,
    # Whether the person who requested a review may approve it.
    "review_self_approve": False,
}


def get_all(conn: sqlite3.Connection) -> dict:
    values = dict(DEFAULTS)
    for r in conn.execute("SELECT key, value FROM settings"):
        if r["key"] in DEFAULTS:
            values[r["key"]] = db.jload(r["value"], DEFAULTS[r["key"]])
    return values


def validate(conn: sqlite3.Connection, new: dict) -> tuple[dict, list[dict]]:
    current = get_all(conn)
    merged = dict(current)
    errors: list[dict] = []
    for key, value in new.items():
        if key not in DEFAULTS:
            continue
        default = DEFAULTS[key]
        if isinstance(default, bool):
            merged[key] = bool(value)
        elif isinstance(default, int):
            try:
                merged[key] = int(value)
            except (TypeError, ValueError):
                errors.append({"field": key, "code": "not_a_number"})
        else:
            merged[key] = str(value)

    if merged["render_style"] not in ("crs", "compact"):
        errors.append({"field": "render_style", "code": "invalid_choice"})
    start, end, size = merged["id_range_start"], merged["id_range_end"], merged["block_size"]
    if not (1 <= start < end <= 99_999):
        errors.append({"field": "id_range_end", "code": "id_range_local_only"})
    if size < 10 or size > (end - start + 1):
        errors.append({"field": "block_size", "code": "invalid_block_size"})
    has_groups = conn.execute("SELECT 1 FROM group_blocks LIMIT 1").fetchone() is not None
    if has_groups and (size != current["block_size"]):
        errors.append({"field": "block_size", "code": "block_size_locked"})
    if has_groups and not errors:
        from .ids import IdPolicy
        policy = IdPolicy(start, end, size)
        outside = [r["block"] for r in conn.execute("SELECT block FROM group_blocks")
                   if not policy.valid_block(r["block"])]
        if outside:
            errors.append({"field": "id_range_start", "code": "range_excludes_used_blocks",
                           "params": {"blocks": outside[:10]}})
    return merged, errors


def save(conn: sqlite3.Connection, values: dict) -> None:
    for key, value in values.items():
        if key in DEFAULTS:
            conn.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)",
                         (key, db.jdump(value)))
