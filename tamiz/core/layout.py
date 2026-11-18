"""Where a target's managed files live, and what goes in them.

Two layouts:

``per_group``
    One file per group and placement, from path templates such as
    ``/etc/nginx/modsec/tamiz/before/{block}-{group}.conf``. Tamiz owns these
    files entirely. The administrator adds two ``Include`` lines once (one
    before the CRS, one after).

``shared``
    Two existing files (one loaded before the CRS, one after) in which Tamiz
    owns only its marked blocks, one per group. For setups that can only load
    exclusions from fixed files, like ``REQUEST-900-...`` and
    ``RESPONSE-999-...``.

Template placeholders: ``{group}`` (group slug, required), ``{block}`` (the
group's first ID block, zero-padded to 3 digits) and ``{placement}``.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..seclang import render
from . import settings as settings_mod
from . import store

PLACEHOLDERS = ("{group}", "{block}", "{placement}")

# ModSecurity v3 refuses ``Include dir/*.conf`` when the glob matches nothing,
# so in the per-group layout Tamiz keeps one placeholder file in each
# directory it writes to. Its name comes from the same template, so it
# matches the same Include glob as the real files.
KEEP_SLUG = "tamiz-keep"
KEEP_CONTENT = (
    "# Placeholder managed by Tamiz. It keeps the Include glob for this directory\n"
    "# matching at least one file: ModSecurity v3 rejects an Include with no matches.\n"
)


@dataclass
class Unit:
    path: str
    mode: str          # file | block
    group_slug: str
    group_name: str
    placement: str
    content: str
    count: int
    order: int         # first ID block, for stable ordering of blocks


def validate_layout(layout: dict, transport: str) -> list[dict]:
    errors: list[dict] = []
    mode = layout.get("mode")
    if mode not in ("per_group", "shared"):
        return [{"field": "layout.mode", "code": "invalid_choice"}]
    before = (layout.get("before") or "").strip()
    after = (layout.get("after") or "").strip()
    for field, value in (("layout.before", before), ("layout.after", after)):
        if not value:
            errors.append({"field": field, "code": "required"})
            continue
        if not value.startswith("/") or any(c in value for c in "\t\n\r\"'`$\\;|&<>"):
            errors.append({"field": field, "code": "invalid_path"})
        if "/../" in value + "/" or "/./" in value:
            errors.append({"field": field, "code": "invalid_path"})
        if mode == "per_group" and "{group}" not in value:
            errors.append({"field": field, "code": "template_needs_group"})
        if mode == "shared" and any(p in value for p in PLACEHOLDERS):
            errors.append({"field": field, "code": "shared_has_no_placeholders"})
        stripped = value
        for p in PLACEHOLDERS:
            stripped = stripped.replace(p, "")
        if "{" in stripped or "}" in stripped:
            errors.append({"field": field, "code": "unknown_placeholder"})
    if before and before == after:
        errors.append({"field": "layout.after", "code": "before_after_same"})
    if mode == "per_group" and before and after:
        a = before.replace("{placement}", "before")
        b = after.replace("{placement}", "after")
        if a == b:
            errors.append({"field": "layout.after", "code": "before_after_same"})
    return errors


def path_for(layout: dict, group: dict, placement: str) -> str:
    template = layout["before"] if placement == "before" else layout["after"]
    if layout.get("mode") == "shared":
        return template
    block = f"{group['blocks'][0]:03d}" if group.get("blocks") else "000"
    return (template.replace("{group}", group["slug"]).replace("{block}", block)
            .replace("{placement}", placement))


def desired_units(conn: sqlite3.Connection, target: dict) -> list[Unit]:
    style = settings_mod.get_all(conn)["render_style"]
    layout = target["layout"]
    mode = "block" if layout.get("mode") == "shared" else "file"
    units: list[Unit] = []
    for g in store.target_groups_for(conn, target["id"]):
        exclusions = store.group_exclusions(conn, g["id"])
        for placement in ("before", "after"):
            chosen = [e for e in exclusions if e.effective_placement() == placement]
            if not chosen:
                continue
            if mode == "file":
                content = render.render_file(g, placement, chosen, style)
            else:
                content = render.render_block(g, placement, chosen, style)
            units.append(Unit(path_for(layout, g, placement), mode, g["slug"], g["name"],
                              placement, content, len(chosen),
                              g["blocks"][0] if g["blocks"] else 0))
    if mode == "file":
        keep = {"slug": KEEP_SLUG, "blocks": [0]}
        for placement in ("before", "after"):
            path = path_for(layout, keep, placement)
            if not any(u.path == path for u in units):
                units.append(Unit(path, "file", f"{KEEP_SLUG}-{placement}", "", placement,
                                  KEEP_CONTENT, 0, -1))
    return units


def managed_paths(conn: sqlite3.Connection, target: dict) -> set[str]:
    paths = {u.path for u in desired_units(conn, target)}
    paths |= {r["path"] for r in conn.execute(
        "SELECT path FROM managed_files WHERE target_id=?", (target["id"],))}
    return paths
