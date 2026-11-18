"""Load order analysis: in which order does the WAF read its rule files?

Where an exclusion is loaded decides whether it works:

* runtime exclusions (``ctl:ruleRemove...``) must be read *before* the CRS
  rules they affect. A phase-1 rule such as 911100 is evaluated in file order,
  so an exclusion loaded after it never runs in time;
* configure-time exclusions (``SecRuleRemoveById`` ...) must be read *after*
  the CRS rules, because they modify rules that already exist.

Glob includes are expanded in byte order (``LC_ALL=C``), which is what both
Apache and libmodsecurity do. A file called ``custom.conf`` sorts after
``RESPONSE-999-...`` and ``APP-exclusions.conf`` sorts before ``REQUEST-901-...``;
this is why "it only works when I put it in REQUEST-900" happens.

Entry points come from the target's ``entry_files`` or, when empty, from the
discover command: ``nginx -T`` (lines ``modsecurity_rules_file``) or
``apachectl -t -D DUMP_INCLUDES`` (the complete ordered list).
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import asdict, dataclass

from ..transports.base import Transport, TransportError

INCLUDE_RE = re.compile(r"""^\s*Include(Optional)?\s+(?:"([^"]+)"|'([^']+)'|(\S+))\s*$""", re.I)
RULES_FILE_RE = re.compile(r"^\s*modsecurity_rules_file\s+[\"']?([^;\"']+?)[\"']?\s*;")
DUMP_RE = re.compile(r"^\s*\((?:\*|\d+)\)\s+(\S.*?)\s*$")
CRS_RULE_RE = re.compile(r"^(REQUEST|RESPONSE)-9\d\d(\.\d+)?-[A-Z0-9.-]+\.conf$")

MAX_FILES = 800
MAX_DEPTH = 16


@dataclass
class Entry:
    order: int
    path: str
    role: str
    depth: int
    included_from: str | None
    exists: bool = True
    scanned: bool = True
    group: str | None = None
    placement: str | None = None


def role_of(path: str, managed: dict[str, dict]) -> str:
    if path in managed:
        return "managed"
    base = posixpath.basename(path)
    if base.startswith("crs-setup.conf"):
        return "crs_setup"
    if base.startswith("REQUEST-900-EXCLUSION-RULES-BEFORE-CRS"):
        return "crs_before"
    if base.startswith("RESPONSE-999-EXCLUSION-RULES-AFTER-CRS"):
        return "crs_after"
    if CRS_RULE_RE.match(base):
        return "crs_rules"
    if "/plugins/" in path and base.endswith(("-before.conf", "-after.conf", "-config.conf")):
        return "crs_plugin"
    return "other"


def _is_glob(p: str) -> bool:
    return any(c in p for c in "*?[")


class Analyzer:
    def __init__(self, transport: Transport, include_base: str = "file", server_root: str = ""):
        self.t = transport
        self.include_base = include_base
        self.server_root = server_root
        self.cache: dict[str, str | None] = {}
        self.notes: list[dict] = []
        self.entries: list[Entry] = []

    def _fetch(self, paths: list[str]) -> None:
        need = [p for p in paths if p not in self.cache and not CRS_RULE_RE.match(posixpath.basename(p))]
        if need:
            for p, fr in self.t.read_files(need).items():
                self.cache[p] = fr.content if fr.status == "ok" else None
                if fr.status == "unreadable":
                    self.notes.append({"code": "unreadable", "path": p})

    def _resolve(self, pattern: str, including: str) -> str:
        if pattern.startswith("/"):
            return posixpath.normpath(pattern)
        if self.include_base == "server_root" and self.server_root:
            return posixpath.normpath(posixpath.join(self.server_root, pattern))
        return posixpath.normpath(posixpath.join(posixpath.dirname(including), pattern))

    def _includes(self, path: str) -> list[str]:
        content = self.cache.get(path)
        if not content:
            return []
        found = []
        logical = re.sub(r"\\[ \t]*\n", "", content)
        for line in logical.splitlines():
            m = INCLUDE_RE.match(line)
            if m:
                found.append(self._resolve(m.group(2) or m.group(3) or m.group(4), path))
        return found

    def run(self, entry_files: list[str], managed: dict[str, dict]) -> None:
        self._fetch(entry_files)
        for p in entry_files:
            self._visit(p, 0, None, managed, [])

    def _visit(self, path: str, depth: int, parent: str | None, managed, stack: list[str]) -> None:
        if len(self.entries) >= MAX_FILES:
            if not any(n["code"] == "too_many_files" for n in self.notes):
                self.notes.append({"code": "too_many_files"})
            return
        if depth > MAX_DEPTH or path in stack:
            self.notes.append({"code": "include_cycle", "path": path})
            return
        base = posixpath.basename(path)
        scanned = not CRS_RULE_RE.match(base)
        exists = path in self.cache and self.cache[path] is not None if scanned else True
        info = managed.get(path) or {}
        self.entries.append(Entry(len(self.entries) + 1, path, role_of(path, managed), depth, parent,
                                  exists, scanned, info.get("group"), info.get("placement")))
        if not scanned:
            return
        children = self._includes(path)
        globs = [c for c in children if _is_glob(c)]
        expanded = self.t.glob(globs) if globs else {}
        ordered: list[str] = []
        for c in children:
            if _is_glob(c):
                ordered.extend(sorted(expanded.get(c, []), key=lambda s: s.encode()))
            else:
                ordered.append(c)
        self._fetch(ordered)
        for c in ordered:
            self._visit(c, depth + 1, path, managed, stack + [path])


def discover_entries(transport: Transport, command: str) -> tuple[list[str], list[str] | None, dict | None]:
    """Return (entry files, complete ordered list or None, error)."""
    res = transport.run_command(command)
    if not res.ok:
        return [], None, {"code": "discover_failed", "detail": (res.stderr or res.stdout)[-600:]}
    if "DUMP_INCLUDES" in command:
        files = []
        for line in res.stdout.splitlines():
            m = DUMP_RE.match(line)
            if m:
                files.append(m.group(1))
        return [], files, None
    entries: list[str] = []
    for line in res.stdout.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = RULES_FILE_RE.match(line)
        if m and m.group(1).strip() not in entries:
            entries.append(m.group(1).strip())
    if not entries:
        return [], None, {"code": "no_rules_file_found"}
    return entries, None, None


def analyze(transport: Transport, target: dict, units: list) -> dict:
    """Build the load-order report for a target.

    ``units`` are the desired layout units (core.layout.Unit) so the report
    can say where each managed file sits and whether it is in the right place.
    """
    managed = {u.path: {"group": u.group_slug, "placement": u.placement} for u in units}
    report: dict = {"source": None, "entries": [], "checks": [], "notes": [], "crs": None}
    if not transport.remote:
        report["notes"].append({"code": "export_target"})
        return report
    cmds = target.get("commands") or {}
    entry_files = [p for p in (target.get("entry_files") or []) if p.strip()]
    an = Analyzer(transport, cmds.get("include_base") or "file", cmds.get("server_root") or "")
    try:
        if entry_files:
            report["source"] = "configured"
            an.run(entry_files, managed)
        elif cmds.get("discover"):
            entries, flat, err = discover_entries(transport, cmds["discover"])
            if err:
                report["notes"].append(err)
                return report
            if flat is not None:
                report["source"] = "dump_includes"
                for i, p in enumerate(flat):
                    info = managed.get(p) or {}
                    an.entries.append(Entry(i + 1, p, role_of(p, managed), 0, None, True, False,
                                            info.get("group"), info.get("placement")))
            else:
                report["source"] = "discovered"
                an.run(entries, managed)
        else:
            report["notes"].append({"code": "no_entry_files"})
            return report
    except TransportError as e:
        report["notes"].append({"code": e.code, "detail": e.message})
        return report

    report["entries"] = [asdict(e) for e in an.entries]
    report["notes"].extend(an.notes)
    crs_idx = [e.order for e in an.entries if e.role == "crs_rules"]
    if crs_idx:
        report["crs"] = {"first": min(crs_idx), "last": max(crs_idx), "count": len(crs_idx)}
    else:
        report["notes"].append({"code": "crs_not_found"})

    for path, info in sorted(managed.items()):
        hits = [e for e in an.entries if e.path == path]
        check = {"path": path, "group": info["group"], "placement": info["placement"]}
        if not hits:
            check.update(status="not_loaded")
        elif len(hits) > 1:
            check.update(status="loaded_twice", orders=[h.order for h in hits])
        elif report["crs"] is None:
            check.update(status="unknown", order=hits[0].order)
        else:
            o = hits[0].order
            ok = o < report["crs"]["first"] if info["placement"] == "before" else o > report["crs"]["last"]
            check.update(status="ok" if ok else "wrong_position", order=o)
        report["checks"].append(check)
    return report
