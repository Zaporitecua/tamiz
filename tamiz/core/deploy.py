"""Talking to targets: check, apply, rollback, verify, diagnose.

An apply runs these steps, all recorded in the ``applies`` table:

1. ``connect``     open the transport; pin the SSH host key on first use.
2. ``plan``        re-read the server and recompute the plan. It must match
                   the plan the user reviewed (same hash), otherwise abort.
3. ``precheck``    run the validate command *before* touching anything. If the
                   configuration is already broken, stop: a rollback could
                   not bring it back to a valid state anyway.
4. ``snapshot``    store the current content of every file about to change.
5. ``write``       write each file atomically (see transports/scripts.py).
6. ``validate``    run the validate command. On failure, restore every
                   snapshot, validate again and do not reload.
7. ``reload``      run the reload command (optional per apply).
8. ``verify``      check that what is on disk is really loaded: SELinux labels,
                   position in the load order, and the rule count nginx logs.
                   "The file is on disk" is not the same as "the rule is
                   active".
9. bookkeeping     remember what was written, to detect hand edits later.

Only one operation runs per target at a time (in-process lock).
"""
from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from .. import db
from ..transports import Transport, TransportError, for_target
from ..transports.base import CmdResult, printable
from . import layout as layout_mod
from . import loadorder, plan as plan_mod, secrets, store

_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()

RULES_LOADED_RE = re.compile(r"rules loaded inline/local/remote: (\d+)/(\d+)/(\d+)")


SUMMARIES = {
    "connect_failed": "could not connect: {message}",
    "plan_changed": "the server or the exclusions changed since the plan was shown",
    "plan_blocked": "some files are blocked (hand edits or unknown files)",
    "nothing": "nothing to change",
    "config_invalid": "the WAF configuration was already invalid before any change",
    "not_writable": "cannot write {paths}; give the connecting user write access or use sudo mode 'all'",
    "write_failed": "could not write {path}",
    "rolled_back": "validation failed; previous files restored",
    "rollback_failed": "validation failed and the previous state could not be restored",
    "reload_failed": "files written and valid, but the reload command failed",
    "updated": "{n} files updated",
    "updated_no_reload": "{n} files updated, not reloaded",
    "transport_error": "{message}",
}


class Summary:
    def __init__(self):
        self.code = ""
        self.params: dict = {}

    def set(self, code: str, **params) -> None:
        self.code, self.params = code, params

    @property
    def text(self) -> str:
        return SUMMARIES.get(self.code, self.code).format(**self.params) if self.code else ""


class DeployError(Exception):
    def __init__(self, code: str, message: str = "", **params):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.params = params


def target_lock(target_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(target_id, threading.Lock())


@dataclass
class Step:
    name: str
    status: str = "ok"                  # ok | failed | skipped | warning
    detail: str = ""
    commands: list[dict] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def add(self, res: CmdResult) -> CmdResult:
        self.commands.append(res.summary())
        return res

    def public(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "commands": self.commands, "data": self.data}


def open_target(conn: sqlite3.Connection, target_id: int) -> tuple[dict, Transport]:
    target = store.get_target(conn, target_id, with_secret=True)
    try:
        secret = secrets.decrypt(target.pop("secret", None))
    except secrets.SecretUnreadable:
        raise TransportError("secret_unreadable", "stored credentials cannot be decrypted with the "
                             "current key: edit the target and enter them again")
    return target, for_target(target, secret)


def persist_host_key(conn: sqlite3.Connection, target: dict, t: Transport) -> None:
    if t.learned_host_key and t.learned_host_key != target.get("host_key"):
        conn.execute("UPDATE targets SET host_key=? WHERE id=?", (t.learned_host_key, target["id"]))
        target["host_key"] = t.learned_host_key


def read_state(conn: sqlite3.Connection, target: dict, t: Transport) -> dict:
    paths = plan_mod.paths_involved(conn, target)
    if not t.remote:
        return plan_mod.exported_reads(conn, target, paths)
    return t.read_files(paths)


# ------------------------------------------------------------------- check --

def check(conn: sqlite3.Connection, target_id: int, force: set[str] | None = None) -> plan_mod.Plan:
    target, t = open_target(conn, target_id)
    try:
        with t:
            persist_host_key(conn, target, t)
            reads = read_state(conn, target, t)
    except TransportError as e:
        plan_mod.record_check(conn, target, None, e.message)
        raise
    p = plan_mod.compute(conn, target, reads, force)
    plan_mod.record_check(conn, target, p, None)
    return p


# ------------------------------------------------------------------- apply --

def rules_loaded(output: str) -> list[int] | None:
    """Rule count libmodsecurity prints while loading the configuration.

    nginx with the ModSecurity connector prints
    ``rules loaded inline/local/remote: 0/920/0`` on every ``nginx -t``.
    Comparing the count before and after an apply reveals files that are on
    disk but were not loaded (wrong SELinux label, missing Include ...).
    """
    found = RULES_LOADED_RE.findall(output or "")
    return [int(x) for x in found[-1]] if found else None


def _directive_count(text: str | None) -> int:
    if not text:
        return 0
    from ..seclang.parser import parse_config
    return sum(1 for i in parse_config(text).items
               if i.kind in ("exclusion", "other") and i.directive.lower() in ("secrule", "secaction"))


def _write(t: Transport, op: plan_mod.FileOp, content: str | None, mkdirs: bool, step: Step) -> bool:
    if content is None:
        res = step.add(t.remove_file(op.path))
    else:
        res = step.add(t.write_file(op.path, content, mkdirs=mkdirs))
    if res.ok and content is not None:
        info = dict(line.split("=", 1) for line in res.stdout.splitlines() if "=" in line)
        if info.get("selinux") == "relabel-failed":
            step.status = "warning"
            step.data.setdefault("selinux", []).append({"path": op.path, "status": "relabel_failed",
                                                        "label": info.get("label", "")})
        elif info.get("selinux") not in (None, "off"):
            step.data.setdefault("selinux", []).append({"path": op.path, "status": info["selinux"],
                                                        "label": info.get("label", "")})
    return res.ok


def _rollback(t: Transport, written: list[plan_mod.FileOp], steps: list[Step]) -> bool:
    step = Step("rollback")
    steps.append(step)
    ok = True
    for op in reversed(written):
        if not _write(t, op, op.old, False, step):
            ok = False
    if not ok:
        step.status = "failed"
        step.detail = "some files could not be restored"
    return ok


def apply(conn: sqlite3.Connection, target_id: int, actor: str, plan_hash: str,
          reload: bool = True, force: set[str] | None = None,
          review_id: int | None = None) -> dict:
    lock = target_lock(target_id)
    if not lock.acquire(blocking=False):
        raise DeployError("busy", "another operation is running on this target")
    try:
        return _apply(conn, target_id, actor, plan_hash, reload, force or set(), review_id)
    finally:
        lock.release()


def _apply(conn, target_id, actor, plan_hash, reload, force, review_id) -> dict:
    target, t = open_target(conn, target_id)
    if not t.remote:
        raise DeployError("export_target", "export targets are deployed with a bundle")
    if not target["enabled"]:
        raise DeployError("target_disabled")
    if target["require_review"]:
        _check_review(conn, target_id, review_id, plan_hash)

    cmds = target.get("commands") or {}
    started = db.now()
    cur = conn.execute("INSERT INTO applies(target_id, actor, started_at, status, reload, plan_hash, "
                       "review_id) VALUES (?,?,?,?,?,?,?)",
                       (target_id, actor, started, "running", int(reload), plan_hash, review_id))
    apply_id = cur.lastrowid
    steps: list[Step] = []
    status = "failed"
    summary = Summary()
    plan = None
    try:
        step = Step("connect")
        steps.append(step)
        try:
            t.open()
        except TransportError as e:
            step.status, step.detail = "failed", e.message
            summary.set("connect_failed", message=e.message)
            raise _Stop()
        persist_host_key(conn, target, t)

        step = Step("plan")
        steps.append(step)
        reads = read_state(conn, target, t)
        plan = plan_mod.compute(conn, target, reads, force)
        step.data = plan.summary()
        if plan.hash != plan_hash:
            step.status, step.detail = "failed", "plan_changed"
            summary.set("plan_changed")
            raise _Stop()
        if plan.blocked:
            step.status, step.detail = "failed", "plan_blocked"
            summary.set("plan_blocked")
            raise _Stop()
        changes = plan.changes
        if not changes:
            step.detail = "nothing_to_do"
            _bookkeeping(conn, target, plan)
            status = "ok"
            summary.set("nothing")
            raise _Stop()

        validate_cmd = (cmds.get("validate") or "").strip()
        step = Step("precheck")
        steps.append(step)
        counts: dict = {}
        if validate_cmd:
            res = step.add(t.run_command(validate_cmd))
            counts["before"] = rules_loaded(res.stdout + res.stderr)
            if not res.ok:
                step.status = "failed"
                step.detail = "config_invalid_before_apply"
                summary.set("config_invalid")
                raise _Stop()
        else:
            step.status, step.detail = "skipped", "no_validate_command"

        step = Step("permissions")
        steps.append(step)
        mkdirs = bool((target.get("layout") or {}).get("mkdirs"))
        perms = t.writable([op.path for op in changes], mkdirs)
        denied = {p: v for p, v in perms.items() if v[0] != "ok"}
        if denied:
            step.status = "failed"
            step.detail = "not_writable"
            step.data = {"paths": [{"path": p, "problem": v[0], "detail": v[1]} for p, v in denied.items()],
                         "user_mode": t.sudo_mode}
            summary.set("not_writable", paths=", ".join(sorted(denied)))
            raise _Stop()

        step = Step("snapshot")
        steps.append(step)
        for op in changes:
            conn.execute("INSERT INTO snapshots(apply_id, target_id, path, existed, content, taken_at) "
                         "VALUES (?,?,?,?,?,?)", (apply_id, target_id, op.path,
                                                  int(op.old is not None), op.old, db.now()))
        step.data = {"files": len(changes)}

        step = Step("write")
        steps.append(step)
        written: list[plan_mod.FileOp] = []
        for op in changes:
            ok = _write(t, op, op.new, mkdirs and op.mode == "file", step)
            if not ok:
                step.status = "failed"
                step.detail = op.path
                _rollback(t, written + [op], steps)
                summary.set("write_failed", path=op.path)
                raise _Stop()
            written.append(op)

        step = Step("validate")
        steps.append(step)
        if validate_cmd:
            res = step.add(t.run_command(validate_cmd))
            counts["after"] = rules_loaded(res.stdout + res.stderr)
            if not res.ok:
                step.status = "failed"
                restored = _rollback(t, written, steps)
                again = Step("revalidate")
                steps.append(again)
                res2 = again.add(t.run_command(validate_cmd))
                again.status = "ok" if res2.ok else "failed"
                status = "rolled_back" if restored and res2.ok else "rollback_failed"
                summary.set(status)
                raise _Stop()
        else:
            step.status, step.detail = "skipped", "no_validate_command"

        reload_cmd = (cmds.get("reload") or "").strip()
        step = Step("reload")
        steps.append(step)
        reloaded = False
        if reload and reload_cmd:
            res = step.add(t.run_command(reload_cmd))
            if not res.ok:
                step.status = "failed"
                status = "reload_failed"
                summary.set("reload_failed")
                _bookkeeping(conn, target, plan)
                raise _Stop()
            reloaded = True
        else:
            step.status = "skipped"
            step.detail = "reload_disabled" if not reload else "no_reload_command"

        verify = _verify(conn, t, target, plan, written, counts)
        steps.append(verify)
        _bookkeeping(conn, target, plan)
        status = "ok" if verify.status == "ok" else "ok_with_warnings"
        n = len(changes)
        summary.set("updated" if reloaded else "updated_no_reload", n=n)
        if review_id:
            conn.execute("UPDATE reviews SET status='applied' WHERE id=?", (review_id,))
    except _Stop:
        pass
    except TransportError as e:
        steps.append(Step("error", "failed", e.message))
        summary.set("transport_error", message=e.message)
        status = "failed"
    finally:
        t.close()
        conn.execute("UPDATE applies SET finished_at=?, status=?, steps=?, summary=?, summary_code=?, "
                     "summary_params=? WHERE id=?",
                     (db.now(), status, db.jdump([s.public() for s in steps]), summary.text,
                      summary.code, db.jdump(summary.params), apply_id))
        db.log_history(conn, actor, "apply", "target", target_id,
                       f"{target['name']}: {summary.text}",
                       {"apply_id": apply_id, "status": status, "target": target["name"],
                        "code": summary.code, "params": summary.params},
                       ok=status in ("ok", "ok_with_warnings"))
        if plan is not None and status in ("ok", "ok_with_warnings"):
            try:
                reads_after = {op.path: _after(op) for op in plan.ops}
                plan_mod.record_check(conn, target, plan_mod.compute(conn, target, reads_after), None)
            except Exception:
                pass
    return {"apply_id": apply_id, "status": status, "summary": summary.text,
            "summary_code": summary.code, "summary_params": summary.params,
            "steps": [s.public() for s in steps]}


class _Stop(Exception):
    pass


def _after(op: plan_mod.FileOp):
    from ..transports.base import FileRead
    content = op.new if op.action != "none" else op.old
    return FileRead(op.path, "ok" if content is not None else "missing", content)


def _check_review(conn, target_id: int, review_id: int | None, plan_hash: str) -> None:
    if not review_id:
        raise DeployError("review_required", "this target requires an approved review")
    r = conn.execute("SELECT * FROM reviews WHERE id=? AND target_id=?", (review_id, target_id)).fetchone()
    if not r or r["status"] != "approved":
        raise DeployError("review_not_approved")
    if r["plan_hash"] != plan_hash:
        raise DeployError("review_plan_mismatch", "the approved plan differs from the current one")


def _verify(conn, t: Transport, target: dict, plan: plan_mod.Plan, written, counts: dict) -> Step:
    step = Step("verify")
    present = [op.path for op in written if op.new is not None]
    checks: dict = {}
    try:
        se = t.selinux_verify(present) if present else {"enabled": False, "files": {}}
        checks["selinux"] = se
        bad = [p for p, f in se["files"].items() if f["status"] == "mislabeled"]
        if bad:
            step.status = "warning"
            step.detail = "mislabeled"
    except TransportError as e:
        checks["selinux"] = {"error": e.message}

    cmds = target.get("commands") or {}
    if target.get("entry_files") or cmds.get("discover"):
        units = layout_mod.desired_units(conn, target)
        report = loadorder.analyze(t, target, units)
        problems = [c for c in report["checks"] if c["status"] in ("not_loaded", "wrong_position",
                                                                   "loaded_twice")]
        checks["load_order"] = {"checks": report["checks"], "notes": report["notes"]}
        if problems:
            step.status = "warning"
            step.detail = step.detail or "load_order"
    else:
        checks["load_order"] = {"skipped": "no_entry_files"}

    before, after = counts.get("before"), counts.get("after")
    if before is not None and after is not None:
        expected = sum(_directive_count(op.new) - _directive_count(op.old) for op in written)
        observed = sum(after) - sum(before)
        checks["rules_loaded"] = {"before": before, "after": after, "expected_delta": expected,
                                  "observed_delta": observed}
        if expected != 0 and observed == 0:
            step.status = "warning"
            step.detail = step.detail or "rules_not_loaded"
    step.data = checks
    return step


def _bookkeeping(conn: sqlite3.Connection, target: dict, plan: plan_mod.Plan) -> None:
    ts = db.now()
    for op in plan.ops:
        if op.action == "blocked":
            continue
        for u in op.units:
            if not u.group:
                continue
            if u.content is not None:
                conn.execute(
                    "INSERT INTO managed_files(target_id, path, mode, group_slug, placement, "
                    "last_applied_hash, last_applied_at, last_applied_content, remote_state) "
                    "VALUES (?,?,?,?,?,?,?,?, 'in_sync') "
                    "ON CONFLICT(target_id, path, group_slug) DO UPDATE SET mode=excluded.mode, "
                    "placement=excluded.placement, last_applied_hash=excluded.last_applied_hash, "
                    "last_applied_at=excluded.last_applied_at, "
                    "last_applied_content=excluded.last_applied_content, remote_state='in_sync'",
                    (target["id"], op.path, u.mode, u.group, u.placement, plan_mod.sha(u.content),
                     ts, u.content))
            else:
                conn.execute("DELETE FROM managed_files WHERE target_id=? AND path=? AND group_slug=?",
                             (target["id"], op.path, u.group))
        for rid in op.retirements:
            conn.execute("UPDATE retirements SET status='done', done_at=? WHERE id=?", (ts, rid))


# ------------------------------------------------------------ export flow --

def mark_deployed(conn: sqlite3.Connection, target_id: int, actor: str, plan_hash: str) -> dict:
    target = store.get_target(conn, target_id)
    if target["transport"] != "export":
        raise DeployError("not_export_target")
    t = for_target(target, {})
    reads = read_state(conn, target, t)
    plan = plan_mod.compute(conn, target, reads)
    if plan.hash != plan_hash:
        raise DeployError("plan_changed")
    if plan.blocked:
        raise DeployError("plan_blocked")
    _bookkeeping(conn, target, plan)
    reads_after = {op.path: _after(op) for op in plan.ops}
    plan_mod.record_check(conn, target, plan_mod.compute(conn, target, reads_after), None)
    db.log_history(conn, actor, "mark_deployed", "target", target_id,
                   f"{target['name']}: {len(plan.changes)} files marked as deployed",
                   {"target": target["name"], "files": len(plan.changes)})
    return {"status": "ok", "files": len(plan.changes)}


def bundle(conn: sqlite3.Connection, target_id: int) -> tuple[bytes, str]:
    """A zip with every desired file of the target (export or any other)."""
    import io
    import json
    import zipfile
    from ..seclang import blocks as blocks_mod
    target = store.get_target(conn, target_id)
    units = layout_mod.desired_units(conn, target)
    files: dict[str, str] = {}
    for path in sorted({u.path for u in units}):
        mine = [u for u in units if u.path == path]
        if mine[0].mode == "file":
            files[path] = mine[0].content
        else:
            mine.sort(key=lambda u: (u.order, u.group_slug))
            files[path] = blocks_mod.apply_blocks("", [(u.group_slug, u.content) for u in mine])
    buf = io.BytesIO()
    mode = (target.get("layout") or {}).get("mode", "")
    manifest = {"target": target["name"], "generated_by": "tamiz", "layout": mode,
                "files": [{"path": p, "sha256": plan_mod.sha(c),
                           "content": "whole_file" if mode != "shared" else "tamiz_blocks_only"}
                          for p, c in files.items()]}
    if mode == "shared":
        how = ("Layout: shared. Each file here contains ONLY Tamiz's blocks, not the rest of\n"
               "the real file. Do not copy it over the real file: in the real file, replace\n"
               "each block between '# ---- tamiz:begin group=X ----' and\n"
               "'# ---- tamiz:end group=X ----' with the block of the same group from here,\n"
               "add blocks that are new and remove blocks whose group is gone.\n")
    else:
        how = ("Layout: per_group. Each file is complete: copy it in place. Delete files of\n"
               "this target's directories that are not in this archive (groups removed).\n")
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, content in files.items():
            z.writestr(path.lstrip("/"), content.encode("utf-8", "surrogateescape"))
        z.writestr("tamiz-manifest.json", json.dumps(manifest, indent=2))
        z.writestr("TAMIZ-README.txt", (
            f"Files generated by Tamiz for target '{target['name']}'.\n\n"
            "Paths inside this archive are the absolute paths on the WAF host.\n\n"
            + how +
            "\nThen validate the configuration, reload the WAF and mark the plan as\n"
            "deployed in Tamiz so it can detect later edits.\n"))
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", target["name"]) + "-tamiz.zip"
    return buf.getvalue(), name


# ---------------------------------------------------------- other actions --

def run_named(conn: sqlite3.Connection, target_id: int, which: str, actor: str) -> dict:
    """Run the validate or reload command alone."""
    target, t = open_target(conn, target_id)
    cmd = ((target.get("commands") or {}).get(which) or "").strip()
    if not cmd:
        raise DeployError("no_command", f"no {which} command configured")
    lock = target_lock(target_id)
    if not lock.acquire(blocking=False):
        raise DeployError("busy")
    try:
        with t:
            persist_host_key(conn, target, t)
            res = t.run_command(cmd)
    finally:
        lock.release()
    db.log_history(conn, actor, which, "target", target_id,
                   f"{target['name']}: {which} {'ok' if res.ok else 'failed'}",
                   {"target": target["name"], **res.summary()}, ok=res.ok)
    return res.summary()


def diagnose(conn: sqlite3.Connection, target_id: int) -> dict:
    target, t = open_target(conn, target_id)
    report: dict = {"steps": []}
    if not t.remote:
        report["steps"].append({"name": "transport", "status": "skipped", "detail": "export_target"})
        return report
    units = layout_mod.desired_units(conn, target)
    lay = target.get("layout") or {}
    dirs = sorted({p.rsplit("/", 1)[0] for p in
                   [u.path for u in units] + [lay.get("before", ""), lay.get("after", "")]
                   if p.startswith("/") and "{" not in p.rsplit("/", 1)[0]})
    try:
        t.open()
    except TransportError as e:
        report["steps"].append({"name": "connect", "status": "failed", "detail": e.message,
                                "params": e.params})
        return report
    try:
        persist_host_key(conn, target, t)
        from ..transports.ssh import fingerprint
        key = target.get("host_key") or ""
        shown = ", ".join(f"{k}: {fingerprint(v)}" for k, v in db.jload(key, {}).items()) \
            if key.startswith("{") else (fingerprint(key) if key else "")
        report["steps"].append({"name": "connect", "status": "ok", "detail": shown})
        info = t.diagnose(dirs)
        report["host"] = info
        dir_problems = [d for d in info.get("dirs", []) if d["state"] != "exists" or not d["writable"]]
        need_write = t.sudo_mode != "all"
        report["steps"].append({"name": "directories",
                                "status": "warning" if dir_problems and need_write else "ok",
                                "data": info.get("dirs", [])})
        if t.sudo_mode != "none":
            res = t.check_sudo()
            report["steps"].append({"name": "sudo", "status": "ok" if res.ok else "failed",
                                    "detail": printable(res.stderr.strip())[-300:]})
        cmds = target.get("commands") or {}
        if (cmds.get("validate") or "").strip():
            res = t.run_command(cmds["validate"].strip())
            report["steps"].append({"name": "validate", "status": "ok" if res.ok else "failed",
                                    "command": res.summary()})
        else:
            report["steps"].append({"name": "validate", "status": "warning",
                                    "detail": "no_validate_command"})
        scan_dirs = sorted(set(dirs) | {p.rsplit("/", 1)[0] for p in target.get("entry_files") or []})
        se = t.selinux_scan(scan_dirs)
        report["steps"].append({"name": "selinux",
                                "status": "warning" if se["mislabeled"] else "ok",
                                "data": se})
        logs = target.get("logs") or {}
        for key in ("audit_log", "error_log"):
            path = (logs.get(key) or "").strip()
            if not path or path.startswith("@"):
                continue
            try:
                t.tail(path, 64)
                report["steps"].append({"name": key, "status": "ok", "detail": path})
            except TransportError as e:
                report["steps"].append({"name": key, "status": "warning", "detail": e.message})
    except TransportError as e:
        report["steps"].append({"name": "error", "status": "failed", "detail": e.message})
    finally:
        t.close()
    return report


def load_order(conn: sqlite3.Connection, target_id: int) -> dict:
    target, t = open_target(conn, target_id)
    units = layout_mod.desired_units(conn, target)
    if not t.remote:
        return loadorder.analyze(t, target, units)
    with t:
        persist_host_key(conn, target, t)
        return loadorder.analyze(t, target, units)
