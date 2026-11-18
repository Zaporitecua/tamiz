"""Read ModSecurity logs and turn false positives into exclusion drafts.

Supported inputs (auto-detected, can be mixed in one paste):

* native audit log, serial format, ModSecurity v2 (``--abcd1234-A--``) and
  libmodsecurity v3 (``---abcdEFGH---A--``);
* JSON audit log, one object per line: libmodsecurity v3, mod_security2
  (2.9+) and Coraza;
* error log lines from nginx or Apache containing ``ModSecurity:``.

Logs carry sensitive data (passwords, tokens) in matched values. Nothing
parsed here is stored; samples sent to the browser are truncated.

The suggestion for each finding is the narrowest exclusion that fits: remove
the matched variable from the rule (``ruleRemoveTargetById``) when the log
names it, otherwise remove the rule, always scoped to the request path. Rules
that only add up the anomaly score (949xxx, 959xxx, 980xxx) are never
suggested: excluding them turns blocking off altogether.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field

from ..seclang import catalog
from ..seclang.model import TARGET_VAR_RE

SERIAL_RE = re.compile(r"^-{2,3}([A-Za-z0-9@_-]{6,})-{1,3}([A-Z])--\s*$")
FIELD_RE = re.compile(r'\[(\w+) "((?:[^"\\]|\\.)*)"\]')
V3_VAR_RE = re.compile(r"against variable `([^']+)'")
V2_AT_RE = re.compile(r"\bat ([A-Z_]+(?::[^\s]+?)?)\.(?:\s|$)")
WITHIN_RE = re.compile(r"found within ([A-Z_]+(?::[^:\s]+)?):")
PHASE_RE = re.compile(r"\(phase (\d)\)")
NGINX_TAIL_RE = re.compile(r'request: "(\w+) ([^ "]+)[^"]*"(?:, host: "([^"]+)")?')
APACHE_CLIENT_RE = re.compile(r"\[client ([0-9a-fA-F:.]+)")
SAMPLE_LIMIT = 100
TARGETABLE = ("ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST", "REQUEST_COOKIES",
              "REQUEST_COOKIES_NAMES", "REQUEST_HEADERS", "FILES", "FILES_NAMES", "XML")
SEGMENT_ID_RE = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")


@dataclass
class Hit:
    rule_id: int
    msg: str = ""
    data: str = ""
    variable: str = ""
    severity: str = ""
    tags: list[str] = field(default_factory=list)
    phase: int | None = None
    blocking: bool = False


@dataclass
class Tx:
    id: str = ""
    time: str = ""
    client: str = ""
    host: str = ""
    method: str = ""
    uri: str = ""
    status: int | None = None
    blocked: bool = False
    hits: list[Hit] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.uri.split("?", 1)[0] or "/"


# ------------------------------------------------------------------ parsing --

def parse_message(text: str) -> tuple[Hit | None, dict]:
    fields: dict[str, list[str]] = {}
    for k, v in FIELD_RE.findall(text):
        fields.setdefault(k, []).append(v.replace('\\"', '"'))
    rid = (fields.get("id") or [""])[0]
    if not rid.isdigit():
        return None, fields
    var = ""
    m = V3_VAR_RE.search(text)
    if m:
        var = m.group(1)
    else:
        data = (fields.get("data") or [""])[0]
        m = WITHIN_RE.search(data) or V2_AT_RE.search(text)
        if m:
            var = m.group(1)
    phase = PHASE_RE.search(text)
    hit = Hit(int(rid), (fields.get("msg") or [""])[0], (fields.get("data") or [""])[0][:SAMPLE_LIMIT],
              var, (fields.get("severity") or [""])[0], fields.get("tag") or [],
              int(phase.group(1)) if phase else None,
              "Access denied" in text or "Intercepted" in text)
    return hit, fields


def _parse_serial(lines: list[str]) -> list[Tx]:
    txs: list[Tx] = []
    cur: dict[str, list[str]] | None = None
    cur_id = None
    section = None
    for line in lines:
        m = SERIAL_RE.match(line)
        if m:
            tid, sec = m.group(1), m.group(2)
            if sec == "A" or cur is None or tid != cur_id:
                if cur is not None:
                    tx = _serial_tx(cur_id, cur)
                    if tx:
                        txs.append(tx)
                cur, cur_id = {}, tid
            if sec == "Z":
                tx = _serial_tx(cur_id, cur)
                if tx:
                    txs.append(tx)
                cur, cur_id, section = None, None, None
                continue
            section = sec
            cur.setdefault(sec, [])
            continue
        if cur is not None and section:
            cur[section].append(line)
    return txs


def _serial_tx(tid: str, sec: dict[str, list[str]]) -> Tx | None:
    if not sec or "A" not in sec:
        return None   # a transaction cut by tail -c: no A section, skip it
    tx = Tx(id=tid)
    a = " ".join(sec.get("A", [])).strip()
    m = re.match(r"\[([^\]]+)\]\s+(\S+)\s+(\S+)", a)
    if m:
        tx.time, tx.id, tx.client = m.group(1), m.group(2), m.group(3)
    b = [ln for ln in sec.get("B", []) if ln.strip()]
    if b:
        parts = b[0].split()
        if len(parts) >= 2:
            tx.method, tx.uri = parts[0], parts[1]
        for ln in b[1:]:
            k, _, v = ln.partition(":")
            if k.strip().lower() == "host":
                tx.host = v.strip()
    f = [ln for ln in sec.get("F", []) if ln.strip()]
    if f:
        m = re.match(r"HTTP/\S+\s+(\d{3})", f[0])
        if m:
            tx.status = int(m.group(1))
    for ln in sec.get("H", []):
        if "[id " not in ln:
            continue
        hit, fields = parse_message(ln)
        if hit:
            tx.hits.append(hit)
            if not tx.uri and fields.get("uri"):
                tx.uri = fields["uri"][0]
    tx.blocked = any(h.blocking for h in tx.hits) or tx.status == 403
    return tx


def _json_tx(obj: dict) -> Tx | None:
    t = obj.get("transaction") or {}
    req = t.get("request") or obj.get("request") or {}
    resp = t.get("response") or obj.get("response") or {}
    tx = Tx()
    tx.id = str(t.get("unique_id") or t.get("transaction_id") or t.get("id") or "")
    tx.time = str(t.get("time_stamp") or t.get("time") or t.get("timestamp") or "")
    tx.client = str(t.get("client_ip") or t.get("remote_address") or "")
    tx.method = str(req.get("method") or "")
    tx.uri = str(req.get("uri") or "")
    if not tx.method and req.get("request_line"):
        parts = str(req["request_line"]).split()
        if len(parts) >= 2:
            tx.method, tx.uri = parts[0], parts[1]
    headers = req.get("headers") or {}
    for k, v in headers.items():
        if k.lower() == "host":
            tx.host = str(v)
    status = resp.get("http_code") or resp.get("status")
    tx.status = int(status) if str(status).isdigit() else None
    messages = t.get("messages") or obj.get("messages") or (obj.get("audit_data") or {}).get("messages") or []
    for msg in messages:
        if isinstance(msg, str):
            hit, _ = parse_message(msg)
        else:
            d = msg.get("details") or msg.get("data") or {}
            rid = str(d.get("ruleId") or d.get("id") or "")
            if not rid.isdigit():
                continue
            match = str(d.get("match") or d.get("raw") or "")
            var = ""
            m = V3_VAR_RE.search(match)
            if m:
                var = m.group(1)
            else:
                m = WITHIN_RE.search(str(d.get("data") or ""))
                if m:
                    var = m.group(1)
            hit = Hit(int(rid), str(msg.get("message") or d.get("msg") or ""),
                      str(d.get("data") or "")[:SAMPLE_LIMIT], var, str(d.get("severity") or ""),
                      list(d.get("tags") or []), None, False)
        if hit:
            tx.hits.append(hit)
    tx.blocked = tx.status == 403 or any(h.blocking for h in tx.hits) or bool(t.get("is_interrupted"))
    return tx


def _parse_error_lines(lines: list[str]) -> list[Tx]:
    by_id: dict[str, Tx] = {}
    order: list[str] = []
    for ln in lines:
        if "ModSecurity:" not in ln or "[id " not in ln:
            continue
        hit, fields = parse_message(ln)
        if not hit:
            continue
        uid = (fields.get("unique_id") or [""])[0] or f"line{len(order)}"
        tx = by_id.get(uid)
        if tx is None:
            tx = Tx(id=uid)
            by_id[uid] = tx
            order.append(uid)
            tx.uri = (fields.get("uri") or [""])[0]
            tx.host = (fields.get("hostname") or [""])[0]
            m = NGINX_TAIL_RE.search(ln)
            if m:
                tx.method = m.group(1)
                tx.uri = tx.uri or m.group(2)
                if m.group(3):
                    tx.host = m.group(3)
            m = APACHE_CLIENT_RE.search(ln)
            if m:
                tx.client = m.group(1)
            elif "client: " in ln:
                tx.client = ln.split("client: ", 1)[1].split(",", 1)[0]
            tx.time = ln[:32].strip("[] ")
        tx.hits.append(hit)
        if hit.blocking:
            tx.blocked = True
    return [by_id[u] for u in order]


def parse(text: str) -> tuple[list[Tx], dict]:
    lines = text.replace("\r\n", "\n").split("\n")
    formats: Counter = Counter()
    serial_lines: list[str] = []
    other: list[str] = []
    json_txs: list[Tx] = []
    in_serial = False
    for ln in lines:
        stripped = ln.strip()
        if stripped.startswith("{") and '"transaction"' in stripped:
            try:
                obj = json.loads(stripped)
                tx = _json_tx(obj)
                if tx:
                    json_txs.append(tx)
                    formats["json"] += 1
                continue
            except ValueError:
                pass
        if SERIAL_RE.match(ln):
            in_serial = True
            formats["serial"] += 1
            serial_lines.append(ln)
            continue
        if in_serial:
            serial_lines.append(ln)
            continue
        if "ModSecurity:" in ln:
            formats["error_log"] += 1
            other.append(ln)
    txs = _parse_serial(serial_lines) + json_txs + _parse_error_lines(other)
    fmt = [k for k, _ in formats.most_common()]
    return txs, {"formats": fmt}


# ---------------------------------------------------------------- analysis --

def path_pattern(path: str) -> tuple[str, bool]:
    segs = path.split("/")
    out = []
    wild = False
    for s in segs:
        if s and SEGMENT_ID_RE.match(s):
            out.append("*")
            wild = True
        else:
            out.append(s)
    return "/".join(out), wild


def _covered(ex: dict, rule_id: int, path: str, variable: str) -> bool:
    if not ex["enabled"] or ex["scope"] == "raw":
        return False
    if ex["selector_type"] != "id":
        return False
    hit_sel = False
    for s in ex["selectors"]:
        lo, _, hi = s.partition("-")
        if lo.isdigit() and (int(lo) == rule_id or (hi.isdigit() and int(lo) <= rule_id <= int(hi))):
            hit_sel = True
    if not hit_sel:
        return False
    if ex["action"] == "remove_target" and variable and variable not in ex["variables"]:
        return False
    if ex["scope"] == "global":
        return True
    for c in ex["conditions"]:
        base = c["variable"].split(":", 1)[0].upper()
        if base not in ("REQUEST_URI", "REQUEST_FILENAME") or c.get("negate"):
            continue
        v, op = c["value"], c["operator"]
        if (op == "beginsWith" and path.startswith(v)) or (op == "streq" and path == v) \
                or (op == "endsWith" and path.endswith(v)) or (op == "contains" and v in path):
            return True
        return False
    return False


def analyze(text: str, exclusions: list[dict] | None = None) -> dict:
    txs, meta = parse(text)
    exclusions = exclusions or []
    hosts = {tx.host for tx in txs if tx.host}
    multi_host = len(hosts) > 1
    groups: dict[tuple, dict] = {}
    scoring: Counter = Counter()
    for tx in txs:
        for h in tx.hits:
            if catalog.is_scoring_rule(h.rule_id):
                scoring[h.rule_id] += 1
                continue
            pattern, wild = path_pattern(tx.path)
            key = (h.rule_id, tx.host if multi_host else "", pattern, h.variable)
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "rule_id": h.rule_id, "msg": h.msg, "category": catalog.crs_category(h.rule_id),
                    "variable": h.variable, "host": tx.host if multi_host else "",
                    "path": pattern, "wildcard": wild, "count": 0, "blocked": 0,
                    "methods": Counter(), "paths": Counter(), "samples": [], "tags": h.tags,
                    "first_seen": tx.time, "last_seen": tx.time,
                }
            g["count"] += 1
            g["blocked"] += 1 if tx.blocked else 0
            if tx.method:
                g["methods"][tx.method] += 1
            g["paths"][tx.path] += 1
            g["last_seen"] = tx.time or g["last_seen"]
            if h.data and len(g["samples"]) < 3 and h.data not in g["samples"]:
                g["samples"].append(h.data)

    out = []
    for g in groups.values():
        g["methods"] = [m for m, _ in g["methods"].most_common()]
        g["paths"] = [p for p, _ in g["paths"].most_common(5)]
        g["suggestion"] = suggest(g)
        g["covered_by"] = [e["id"] for e in exclusions
                           if all(_covered(e, g["rule_id"], p, g["variable"]) for p in g["paths"])]
        out.append(g)
    out.sort(key=lambda g: (-g["blocked"], -g["count"], g["rule_id"]))
    return {
        "formats": meta["formats"],
        "transactions": len(txs),
        "blocked": sum(1 for t in txs if t.blocked),
        "with_hits": sum(1 for t in txs if t.hits),
        "findings": out,
        "scoring_rules": [{"rule_id": r, "count": c} for r, c in scoring.most_common()],
        "hosts": sorted(hosts)[:50],
    }


def suggest(g: dict) -> dict:
    path = g["path"]
    if g["wildcard"]:
        prefix = path.split("*", 1)[0]
        cond = {"variable": "REQUEST_FILENAME", "operator": "beginsWith", "value": prefix or "/"}
    else:
        cond = {"variable": "REQUEST_FILENAME", "operator": "streq", "value": path}
    conditions = [cond]
    if g["host"]:
        host = g["host"].split(":", 1)[0]
        conditions.append({"variable": "REQUEST_HEADERS:Host", "operator": "streq", "value": host,
                           "transforms": ["lowercase"]})
    var = g["variable"]
    base = var.split(":", 1)[0]
    draft = {"scope": "conditional", "selector_type": "id", "selectors": [str(g["rule_id"])],
             "conditions": conditions,
             "reason": (g["msg"] or f"Rule {g['rule_id']}")[:200]}
    if var and base in TARGETABLE and TARGET_VAR_RE.match(var):
        draft.update(action="remove_target", variables=[var])
    else:
        draft.update(action="remove_rule", variables=[])
    return draft
