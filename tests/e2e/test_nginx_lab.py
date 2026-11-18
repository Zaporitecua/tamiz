"""End-to-end test against a real nginx + libmodsecurity v3 + CRS over SSH.

Runs only with TAMIZ_E2E=1 and the lab from tests/e2e/lab-nginx.sh:
nginx on :8080 with ModSecurity, sshd on :2222, user ``tamiz`` with a narrow
sudoers rule, key in /root/tamiz-keys.

It walks through the real onboarding: first apply before the Include lines
exist, then the Include lines, then a false positive found in the audit log,
turned into an exclusion and deployed; plus drift, import with retirement of
legacy rules and a rollback caused by a real ``nginx -t`` failure.
"""
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("TAMIZ_E2E") != "1", reason="needs the nginx lab")

MAIN = Path("/etc/nginx/modsec/main.conf")
LEGACY = Path("/etc/nginx/modsec/legacy/old-exclusions.conf")
BASE_MAIN = ("Include /etc/nginx/modsec/modsecurity.conf\n"
             "Include /etc/nginx/modsec/legacy/*.conf\n"
             "Include /etc/modsecurity/crs/crs-setup.conf\n"
             "Include /usr/share/modsecurity-crs/rules/*.conf\n")
FULL_MAIN = ("Include /etc/nginx/modsec/modsecurity.conf\n"
             "Include /etc/nginx/modsec/legacy/*.conf\n"
             "Include /etc/nginx/modsec/tamiz/before/*.conf\n"
             "Include /etc/modsecurity/crs/crs-setup.conf\n"
             "Include /usr/share/modsecurity-crs/rules/*.conf\n"
             "Include /etc/nginx/modsec/tamiz/after/*.conf\n")
SQLI = "/search?q=1%27%20or%201%3D1--"


def http(path: str) -> int:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:8080{path}", timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def sh(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True).stdout


@pytest.fixture
def lab(tmp_path):
    for d in ("before", "after"):
        sh(f"rm -rf /etc/nginx/modsec/tamiz/{d}")
    LEGACY.parent.mkdir(exist_ok=True)
    LEGACY.write_text(
        "# Legacy exclusions written by hand\n"
        "# Reports module uploads\n"
        'SecRule REQUEST_URI "@beginsWith /legacy/upload" \\\n'
        '    "id:1009502, phase:1, pass, nolog, ctl:ruleRemoveById=942100"\n'
        "\n"
        "# Something else that is not an exclusion\n"
        'SecRule REQUEST_HEADERS:X-Lab "@streq block-me" "id:1009600,phase:1,deny,status:418"\n')
    MAIN.write_text(BASE_MAIN)
    sh(": > /var/log/modsec_audit.log && nginx -s reload")
    time.sleep(0.8)
    yield
    MAIN.write_text(BASE_MAIN)
    sh("nginx -s reload")


@pytest.fixture
def e2e_client(tmp_path):
    from fastapi.testclient import TestClient

    from tamiz import config
    from tamiz.core import secrets
    from tests.conftest import make_config
    cfg = make_config(tmp_path, keys_dir=Path("/root/tamiz-keys"))
    config.set_for_tests(cfg)
    secrets.reset_for_tests()
    from tamiz.main import app
    with TestClient(app) as c:
        c.headers["X-Tamiz"] = "1"
        assert c.post("/api/auth/login", json={"username": "admin",
                                               "password": "correct horse battery"}).status_code == 200
        yield c


def check(c, tid, force=()):
    r = c.post(f"/api/targets/{tid}/check", json={"force": list(force)})
    assert r.status_code == 200, r.text
    return r.json()


def apply(c, tid, plan, **kw):
    r = c.post(f"/api/targets/{tid}/apply", json={"plan_hash": plan["summary"]["hash"], **kw})
    assert r.status_code == 200, r.text
    return r.json()


def step(result, name):
    return next(s for s in result["steps"] if s["name"] == name)


def test_nginx_lab(lab, e2e_client):
    c = e2e_client
    r = c.post("/api/targets", json={
        "name": "nginx-lab", "platform": "nginx", "transport": "ssh", "environment": "lab",
        "conn": {"host": "127.0.0.1", "port": 2222, "username": "tamiz", "key_file": "lab_ed25519"},
        "layout": {"mode": "per_group", "before": "/etc/nginx/modsec/tamiz/before/{block}-{group}.conf",
                   "after": "/etc/nginx/modsec/tamiz/after/{block}-{group}.conf", "mkdirs": True},
        "commands": {"validate": "nginx -t", "reload": "nginx -s reload", "discover": "nginx -T",
                     "sudo_mode": "commands"},
        "logs": {"audit_log": "/var/log/modsec_audit.log", "error_log": "/var/log/nginx/error.log"},
        "import_paths": ["/etc/nginx/modsec/legacy/*.conf"],
    })
    assert r.status_code == 200, r.text
    tid = r.json()["id"]

    # Diagnose: connects, pins the host key, checks sudo and nginx -t.
    d = c.post(f"/api/targets/{tid}/diagnose").json()
    by = {s["name"]: s for s in d["steps"]}
    assert by["connect"]["status"] == "ok" and by["sudo"]["status"] == "ok"
    assert by["validate"]["status"] == "ok"
    assert c.get(f"/api/targets/{tid}").json()["host_key"].startswith("ssh-")

    # 1. First apply before the Include lines exist: creates the directories
    #    and placeholders; verification warns that they are not loaded.
    plan = check(c, tid)
    assert plan["summary"]["status"] == "pending"
    res = apply(c, tid, plan)
    assert res["status"] == "ok_with_warnings", res
    lo = step(res, "verify")["data"]["load_order"]["checks"]
    assert {x["status"] for x in lo} == {"not_loaded"}

    # 2. The administrator adds the two Include lines.
    MAIN.write_text(FULL_MAIN)
    sh("nginx -t && nginx -s reload")
    time.sleep(0.8)
    order = c.get(f"/api/targets/{tid}/load-order").json()
    assert order["source"] == "discovered"
    assert {x["status"] for x in order["checks"]} == {"ok"}, order["checks"]
    roles = [e["role"] for e in order["entries"]]
    assert "crs_rules" in roles and roles.index("managed") < roles.index("crs_rules")

    # 3. A false positive: blocked, found in the audit log, excluded.
    assert http(SQLI) == 403
    a = c.post(f"/api/targets/{tid}/analyze", json={"source": "audit_log", "bytes": 200000}).json()
    finding = next(f for f in a["findings"] if f["path"] == "/search" and f["variable"] == "ARGS:q")
    assert finding["suggestion"]["action"] == "remove_target"
    assert all(s["rule_id"] // 1000 in (949, 959, 980) for s in a["scoring_rules"])
    g = c.post("/api/groups", json={"name": "Search", "target_ids": [tid]}).json()
    rules = sorted({f["rule_id"] for f in a["findings"] if f["path"] == "/search" and f["variable"] == "ARGS:q"})
    draft = dict(finding["suggestion"], group_id=g["id"], selectors=[str(x) for x in rules],
                 reason="Search accepts free text")
    r = c.post("/api/exclusions", json=draft)
    assert r.status_code == 200, r.text
    plan = check(c, tid)
    res = apply(c, tid, plan)
    assert res["status"] == "ok", res
    counts = step(res, "verify")["data"]["rules_loaded"]
    assert counts["expected_delta"] == 1 and counts["observed_delta"] == 1, counts
    time.sleep(0.5)
    assert http(SQLI) == 200
    assert http("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E") == 403   # XSS still blocked

    # 4. Drift: someone edits the managed file by hand.
    managed = Path(f"/etc/nginx/modsec/tamiz/before/{g['blocks'][0]:03d}-search.conf")
    managed.write_text(managed.read_text() + "# edited on the server\n")
    plan = check(c, tid)
    assert plan["summary"]["status"] == "in_sync" or plan["summary"]["units"].get("drift")
    c.patch(f"/api/exclusions/{r.json()['id']}", json={"reason": "Search box"})
    plan = check(c, tid)
    assert plan["summary"]["status"] == "blocked"
    plan = check(c, tid, force=[str(managed)])
    assert apply(c, tid, plan, force=[str(managed)])["status"] == "ok"
    assert "edited on the server" not in managed.read_text()

    # 5. Import legacy rules, renumber them and retire them from the old file
    #    in the same apply (no duplicate IDs at any point).
    assert http("/legacy/upload?q=1%27%20or%201%3D1--") == 200
    files = c.get(f"/api/targets/{tid}/import").json()["files"]
    assert str(LEGACY) in files
    scan = c.post(f"/api/targets/{tid}/import/scan", json={"path": str(LEGACY)}).json()
    props = {p["line"]: p for p in scan["proposals"]}
    excl = next(p for p in props.values() if p["kind"] == "exclusion")
    assert excl["structured"] and excl["comment"] == "Reports module uploads"
    assert excl["group_hint"] == "legacy"
    r = c.post(f"/api/targets/{tid}/import/commit", json={
        "path": str(LEGACY), "file_hash": scan["file_hash"], "renumber": True, "retire": True,
        "items": [{"key": excl["key"], "new_group": "Legacy"}]})
    assert r.status_code == 200, r.text
    plan = check(c, tid)
    actions = {o["path"]: o["action"] for o in plan["ops"]}
    assert actions[str(LEGACY)] == "update"
    # The legacy file belongs to root: the permission check stops the apply
    # before anything is written.
    res = apply(c, tid, plan)
    assert res["status"] == "failed" and res["steps"][-1]["name"] == "permissions", res
    assert "write" not in [s["name"] for s in res["steps"]]
    # The administrator switches this target to sudo mode "all".
    r2 = c.put(f"/api/targets/{tid}", json={"commands": {"sudo_mode": "all"}})
    assert r2.status_code == 200, r2.text
    plan = check(c, tid)
    res = apply(c, tid, plan)
    assert res["status"] == "ok", res
    legacy_text = LEGACY.read_text()
    assert "1009502" not in legacy_text and "1009600" in legacy_text   # non-exclusion kept
    assert "Reports module uploads" not in legacy_text
    time.sleep(0.5)
    assert http("/legacy/upload?q=1%27%20or%201%3D1--") == 200       # still excluded, new ID
    ex = [e for e in c.get("/api/exclusions").json() if e["origin"] == "import"][0]
    assert ex["verbatim"] and 10000 <= ex["rule_id"] <= 99999
    assert "id:%d, phase:1" % ex["rule_id"] in ex["source_text"]

    # 6. A broken raw exclusion: real nginx -t fails, Tamiz rolls back.
    before_files = {p: p.read_text() for p in Path("/etc/nginx/modsec/tamiz").rglob("*.conf")}
    c.post("/api/exclusions", json={"group_id": g["id"], "scope": "raw", "placement": "after",
                                    "raw_text": "SecRuleRemoveByIdd 942100"})
    plan = check(c, tid)
    res = apply(c, tid, plan)
    assert res["status"] == "rolled_back", res
    assert step(res, "validate")["status"] == "failed"
    after_files = {p: p.read_text() for p in Path("/etc/nginx/modsec/tamiz").rglob("*.conf")}
    assert after_files == before_files
    assert http(SQLI) == 200 and http("/") == 200


def test_ssh_host_key_is_pinned(e2e_client):
    c = e2e_client
    tid = c.post("/api/targets", json={
        "name": "pinned", "platform": "nginx", "transport": "ssh",
        "conn": {"host": "127.0.0.1", "port": 2222, "username": "tamiz", "key_file": "lab_ed25519"},
        "layout": {"mode": "per_group", "before": "/tmp/pin/b/{group}.conf", "after": "/tmp/pin/a/{group}.conf"},
        "commands": {"sudo_mode": "none"}}).json()["id"]
    assert c.post(f"/api/targets/{tid}/check", json={}).status_code == 200
    from tamiz import db
    with db.db() as conn:
        conn.execute("UPDATE targets SET host_key=? WHERE id=?",
                     ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", tid))
    r = c.post(f"/api/targets/{tid}/check", json={})
    assert r.status_code == 409 and r.json()["error"] == "host_key_mismatch"
    assert r.json()["params"]["seen"].startswith("SHA256:")
    c.post(f"/api/targets/{tid}/host-key/reset")
    assert c.post(f"/api/targets/{tid}/check", json={}).status_code == 200
