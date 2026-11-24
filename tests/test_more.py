"""Transports, auth modes, reviews, renumbering, workspace I/O, log formats."""
import http.server
import json
import os
import socketserver
import struct
import subprocess
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tamiz import config
from tamiz.core import auditlog
from tamiz.transports.local import LocalTransport


# ------------------------------------------------------------------ SELinux --

@pytest.fixture
def fake_selinux(tmp_path, monkeypatch):
    """selinuxenabled says yes; restorecon records its calls and reports
    files listed in ``bad`` as mislabeled on dry runs."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir()
    log = tmp_path / "restorecon.log"
    bad = tmp_path / "bad"
    bad.write_text("")
    (bin_dir / "selinuxenabled").write_text("#!/bin/sh\nexit 0\n")
    (bin_dir / "restorecon").write_text(
        f"#!/bin/sh\necho \"$@\" >> {log}\n"
        "case \"$*\" in *-n*) for f; do :; done; "
        f"grep -qx \"$f\" {bad} && echo \"Would relabel $f from user_tmp_t to httpd_config_t\";; esac\n"
        "exit 0\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log, bad


def test_large_files_are_written_in_parts(cfg, tmp_path):
    # A single argument over 128 KiB makes execve fail with E2BIG; big files
    # (legacy REQUEST-900 files, large groups) go in parts to the same temp file.
    t = LocalTransport({"transport": "local", "commands": {"sudo_mode": "none"}}, {})
    dest = tmp_path / "waf" / "big"
    content = "".join(f"SecRuleRemoveById {i}  # línea {i}\n" for i in range(20000))
    assert len(content.encode()) > 400_000
    res = t.write_file(str(dest / "big.conf"), content, mkdirs=True)
    assert res.ok, res.stderr
    assert (dest / "big.conf").read_text() == content
    assert [p.name for p in dest.iterdir()] == ["big.conf"]     # no temporary file left


def test_write_relabels_final_path_not_temp(cfg, tmp_path, fake_selinux):
    log, bad = fake_selinux
    target = {"transport": "local", "commands": {"sudo_mode": "none"}}
    t = LocalTransport(target, {})
    dest = tmp_path / "waf" / "rules"
    dest.mkdir(parents=True)
    res = t.write_file(str(dest / "x.conf"), "SecRuleRemoveById 1\n")
    assert res.ok, res.stderr
    assert "selinux=relabeled" in res.stdout
    calls = log.read_text().splitlines()
    assert calls == [f"-F {dest}/x.conf"]          # relabels the final file
    assert not list(dest.glob(".*tamiz-tmp"))
    bad.write_text(f"{dest}/x.conf\n")
    report = t.selinux_verify([str(dest / "x.conf")])
    assert report["enabled"] and report["files"][str(dest / "x.conf")]["status"] == "mislabeled"


# ------------------------------------------------------- Docker (simulated) --

class _DockerAPI(http.server.BaseHTTPRequestHandler):
    execs: dict = {}

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/containers/waf/json"):
            return self._json(200, {"State": {"Running": True}})
        if self.path.startswith("/exec/") and self.path.endswith("/json"):
            eid = self.path.split("/")[2]
            return self._json(200, {"ExitCode": self.execs[eid]["rc"]})
        if self.path.startswith("/containers/waf/logs"):
            line = (b'{"transaction":{"client_ip":"10.0.0.9","unique_id":"u1","request":{"method":"GET",'
                    b'"uri":"/api/items/42?x=1","headers":{"Host":"shop.example"}},"response":{"http_code":403},'
                    b'"messages":[{"message":"SQL Injection","details":{"ruleId":"942100","match":"Matched '
                    b'\\"Operator `DetectSQLi\' with parameter `\' against variable `ARGS:x\' (Value: `1\' )",'
                    b'"data":"Matched Data: s&1 found within ARGS:x: 1"}}]}}\n')
            frame = struct.pack(">BxxxI", 1, len(line)) + line
            self.send_response(200)
            self.send_header("Content-Length", str(len(frame)))
            self.end_headers()
            self.wfile.write(frame)
            return
        self._json(404, {"message": "no such container"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/containers/waf/exec":
            eid = f"e{len(self.execs)}"
            self.execs[eid] = {"cmd": body["Cmd"], "rc": None}
            return self._json(201, {"Id": eid})
        if self.path.startswith("/exec/") and self.path.endswith("/start"):
            eid = self.path.split("/")[2]
            p = subprocess.run(self.execs[eid]["cmd"], capture_output=True)
            self.execs[eid]["rc"] = p.returncode
            data = b""
            for stream, chunk in ((1, p.stdout), (2, p.stderr)):
                if chunk:
                    data += struct.pack(">BxxxI", stream, len(chunk)) + chunk
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.docker.multiplexed-stream")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
            return
        self._json(404, {"message": "not found"})


@pytest.fixture
def docker_socket(tmp_path):
    path = str(tmp_path / "docker.sock")

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    class Handler(_DockerAPI):
        def address_string(self):
            return "docker"

    srv = Server(path, Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield path
    srv.shutdown()


def test_docker_transport_full_cycle(client, tmp_path, docker_socket):
    waf = tmp_path / "container-fs" / "plugins"
    waf.mkdir(parents=True)
    r = client.post("/api/targets", json={
        "name": "crs-container", "platform": "crs-docker", "transport": "docker",
        "conn": {"container": "waf", "docker_host": f"unix://{docker_socket}", "exec_user": "root"},
        "layout": {"mode": "per_group", "before": f"{waf}/tamiz-{{block}}-{{group}}-before.conf",
                   "after": f"{waf}/tamiz-{{block}}-{{group}}-after.conf"},
        "commands": {"validate": "true", "reload": "true"},
        "logs": {"audit_log": "@stdout"}})
    assert r.status_code == 200, r.text
    tid = r.json()["id"]
    g = client.post("/api/groups", json={"name": "shop", "target_ids": [tid]}).json()
    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "conditional", "action": "remove_rule", "selector_type": "id",
        "selectors": ["942100"], "conditions": [{"variable": "REQUEST_FILENAME", "operator": "beginsWith",
                                                  "value": "/api/items/"}]})
    plan = client.post(f"/api/targets/{tid}/check", json={}).json()
    res = client.post(f"/api/targets/{tid}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"].startswith("ok"), res
    assert "ctl:ruleRemoveById=942100" in (waf / "tamiz-010-shop-before.conf").read_text()
    assert (waf / "tamiz-000-tamiz-keep-after.conf").exists()

    a = client.post(f"/api/targets/{tid}/analyze", json={"source": "audit_log"}).json()
    f = a["findings"][0]
    assert f["rule_id"] == 942100 and f["path"] == "/api/items/*" and f["variable"] == "ARGS:x"
    assert f["covered_by"]                       # the exclusion above already covers it


# ------------------------------------------------------------- proxy auth --

def test_proxy_auth_maps_groups_to_roles(cfg):
    cfg.auth_mode = "proxy"
    from tamiz.main import app
    with TestClient(app, client=("127.0.0.1", 40000)) as c:
        c.headers["X-Tamiz"] = "1"
        h = {"X-Forwarded-User": "lucia", "X-Forwarded-Groups": "staff,waf-editors"}
        me = c.get("/api/auth/status", headers=h).json()["user"]
        assert me["username"] == "lucia" and me["role"] == "editor"
        assert c.post("/api/groups", json={"name": "x"}, headers=h).status_code == 200
        assert c.get("/api/users", headers=h).status_code == 403
    with TestClient(app, client=("10.9.9.9", 40000)) as c:   # not a trusted proxy
        r = c.get("/api/groups", headers={"X-Forwarded-User": "mallory"})
        assert r.status_code == 401


def test_client_ip_only_reads_forwarded_for_from_trusted_proxies(cfg):
    from types import SimpleNamespace
    from tamiz.core import auth

    def req(peer, xff=""):
        return SimpleNamespace(client=SimpleNamespace(host=peer),
                               headers={"x-forwarded-for": xff} if xff else {})
    # Direct connection: the header is ignored.
    assert auth.client_ip(req("203.0.113.9", "127.0.0.1")) == "203.0.113.9"
    # Through a trusted proxy: rightmost hop that is not a trusted proxy.
    assert auth.client_ip(req("127.0.0.1", "127.0.0.1, 198.51.100.7")) == "198.51.100.7"
    assert auth.client_ip(req("127.0.0.1", "198.51.100.7, 127.0.0.1")) == "198.51.100.7"
    # Garbage or nothing: fall back to the proxy itself.
    assert auth.client_ip(req("127.0.0.1", "not-an-ip")) == "127.0.0.1"
    assert auth.client_ip(req("127.0.0.1")) == "127.0.0.1"


def test_setup_code_required_for_first_admin(cfg):
    cfg.admin_user = cfg.admin_password = None
    from tamiz import db
    from tamiz.main import app
    with TestClient(app) as c:
        c.headers["X-Tamiz"] = "1"
        assert c.get("/api/auth/status").json()["setup_needed"] is True
        bad = c.post("/api/auth/setup", json={"code": "nope", "username": "root", "password": "x" * 12})
        assert bad.status_code == 403
        with db.db() as conn:
            code = db.meta_get(conn, "setup_code")
        ok = c.post("/api/auth/setup", json={"code": code, "username": "root", "password": "x" * 12})
        assert ok.status_code == 200
        assert c.get("/api/auth/status").json()["user"]["role"] == "admin"


def test_admin_from_environment_needs_a_valid_password(cfg, caplog):
    """TAMIZ_ADMIN_PASSWORD skipped the 10-character minimum of the setup form."""
    cfg.admin_password = "short"
    from tamiz import db
    from tamiz.main import app
    with TestClient(app) as c:
        c.headers["X-Tamiz"] = "1"
        assert c.get("/api/auth/status").json()["setup_needed"] is True
        assert c.post("/api/auth/login", json={"username": "admin", "password": "short"}).status_code == 401
        with db.db() as conn:
            assert db.meta_get(conn, "setup_code")
    assert "TAMIZ_ADMIN_PASSWORD must have 10 to 256 characters" in caplog.text


# --------------------------------------------------------------- reviews --

def test_review_is_required_and_cannot_be_self_approved(client, tmp_path):
    waf = tmp_path / "waf" / "r"
    waf.mkdir(parents=True)
    t = client.post("/api/targets", json={
        "name": "prod", "platform": "custom", "transport": "local", "require_review": True,
        "layout": {"mode": "per_group", "before": f"{waf}/b-{{group}}.conf", "after": f"{waf}/a-{{group}}.conf"},
        "commands": {}}).json()
    g = client.post("/api/groups", json={"name": "a", "target_ids": [t["id"]]}).json()
    client.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                         "selector_type": "id", "selectors": ["1"]})
    plan = client.post(f"/api/targets/{t['id']}/check", json={}).json()
    h = plan["summary"]["hash"]
    assert client.post(f"/api/targets/{t['id']}/apply", json={"plan_hash": h}).json()["error"] == "review_required"
    rid = client.post(f"/api/targets/{t['id']}/reviews", json={"plan_hash": h, "note": "please"}).json()["id"]
    assert client.post(f"/api/targets/{t['id']}/reviews/{rid}/approve").status_code == 403
    client.post("/api/users", json={"username": "bob", "password": "0123456789ab", "role": "editor"})
    from tamiz.main import app
    with TestClient(app) as bob:
        bob.headers["X-Tamiz"] = "1"
        bob.post("/api/auth/login", json={"username": "bob", "password": "0123456789ab"})
        assert bob.post(f"/api/targets/{t['id']}/reviews/{rid}/approve").json()["status"] == "approved"
    res = client.post(f"/api/targets/{t['id']}/apply", json={"plan_hash": h, "review_id": rid}).json()
    assert res["status"].startswith("ok"), res


# ------------------------------------------------------------ renumbering --

def test_import_renumber_and_reserved_range_lint(client):
    text = ('# Upload API\nSecRule REQUEST_URI "@beginsWith /up" "id:1009502,phase:1,pass,nolog,'
            'ctl:ruleRemoveById=942100"\n'
            'SecRule REQUEST_URI "@beginsWith /dl" "id:1009503,phase:1,pass,nolog,ctl:ruleRemoveById=941100"\n')
    scan = client.post("/api/import/scan", json={"text": text}).json()
    keys = [p["key"] for p in scan["proposals"]]
    r = client.post("/api/import/commit", json={"text": text, "renumber": False,
                                                "items": [{"key": k, "new_group": "files"} for k in keys]})
    assert r.status_code == 200, r.text
    ex = client.get("/api/exclusions").json()
    assert {e["rule_id"] for e in ex} == {1009502, 1009503}
    assert any(i["code"] == "rule_id_reserved" for i in ex[0]["lint"])
    gid = ex[0]["group_id"]
    plan = client.get(f"/api/groups/{gid}/renumber").json()
    assert [(c["old"], c["new"]) for c in plan["changes"]] == [(1009502, 10000), (1009503, 10001)]
    client.post(f"/api/groups/{gid}/renumber")
    ex = client.get("/api/exclusions").json()
    assert [e["rule_id"] for e in ex] == [10000, 10001]
    assert "id:10000," in ex[0]["source_text"]
    assert client.get(f"/api/groups/{gid}/renumber").json()["changes"] == []


def test_workspace_export_import_roundtrip(client):
    g = client.post("/api/groups", json={"name": "web"}).json()
    client.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                         "selector_type": "id", "selectors": ["920350"], "reason": "x"})
    data = client.get("/api/io/export").json()
    assert data["groups"][0]["exclusions"][0]["selectors"] == ["920350"]
    r = client.post("/api/io/import", json=data).json()
    assert r == {"created": 0, "skipped": 1, "groups_created": 0}


def test_editing_imported_rule_metadata_keeps_original_text(client):
    text = 'SecRule REQUEST_URI "@beginsWith /x" "id:4242, phase:1, pass, nolog, ctl:ruleRemoveById=1"\n'
    scan = client.post("/api/import/scan", json={"text": text}).json()
    client.post("/api/import/commit", json={"text": text, "renumber": False,
                                            "items": [{"key": scan["proposals"][0]["key"]}]})
    e = client.get("/api/exclusions").json()[0]
    body = dict(e, reason="kept")
    r = client.put(f"/api/exclusions/{e['id']}", json=body).json()
    assert r["verbatim"] and r["source_text"].startswith('SecRule REQUEST_URI "@beginsWith /x"')
    body = dict(r, selectors=["1", "2"])
    r = client.put(f"/api/exclusions/{e['id']}", json=body).json()
    assert not r["verbatim"] and r["selectors"] == ["1", "2"]


# ----------------------------------------------------------- log formats --

def test_analyzer_formats():
    v3_json = json.dumps({"transaction": {
        "client_ip": "1.2.3.4", "unique_id": "a", "request": {"method": "PUT", "uri": "/personal/api/fam",
                                                              "headers": {"Host": "pds.example"}},
        "response": {"http_code": 403},
        "messages": [{"message": "Remote Command Execution: Windows Command Injection",
                      "details": {"ruleId": "932380",
                                  "match": "Matched \"Operator `Rx' with parameter `x' against variable "
                                           "`ARGS:json.domicilioCompleto' (Value: `a; b' )",
                                  "data": "Matched Data: ; b found within ARGS:json.domicilioCompleto: a; b"}},
                     {"message": "Inbound Anomaly Score Exceeded",
                      "details": {"ruleId": "949110", "match": "", "data": ""}}]}})
    coraza = json.dumps({"transaction": {"id": "c1", "client_ip": "5.6.7.8",
                                         "request": {"method": "POST", "uri": "/login"},
                                         "response": {"status": 403}, "is_interrupted": True},
                         "messages": [{"message": "XSS", "data": {"id": 941100, "msg": "XSS Attack",
                                                                  "data": "Matched Data: <x found within ARGS:name: <x"}}]})
    nginx_err = ('2026/10/28 10:00:00 [error] 1#1: *5 [client 9.9.9.9] ModSecurity: Access denied with code 403 '
                 '(phase 2). Matched "Operator `Ge\' with parameter `5\' against variable `TX:ANOMALY_SCORE\' '
                 '(Value: `5\' ) [file "x"] [line "1"] [id "949110"] [msg "Inbound Anomaly Score Exceeded"] '
                 '[hostname "10.0.0.1"] [uri "/x"] [unique_id "u9"] [ref ""], client: 9.9.9.9, server: _, '
                 'request: "GET /x?a=1 HTTP/1.1", host: "site.example"')
    out = auditlog.analyze("\n".join([v3_json, coraza, nginx_err]))
    assert set(out["formats"]) == {"json", "error_log"}
    rules = {f["rule_id"]: f for f in out["findings"]}
    assert set(rules) == {932380, 941100}                 # 949110 is reported apart
    assert rules[932380]["variable"] == "ARGS:json.domicilioCompleto"
    assert rules[932380]["suggestion"]["action"] == "remove_target"
    assert rules[941100]["variable"] == "ARGS:name"
    assert {s["rule_id"] for s in out["scoring_rules"]} == {949110}
    assert out["blocked"] == 3


def test_analyzer_path_patterns_and_cut_transactions():
    tx = ("--a1b2c3d4-B--\nGET /api/users/123 HTTP/1.1\nHost: x\n\n--a1b2c3d4-H--\n"
          'Message: Warning. Pattern match "x" at ARGS:q. [id "942100"] [msg "SQLi"]\n--a1b2c3d4-Z--\n')
    full = ("--b1b2c3d4-A--\n[28/Oct/2026:10:00:00 +0000] Yx 1.1.1.1 1 2.2.2.2 80\n"
            "--b1b2c3d4-B--\nGET /api/users/456 HTTP/1.1\nHost: x\n\n--b1b2c3d4-F--\nHTTP/1.1 403 Forbidden\n"
            '--b1b2c3d4-H--\nMessage: Warning. Pattern match "x" at ARGS:q. [id "942100"] [msg "SQLi"]\n'
            "--b1b2c3d4-Z--\n")
    full2 = full.replace("b1b2", "c1b2").replace("/456", "/789")
    out = auditlog.analyze(tx + full + full2)
    assert out["transactions"] == 2                        # the one without an A section is skipped
    f = out["findings"][0]
    assert f["path"] == "/api/users/*"
    assert f["suggestion"]["conditions"][0] == {"variable": "REQUEST_FILENAME", "operator": "beginsWith",
                                                 "value": "/api/users/"}


def test_lost_secret_key_is_reported_and_recoverable(client, cfg):
    from cryptography.fernet import Fernet
    from tamiz.core import secrets
    t = client.post("/api/targets", json={
        "name": "remote", "platform": "custom", "transport": "ssh",
        "conn": {"host": "127.0.0.1", "port": 1, "username": "tamiz"},
        "secret": {"password": "s3cret-pass"},
        "layout": {"mode": "per_group", "before": "/etc/w/b-{group}.conf", "after": "/etc/w/a-{group}.conf"},
        "commands": {}}).json()
    assert client.get(f"/api/targets/{t['id']}").json()["secret_keys"] == ["password"]

    # secret.key lost: Tamiz now runs with another key.
    cfg.secret_key = Fernet.generate_key().decode()
    secrets.reset_for_tests()
    got = client.get(f"/api/targets/{t['id']}").json()
    assert got["secret_unreadable"] is True and got["secret_keys"] == []
    r = client.post(f"/api/targets/{t['id']}/check", json={})
    assert r.status_code == 502 and r.json()["error"] == "secret_unreadable"

    # Typing the credentials again replaces the unreadable value.
    body = {k: got[k] for k in ("name", "platform", "transport", "conn", "layout", "commands")}
    body["secret"] = {"password": "new-pass"}
    assert client.put(f"/api/targets/{t['id']}", json=body).status_code == 200
    again = client.get(f"/api/targets/{t['id']}").json()
    assert again["secret_unreadable"] is False and again["secret_keys"] == ["password"]


# ------------------------------------------------------------------ export --

def test_export_target_bundle_and_mark_deployed(client):
    import io
    import json
    import zipfile
    t = client.post("/api/targets", json={
        "name": "edge eu", "platform": "custom", "transport": "export",
        "layout": {"mode": "per_group", "before": "/etc/waf/b/{block}-{group}.conf",
                   "after": "/etc/waf/a/{block}-{group}.conf"},
        "commands": {}}).json()
    g = client.post("/api/groups", json={"name": "shop", "target_ids": [t["id"]]}).json()
    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "conditional", "action": "remove_rule", "selector_type": "id",
        "selectors": ["920350"], "reason": "health checks",
        "conditions": [{"variable": "REQUEST_FILENAME", "operator": "streq", "value": "/health"}]})

    plan = client.post(f"/api/targets/{t['id']}/check", json={}).json()
    assert plan["summary"]["status"] == "pending"
    r = client.post(f"/api/targets/{t['id']}/apply", json={"plan_hash": plan["summary"]["hash"]})
    assert r.status_code == 400 and r.json()["error"] == "export_target"

    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/targets/{t['id']}/bundle").content))
    names = set(z.namelist())
    assert {"etc/waf/b/010-shop.conf", "tamiz-manifest.json", "TAMIZ-README.txt"} <= names
    manifest = json.loads(z.read("tamiz-manifest.json"))
    assert manifest["layout"] == "per_group"
    assert all(f["content"] == "whole_file" for f in manifest["files"])
    assert "ruleRemoveById=920350" in z.read("etc/waf/b/010-shop.conf").decode()

    r = client.post(f"/api/targets/{t['id']}/mark-deployed", json={"plan_hash": plan["summary"]["hash"]})
    assert r.status_code == 200, r.text
    assert client.post(f"/api/targets/{t['id']}/check", json={}).json()["summary"]["status"] == "in_sync"


def test_shared_layout_bundle_warns_it_holds_only_blocks(client):
    import io
    import json
    import zipfile
    t = client.post("/api/targets", json={
        "name": "legacy", "platform": "custom", "transport": "export",
        "layout": {"mode": "shared", "before": "/etc/waf/REQUEST-900.conf", "after": "/etc/waf/RESPONSE-999.conf"},
        "commands": {}}).json()
    g = client.post("/api/groups", json={"name": "shop", "target_ids": [t["id"]]}).json()
    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "global", "action": "remove_rule", "selector_type": "id",
        "selectors": ["920350"], "reason": "x"})
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/targets/{t['id']}/bundle").content))
    manifest = json.loads(z.read("tamiz-manifest.json"))
    assert manifest["files"][0]["content"] == "tamiz_blocks_only"
    assert "Do not copy it over the real file" in z.read("TAMIZ-README.txt").decode()
    assert "# ---- tamiz:begin group=shop ----" in z.read("etc/waf/RESPONSE-999.conf").decode()
