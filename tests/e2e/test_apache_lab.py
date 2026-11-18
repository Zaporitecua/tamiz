"""End-to-end test against Apache httpd + mod_security2 (ModSecurity v2) over SSH.

Runs only with TAMIZ_E2E=1 and the lab from tests/e2e/lab-apache.sh (Apache on
:8081, IncludeOptional for Tamiz's directories already in security2.conf).
Covers v2 specifics: DUMP_INCLUDES for the load order, v2 audit and error log
formats, ``apachectl graceful``, and a configure-time exclusion.
"""
import os
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from .test_nginx_lab import e2e_client  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(os.environ.get("TAMIZ_E2E") != "1", reason="needs the apache lab")

SQLI = "/search?q=1%27%20or%201%3D1--"


def http(path: str, headers: dict | None = None) -> int:
    req = urllib.request.Request(f"http://127.0.0.1:8081{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


@pytest.fixture
def apache_lab():
    subprocess.run("rm -rf /etc/modsecurity/tamiz/before /etc/modsecurity/tamiz/after; "
                   ": > /var/log/apache2/modsec_audit.log; apachectl graceful", shell=True, check=True)
    time.sleep(1)
    yield


def test_apache_lab(apache_lab, e2e_client):  # noqa: F811
    c = e2e_client
    r = c.post("/api/targets", json={
        "name": "apache-lab", "platform": "apache", "transport": "ssh",
        "conn": {"host": "127.0.0.1", "port": 2222, "username": "tamiz", "key_file": "lab_ed25519"},
        "layout": {"mode": "per_group", "before": "/etc/modsecurity/tamiz/before/{block}-{group}.conf",
                   "after": "/etc/modsecurity/tamiz/after/{block}-{group}.conf", "mkdirs": True},
        "commands": {"validate": "apachectl -t", "reload": "apachectl graceful",
                     "discover": "apachectl -t -D DUMP_INCLUDES", "sudo_mode": "commands"},
        "logs": {"audit_log": "/var/log/apache2/modsec_audit.log",
                 "error_log": "/var/log/apache2/error.log"},
    })
    assert r.status_code == 200, r.text
    tid = r.json()["id"]

    assert http(SQLI) == 403
    a = c.post(f"/api/targets/{tid}/analyze", json={"source": "audit_log"}).json()
    assert "serial" in a["formats"]
    f = next(x for x in a["findings"] if x["path"] == "/search" and x["variable"] == "ARGS:q")
    assert f["suggestion"]["action"] == "remove_target"
    host = next(x for x in a["findings"] if x["rule_id"] == 920350)
    assert host["variable"] == "REQUEST_HEADERS:Host"
    e = c.post(f"/api/targets/{tid}/analyze", json={"source": "error_log", "bytes": 100000}).json()
    assert any(x["rule_id"] == f["rule_id"] for x in e["findings"])

    g = c.post("/api/groups", json={"name": "Search", "target_ids": [tid]}).json()
    rules = sorted({x["rule_id"] for x in a["findings"]
                    if x["path"] == "/search" and x["variable"] == "ARGS:q"})
    r = c.post("/api/exclusions", json={**f["suggestion"], "group_id": g["id"],
                                        "selectors": [str(x) for x in rules]})
    assert r.status_code == 200, r.text
    # A configure-time exclusion as well: 920350 (Host is a numeric IP).
    r = c.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                        "selector_type": "id", "selectors": ["920350"],
                                        "reason": "Health checks use the IP as Host"})
    assert r.status_code == 200, r.text

    plan = c.post(f"/api/targets/{tid}/check", json={}).json()
    res = c.post(f"/api/targets/{tid}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"] == "ok", res
    verify = next(s for s in res["steps"] if s["name"] == "verify")
    checks = {x["placement"]: x["status"] for x in verify["data"]["load_order"]["checks"]
              if not x["group"].startswith("tamiz-keep")}
    assert checks == {"before": "ok", "after": "ok"}, verify["data"]["load_order"]
    time.sleep(1.5)
    assert http(SQLI) == 404   # passes the WAF; Apache has no /search page

    order = c.get(f"/api/targets/{tid}/load-order").json()
    assert order["source"] == "dump_includes"
    roles = [x["role"] for x in order["entries"]]
    assert roles.index("managed") < roles.index("crs_rules")
    assert max(i for i, r in enumerate(roles) if r == "managed") > max(
        i for i, r in enumerate(roles) if r == "crs_rules")
