"""End-to-end flow through the API with the local transport.

The "WAF" is a directory; the validate command is a small script that fails
when any file contains the word BROKEN, which lets the tests exercise the
rollback path.
"""
import os
import stat
from pathlib import Path


def make_validator(tmp: Path) -> str:
    script = tmp / "validate.sh"
    script.write_text("#!/bin/sh\nif grep -rq BROKEN \"$1\"; then echo 'syntax error near BROKEN' >&2; exit 1; fi\necho ok\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def setup_target(client, tmp_path, **layout):
    waf = tmp_path / "waf" / "conf"
    waf.mkdir(parents=True, exist_ok=True)
    validator = make_validator(tmp_path)
    body = {
        "name": "lab", "platform": "custom", "transport": "local",
        "layout": {"mode": "per_group", "before": f"{waf}/before/{{block}}-{{group}}.conf",
                   "after": f"{waf}/after/{{block}}-{{group}}.conf", "mkdirs": True, **layout},
        "commands": {"validate": f"{validator} {waf}", "reload": "true", "sudo_mode": "none"},
    }
    r = client.post("/api/targets", json=body)
    assert r.status_code == 200, r.text
    return r.json(), waf


def test_full_cycle(client, tmp_path):
    target, waf = setup_target(client, tmp_path)
    g = client.post("/api/groups", json={"name": "Shop API", "target_ids": [target["id"]]}).json()
    assert g["slug"] == "shop-api" and g["id_ranges"] == "10000-10999"

    r = client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "conditional", "action": "remove_target", "selector_type": "id",
        "selectors": ["942100"], "variables": ["ARGS:q"], "reason": "Search box accepts SQL-ish text",
        "conditions": [{"variable": "REQUEST_FILENAME", "operator": "streq", "value": "/search"}]})
    assert r.status_code == 200, r.text
    ex = r.json()
    assert ex["rule_id"] == 10000 and ex["placement"] == "before"

    r = client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "global", "action": "remove_rule", "selector_type": "id",
        "selectors": ["920350"], "reason": "IP in Host header from load balancer checks"})
    assert r.status_code == 200, r.text

    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    assert plan["summary"]["status"] == "pending"
    assert {o["action"] for o in plan["ops"]} == {"create"}

    res = client.post(f"/api/targets/{target['id']}/apply",
                      json={"plan_hash": plan["summary"]["hash"], "reload": True}).json()
    assert res["status"] in ("ok", "ok_with_warnings"), res
    before = (waf / "before" / "010-shop-api.conf").read_text()
    assert "ctl:ruleRemoveTargetById=942100;ARGS:q" in before
    assert "SecRuleRemoveById 920350" in (waf / "after" / "010-shop-api.conf").read_text()
    # no temporary file left behind
    assert not [p for p in (waf / "before").iterdir() if p.name.endswith("tamiz-tmp")]

    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    assert plan["summary"]["status"] == "in_sync", plan

    # A hand edit is drift: blocked until forced.
    path = waf / "before" / "010-shop-api.conf"
    path.write_text(before + "\n# edited by hand\n")
    client.patch(f"/api/exclusions/{ex['id']}", json={"reason": "Search box"})
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    assert plan["summary"]["status"] == "blocked"
    r = client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]})
    assert r.json()["status"] == "failed"
    assert "# edited by hand" in path.read_text()
    plan = client.post(f"/api/targets/{target['id']}/check", json={"force": [str(path)]}).json()
    assert plan["summary"]["status"] == "pending"
    res = client.post(f"/api/targets/{target['id']}/apply",
                      json={"plan_hash": plan["summary"]["hash"], "force": [str(path)]}).json()
    assert res["status"].startswith("ok"), res
    assert "# edited by hand" not in path.read_text()
    assert "# Tamiz #1: Search box" in path.read_text()


def test_validation_failure_rolls_back(client, tmp_path):
    target, waf = setup_target(client, tmp_path)
    g = client.post("/api/groups", json={"name": "app", "target_ids": [target["id"]]}).json()
    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "global", "action": "remove_rule", "selector_type": "id",
        "selectors": ["920350"], "reason": "fine"})
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]})
    good = (waf / "after" / "010-app.conf").read_text()

    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "raw", "placement": "after", "raw_text": "SecRuleRemoveById 1 # BROKEN"})
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    res = client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"] == "rolled_back", res
    names = [s["name"] for s in res["steps"]]
    assert names[-3:] == ["validate", "rollback", "revalidate"]
    assert (waf / "after" / "010-app.conf").read_text() == good


def test_plan_hash_must_match(client, tmp_path):
    target, waf = setup_target(client, tmp_path)
    g = client.post("/api/groups", json={"name": "app", "target_ids": [target["id"]]}).json()
    client.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                         "selector_type": "id", "selectors": ["1"]})
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    client.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                         "selector_type": "id", "selectors": ["2"]})
    res = client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"] == "failed" and res["steps"][-1]["detail"] == "plan_changed"


def test_shared_layout_keeps_foreign_content(client, tmp_path):
    waf = tmp_path / "waf" / "crs"
    waf.mkdir(parents=True)
    before = waf / "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
    after = waf / "RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf"
    original = "# hand written\nSecRule REMOTE_ADDR \"@ipMatch 10.1.1.1\" \"id:5,phase:1,pass,nolog,ctl:ruleEngine=Off\"\n"
    before.write_text(original)
    after.write_text("")
    r = client.post("/api/targets", json={
        "name": "shared", "platform": "custom", "transport": "local",
        "layout": {"mode": "shared", "before": str(before), "after": str(after)},
        "commands": {"validate": "", "reload": "", "sudo_mode": "none"}})
    t = r.json()
    g = client.post("/api/groups", json={"name": "web", "target_ids": [t["id"]]}).json()
    client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "conditional", "action": "remove_rule", "selector_type": "id",
        "selectors": ["911100"],
        "conditions": [{"variable": "REQUEST_FILENAME", "operator": "beginsWith", "value": "/api/"}]})
    plan = client.post(f"/api/targets/{t['id']}/check", json={}).json()
    res = client.post(f"/api/targets/{t['id']}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"].startswith("ok"), res
    text = before.read_text()
    assert text.startswith(original)
    assert "tamiz:begin group=web" in text
    # Removing the group from the target removes only the block.
    client.put(f"/api/targets/{t['id']}/groups", json={"group_ids": []})
    plan = client.post(f"/api/targets/{t['id']}/check", json={}).json()
    res = client.post(f"/api/targets/{t['id']}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"].startswith("ok"), res
    assert before.read_text() == original


def test_local_transport_refuses_paths_outside_roots(client, tmp_path):
    r = client.post("/api/targets", json={
        "name": "evil", "platform": "custom", "transport": "local",
        "layout": {"mode": "per_group", "before": "/etc/{group}-b.conf", "after": "/etc/{group}-a.conf"},
        "commands": {}})
    t = r.json()
    g = client.post("/api/groups", json={"name": "x", "target_ids": [t["id"]]}).json()
    client.post("/api/exclusions", json={"group_id": g["id"], "scope": "global", "action": "remove_rule",
                                         "selector_type": "id", "selectors": ["1"]})
    r = client.post(f"/api/targets/{t['id']}/check", json={})
    assert r.status_code == 502 and r.json()["error"] == "path_not_allowed"


def test_roles_and_csrf(client, cfg):
    r = client.post("/api/users", json={"username": "ana", "password": "0123456789ab", "role": "viewer"})
    assert r.status_code == 200
    from fastapi.testclient import TestClient
    from tamiz.main import app
    with TestClient(app) as other:
        other.headers["X-Tamiz"] = "1"
        other.post("/api/auth/login", json={"username": "ana", "password": "0123456789ab"})
        assert other.get("/api/groups").status_code == 200
        assert other.post("/api/groups", json={"name": "nope"}).status_code == 403
        del other.headers["X-Tamiz"]
        assert other.post("/api/auth/logout").status_code == 403  # missing CSRF header


def test_static_files_are_revalidated(client):
    """Without Cache-Control the browser kept the old JavaScript after an upgrade."""
    r = client.get("/static/js/app.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
    again = client.get("/static/js/app.js", headers={"If-None-Match": r.headers["etag"]})
    assert again.status_code == 304 and again.headers["cache-control"] == "no-cache"
    assert client.get("/").headers["cache-control"] == "no-cache"
    assert client.get("/api/health").headers["cache-control"] == "no-store"


def test_empty_file_at_a_managed_path_is_adopted(client, tmp_path):
    # Admins create empty placeholder files so a new Include glob matches
    # before Tamiz's first apply; those must not block the plan as "foreign".
    target, waf = setup_target(client, tmp_path)
    (waf / "before").mkdir()
    (waf / "before" / "000-tamiz-keep.conf").write_text("")
    (waf / "after").mkdir()
    (waf / "after" / "000-tamiz-keep.conf").write_text("# notes from someone\n")
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    ops = {o["path"].split("/conf/")[1]: o for o in plan["ops"]}
    assert ops["before/000-tamiz-keep.conf"]["action"] == "update"
    assert ops["after/000-tamiz-keep.conf"]["action"] == "blocked"   # has content: never overwritten silently


def test_removing_the_last_exclusion_deletes_the_file_but_keeps_the_placeholder(client, tmp_path):
    target, waf = setup_target(client, tmp_path)
    g = client.post("/api/groups", json={"name": "shop", "target_ids": [target["id"]]}).json()
    ex = client.post("/api/exclusions", json={
        "group_id": g["id"], "scope": "global", "action": "remove_rule", "selector_type": "id",
        "selectors": ["920350"], "reason": "x"}).json()
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]})
    group_file = waf / "after" / "010-shop.conf"
    assert group_file.exists()

    assert client.delete(f"/api/exclusions/{ex['id']}").status_code == 200
    plan = client.post(f"/api/targets/{target['id']}/check", json={}).json()
    actions = {o["path"]: o["action"] for o in plan["ops"]}
    assert actions[str(group_file)] == "delete"
    res = client.post(f"/api/targets/{target['id']}/apply", json={"plan_hash": plan["summary"]["hash"]}).json()
    assert res["status"].startswith("ok"), res
    assert not group_file.exists()
    assert (waf / "after" / "000-tamiz-keep.conf").exists()
