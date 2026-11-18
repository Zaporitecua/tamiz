"""Test fixtures: an isolated data directory and an API client per test."""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tamiz import config
from tamiz.core import secrets


def make_config(tmp: Path, **overrides) -> config.Config:
    cfg = config.Config(
        data_dir=tmp / "data", keys_dir=tmp / "keys", auth_mode="local", secret_key=None,
        session_hours=12, cookie_secure="false", proxy_user_header="X-Forwarded-User",
        proxy_groups_header="X-Forwarded-Groups", proxy_admin_groups=["waf-admins"],
        proxy_editor_groups=["waf-editors"], proxy_default_role="viewer",
        trusted_proxies=[ipaddress.ip_network("127.0.0.1/32")],
        local_roots=[str(tmp / "waf")], admin_user="admin", admin_password="correct horse battery",
        command_timeout=30,
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    (tmp / "keys").mkdir(exist_ok=True)
    (tmp / "waf").mkdir(exist_ok=True)
    return cfg


@pytest.fixture
def cfg(tmp_path):
    c = make_config(tmp_path)
    config.set_for_tests(c)
    secrets.reset_for_tests()
    yield c
    secrets.reset_for_tests()


@pytest.fixture
def client(cfg):
    from tamiz.main import app
    with TestClient(app) as c:
        c.headers["X-Tamiz"] = "1"
        r = c.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery"})
        assert r.status_code == 200, r.text
        yield c
