"""Runtime configuration, read once from environment variables.

Every variable is listed in .env.example. Values here are infrastructure
settings; workspace preferences that users change from the UI (ID ranges,
rendering style ...) live in the database (see core/settings.py).
"""
from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("tamiz")


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str = "") -> list[str]:
    return [p.strip() for p in os.environ.get(name, default).split(",") if p.strip()]


@dataclass
class Config:
    data_dir: Path
    keys_dir: Path
    auth_mode: str                      # local | proxy | none
    secret_key: str | None
    session_hours: int
    cookie_secure: str                  # auto | true | false
    proxy_user_header: str
    proxy_groups_header: str
    proxy_admin_groups: list[str]
    proxy_editor_groups: list[str]
    proxy_default_role: str
    trusted_proxies: list[ipaddress._BaseNetwork] = field(default_factory=list)
    local_roots: list[str] = field(default_factory=list)
    docker_host: str = "unix:///var/run/docker.sock"
    admin_user: str | None = None
    admin_password: str | None = None
    command_timeout: int = 60
    log_level: str = "INFO"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "tamiz.db"


def load() -> Config:
    data_dir = Path(os.environ.get("TAMIZ_DATA_DIR", "/data"))
    auth_mode = os.environ.get("TAMIZ_AUTH_MODE", "local").strip().lower()
    if auth_mode not in ("local", "proxy", "none"):
        raise SystemExit(f"TAMIZ_AUTH_MODE must be local, proxy or none (got {auth_mode!r})")
    proxies = []
    for cidr in _list("TAMIZ_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"):
        try:
            proxies.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            raise SystemExit(f"TAMIZ_TRUSTED_PROXIES: invalid network {cidr!r}")
    role = os.environ.get("TAMIZ_PROXY_DEFAULT_ROLE", "viewer").strip().lower()
    if role not in ("viewer", "editor", "admin", "none"):
        raise SystemExit("TAMIZ_PROXY_DEFAULT_ROLE must be viewer, editor, admin or none")
    cookie_secure = os.environ.get("TAMIZ_COOKIE_SECURE", "auto").strip().lower() or "auto"
    if cookie_secure not in ("auto", "true", "false"):
        raise SystemExit("TAMIZ_COOKIE_SECURE must be auto, true or false")
    return Config(
        data_dir=data_dir,
        keys_dir=Path(os.environ.get("TAMIZ_KEYS_DIR", "/keys")),
        auth_mode=auth_mode,
        secret_key=os.environ.get("TAMIZ_SECRET_KEY") or None,
        session_hours=int(os.environ.get("TAMIZ_SESSION_HOURS", "12")),
        cookie_secure=cookie_secure,
        proxy_user_header=os.environ.get("TAMIZ_PROXY_USER_HEADER", "X-Forwarded-User"),
        proxy_groups_header=os.environ.get("TAMIZ_PROXY_GROUPS_HEADER", "X-Forwarded-Groups"),
        proxy_admin_groups=_list("TAMIZ_PROXY_ADMIN_GROUPS"),
        proxy_editor_groups=_list("TAMIZ_PROXY_EDITOR_GROUPS"),
        proxy_default_role=role,
        trusted_proxies=proxies,
        local_roots=_list("TAMIZ_LOCAL_ROOTS", "/waf"),
        docker_host=os.environ.get("TAMIZ_DOCKER_HOST", "unix:///var/run/docker.sock"),
        admin_user=os.environ.get("TAMIZ_ADMIN_USER") or None,
        admin_password=os.environ.get("TAMIZ_ADMIN_PASSWORD") or None,
        command_timeout=int(os.environ.get("TAMIZ_COMMAND_TIMEOUT", "60")),
        log_level=os.environ.get("TAMIZ_LOG_LEVEL", "INFO").upper(),
    )


_config: Config | None = None


def get() -> Config:
    global _config
    if _config is None:
        _config = load()
    return _config


def set_for_tests(cfg: Config) -> None:
    global _config
    _config = cfg
