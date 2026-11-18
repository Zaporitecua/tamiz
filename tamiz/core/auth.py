"""Authentication and roles.

Three modes (TAMIZ_AUTH_MODE):

``local``  users and passwords stored in Tamiz (scrypt hashes). Sessions are
           random tokens in an HttpOnly, SameSite=Strict cookie; the database
           stores only their SHA-256.
``proxy``  a reverse proxy (Authelia, oauth2-proxy, Authentik ...) logs the
           user in and passes the name in a header. The header is trusted only
           from TAMIZ_TRUSTED_PROXIES. Roles come from group headers.
``none``   no login. Everyone is an administrator. Only for a lab or a network
           where nobody else can reach Tamiz; the UI shows a permanent banner.

Roles: ``viewer`` (read only) < ``editor`` (exclusions, groups, apply,
import, analyze) < ``admin`` (targets, credentials, users, settings).

API tokens (``Authorization: Bearer tmz_...``) act as their owner, for
scripts and CI pipelines.

CSRF: requests authenticated with the session cookie that change state must
carry the header ``X-Tamiz: 1``. Browsers cannot add custom headers to
cross-site requests without a CORS preflight, which Tamiz never allows.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import logging
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .. import config, db

log = logging.getLogger("tamiz")

ROLES =("viewer", "editor", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
COOKIE = "tamiz_session"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


@dataclass
class Principal:
    id: int | None
    username: str
    display_name: str
    role: str
    via: str                    # session | token | proxy | none

    def can(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]

    def public(self) -> dict:
        return {"id": self.id, "username": self.username, "display_name": self.display_name,
                "role": self.role, "via": self.via}


# --------------------------------------------------------------- passwords --

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=128 * 1024 * 1024, dklen=32)
    return "scrypt${}${}${}${}${}".format(SCRYPT_N, SCRYPT_R, SCRYPT_P,
                                          base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        # Burn the same time as a real check so missing users are not detectable.
        hashlib.scrypt(b"x", salt=b"0" * 16, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                       maxmem=128 * 1024 * 1024, dklen=32)
        return False
    _, n, r, p, salt, dk = stored.split("$")
    test = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r),
                          p=int(p), maxmem=128 * 1024 * 1024, dklen=32)
    return hmac.compare_digest(test, base64.b64decode(dk))


def password_problem(password: str) -> str | None:
    if len(password) < 10:
        return "password_too_short"
    if len(password) > 256:
        return "password_too_long"
    return None


# ------------------------------------------------------------ rate limiting --

class LoginThrottle:
    """At most 5 failures per (IP, user) in 15 minutes."""

    def __init__(self, limit: int = 5, window: int = 900):
        self.limit, self.window = limit, window
        self.failures: dict[tuple[str, str], list[float]] = {}
        self.lock = threading.Lock()

    def _recent(self, key) -> list[float]:
        now = time.monotonic()
        hits = [t for t in self.failures.get(key, []) if now - t < self.window]
        self.failures[key] = hits
        return hits

    def blocked(self, ip: str, user: str) -> bool:
        with self.lock:
            return len(self._recent((ip, user.lower()))) >= self.limit

    def fail(self, ip: str, user: str) -> None:
        with self.lock:
            self._recent((ip, user.lower())).append(time.monotonic())

    def reset(self, ip: str, user: str) -> None:
        with self.lock:
            self.failures.pop((ip, user.lower()), None)


throttle = LoginThrottle()


# ---------------------------------------------------------------- sessions --

def _sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int, ip: str, ua: str) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=config.get().session_hours)
    conn.execute("INSERT INTO sessions(id, user_id, created_at, expires_at, ip, user_agent) "
                 "VALUES (?,?,?,?,?,?)", (_sha(token), user_id, now.isoformat(), expires.isoformat(),
                                          ip, (ua or "")[:200]))
    conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now(), user_id))
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
    return token


def drop_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE id=?", (_sha(token),))


def session_user(conn: sqlite3.Connection, token: str) -> Principal | None:
    r = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.id=? AND s.expires_at > ? AND u.disabled=0",
        (_sha(token), datetime.now(timezone.utc).isoformat())).fetchone()
    if not r:
        return None
    return Principal(r["id"], r["username"], r["display_name"] or r["username"], r["role"], "session")


# ------------------------------------------------------------------ tokens --

def create_token(conn: sqlite3.Connection, user_id: int, name: str, days: int | None) -> tuple[str, int]:
    prefix = secrets.token_hex(4)
    token = f"tmz_{prefix}_{secrets.token_urlsafe(32)}"
    expires = None
    if days:
        expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    cur = conn.execute("INSERT INTO api_tokens(user_id, name, token_hash, prefix, created_at, expires_at) "
                       "VALUES (?,?,?,?,?,?)", (user_id, name.strip()[:80], _sha(token), prefix,
                                                db.now(), expires))
    return token, cur.lastrowid


def token_user(conn: sqlite3.Connection, token: str) -> Principal | None:
    r = conn.execute(
        "SELECT u.*, t.id AS token_id, t.expires_at AS token_expires FROM api_tokens t "
        "JOIN users u ON u.id = t.user_id WHERE t.token_hash=? AND u.disabled=0",
        (_sha(token),)).fetchone()
    if not r:
        return None
    if r["token_expires"] and r["token_expires"] < datetime.now(timezone.utc).isoformat():
        return None
    conn.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (db.now(), r["token_id"]))
    return Principal(r["id"], r["username"], r["display_name"] or r["username"], r["role"], "token")


# ------------------------------------------------------------------- proxy --

def trusted_proxy(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in config.get().trusted_proxies)


def peer_ip(request) -> str:
    """The address of whoever opened the connection (uvicorn runs with
    --no-proxy-headers, so this is never taken from a header)."""
    return request.client.host if request.client else ""


def client_ip(request) -> str:
    """Best guess of the end user's address, for login throttling and the
    sessions list. X-Forwarded-For is only read when the connection comes from
    a trusted proxy, walking it right to left and skipping trusted hops."""
    peer = peer_ip(request)
    if not trusted_proxy(peer):
        return peer
    hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
    for hop in reversed(hops):
        if not trusted_proxy(hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return peer
    return peer


_warned_untrusted: set[str] = set()


def warn_untrusted_proxy(ip: str, header: str) -> None:
    """Proxy mode received a user header from an address outside
    TAMIZ_TRUSTED_PROXIES. Logged once per address: the usual cause is the
    Docker network gateway missing from the list."""
    if ip in _warned_untrusted or len(_warned_untrusted) > 100:
        return
    _warned_untrusted.add(ip)
    log.warning("ignored %s header from %s: not in TAMIZ_TRUSTED_PROXIES", header, ip or "?")


def proxy_user(conn: sqlite3.Connection, username: str, groups_header: str) -> Principal | None:
    cfg = config.get()
    groups = {g.strip() for g in groups_header.replace(";", ",").split(",") if g.strip()}
    if cfg.proxy_admin_groups and groups & set(cfg.proxy_admin_groups):
        role = "admin"
    elif cfg.proxy_editor_groups and groups & set(cfg.proxy_editor_groups):
        role = "editor"
    else:
        role = cfg.proxy_default_role
    if role == "none":
        return None
    username = username.strip()[:120]
    r = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if r is None:
        conn.execute("INSERT INTO users(username, display_name, role, source, created_at) "
                     "VALUES (?,?,?,?,?)", (username, username, role, "proxy", db.now()))
        r = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    elif r["disabled"]:
        return None
    elif r["role"] != role and r["source"] == "proxy":
        conn.execute("UPDATE users SET role=? WHERE id=?", (role, r["id"]))
    conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (db.now(), r["id"]))
    return Principal(r["id"], r["username"], r["display_name"] or r["username"], role, "proxy")


# ------------------------------------------------------------ first start --

def setup_needed(conn: sqlite3.Connection) -> bool:
    if config.get().auth_mode != "local":
        return False
    return conn.execute("SELECT 1 FROM users WHERE source='local' AND role='admin' AND disabled=0 "
                        "LIMIT 1").fetchone() is None


def ensure_setup_code(conn: sqlite3.Connection) -> str | None:
    """One-time code printed in the container log; required to create the
    first administrator, so whoever reaches the UI first cannot claim it."""
    if not setup_needed(conn):
        db.meta_set(conn, "setup_code", None)
        return None
    code = db.meta_get(conn, "setup_code")
    if not code:
        code = "-".join(secrets.token_hex(2) for _ in range(4))
        db.meta_set(conn, "setup_code", code)
    return code


def bootstrap_admin(conn: sqlite3.Connection) -> bool:
    cfg = config.get()
    if not (cfg.admin_user and cfg.admin_password) or not setup_needed(conn):
        return False
    conn.execute("INSERT INTO users(username, display_name, password_hash, role, created_at) "
                 "VALUES (?,?,?,?,?)", (cfg.admin_user, cfg.admin_user,
                                        hash_password(cfg.admin_password), "admin", db.now()))
    return True
