"""SQLite storage: connection handling and schema migrations.

One SQLite file in the data volume holds everything. Each request opens its
own connection (cheap with SQLite) and wraps writes in ``tx()``. WAL mode lets
readers continue while an apply is writing its history.

Migrations are a list of SQL scripts. ``meta.schema_version`` records how
many have run; a new release appends scripts and never edits old ones.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from . import config

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT,
        role TEXT NOT NULL CHECK (role IN ('admin','editor','viewer')),
        source TEXT NOT NULL DEFAULT 'local',
        disabled INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        last_login_at TEXT
    );
    CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        ip TEXT, user_agent TEXT
    );
    CREATE TABLE api_tokens (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        expires_at TEXT
    );

    CREATE TABLE targets (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        description TEXT NOT NULL DEFAULT '',
        environment TEXT NOT NULL DEFAULT '',
        platform TEXT NOT NULL,
        transport TEXT NOT NULL,
        conn TEXT NOT NULL DEFAULT '{}',
        secret TEXT,
        layout TEXT NOT NULL DEFAULT '{}',
        commands TEXT NOT NULL DEFAULT '{}',
        logs TEXT NOT NULL DEFAULT '{}',
        entry_files TEXT NOT NULL DEFAULT '[]',
        import_paths TEXT NOT NULL DEFAULT '[]',
        host_key TEXT,
        require_review INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_check_at TEXT,
        last_check_error TEXT,
        last_status TEXT
    );

    CREATE TABLE groups (
        id INTEGER PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE group_blocks (
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        block INTEGER NOT NULL UNIQUE,
        position INTEGER NOT NULL,
        PRIMARY KEY (group_id, block)
    );
    CREATE TABLE target_groups (
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
        PRIMARY KEY (target_id, group_id)
    );

    CREATE TABLE exclusions (
        id INTEGER PRIMARY KEY,
        group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE RESTRICT,
        scope TEXT NOT NULL CHECK (scope IN ('conditional','global','raw')),
        action TEXT,
        selector_type TEXT,
        selectors TEXT NOT NULL DEFAULT '[]',
        variables TEXT NOT NULL DEFAULT '[]',
        engine_mode TEXT,
        conditions TEXT NOT NULL DEFAULT '[]',
        phase INTEGER,
        log INTEGER NOT NULL DEFAULT 0,
        extra_actions TEXT NOT NULL DEFAULT '[]',
        rule_id INTEGER UNIQUE,
        raw_text TEXT,
        placement TEXT,
        raw_ids TEXT NOT NULL DEFAULT '[]',
        source_text TEXT,
        verbatim INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL DEFAULT '',
        reference TEXT NOT NULL DEFAULT '',
        expires_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        origin TEXT NOT NULL DEFAULT 'ui',
        fingerprint TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
    );
    CREATE INDEX exclusions_group ON exclusions(group_id);

    CREATE TABLE managed_files (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        mode TEXT NOT NULL CHECK (mode IN ('file','block')),
        group_slug TEXT NOT NULL,
        placement TEXT NOT NULL,
        last_applied_hash TEXT,
        last_applied_at TEXT,
        last_applied_content TEXT,
        remote_hash TEXT,
        remote_state TEXT,
        remote_checked_at TEXT,
        UNIQUE (target_id, path, group_slug)
    );

    CREATE TABLE retirements (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        spans TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT '',
        done_at TEXT
    );

    CREATE TABLE applies (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        actor TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        reload INTEGER NOT NULL DEFAULT 1,
        plan_hash TEXT,
        steps TEXT NOT NULL DEFAULT '[]',
        summary TEXT NOT NULL DEFAULT '',
        summary_code TEXT NOT NULL DEFAULT '',
        summary_params TEXT NOT NULL DEFAULT '{}',
        review_id INTEGER
    );
    CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY,
        apply_id INTEGER REFERENCES applies(id) ON DELETE CASCADE,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        path TEXT NOT NULL,
        existed INTEGER NOT NULL,
        content TEXT,
        taken_at TEXT NOT NULL
    );

    CREATE TABLE reviews (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
        plan_hash TEXT NOT NULL,
        plan_summary TEXT NOT NULL DEFAULT '',
        requested_by TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        decided_by TEXT,
        decided_at TEXT,
        decision_note TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE history (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        entity TEXT NOT NULL DEFAULT '',
        entity_id INTEGER,
        summary TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '{}',
        ok INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX history_at ON history(at);
    CREATE INDEX history_entity ON history(entity, entity_id);
    """,
]


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    cfg = config.get()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cfg.db_path, timeout=15, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block inside an IMMEDIATE transaction (one writer at a time)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migrate() -> int:
    with db() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        version = int(row["value"]) if row else 0
        for i, script in enumerate(MIGRATIONS[version:], start=version + 1):
            with tx(conn):
                # executescript would commit implicitly; run statements one by one.
                for stmt in _split_sql(script):
                    if stmt.upper().startswith("CREATE TABLE META "):
                        continue
                    conn.execute(stmt)
                conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                             (str(i),))
            version = i
        return version


def _split_sql(script: str) -> list[str]:
    return [s.strip() for s in script.split(";") if s.strip()]


# ------------------------------------------------------------ JSON columns --

def jload(value: Any, default: Any = None) -> Any:
    if value is None or value == "":
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def jdump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r is not None else None


def rows(rs) -> list[dict]:
    return [dict(r) for r in rs]


def meta_get(conn: sqlite3.Connection, key: str) -> str | None:
    r = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def meta_set(conn: sqlite3.Connection, key: str, value: str | None) -> None:
    if value is None:
        conn.execute("DELETE FROM meta WHERE key=?", (key,))
    else:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))


def log_history(conn: sqlite3.Connection, actor: str, action: str, entity: str = "",
                entity_id: int | None = None, summary: str = "", detail: Any = None,
                ok: bool = True) -> int:
    cur = conn.execute(
        "INSERT INTO history(at, actor, action, entity, entity_id, summary, detail, ok) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (now(), actor, action, entity, entity_id, summary[:500], jdump(detail or {}), 1 if ok else 0),
    )
    return cur.lastrowid
