"""Encryption of stored credentials (SSH passwords, inline keys, sudo passwords).

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The key comes
from TAMIZ_SECRET_KEY; when it is not set, Tamiz generates one on first start
and keeps it in the data volume (``secret.key``, mode 0600) so that a plain
``docker compose up`` works. Back up the data volume and that key together:
without the key, stored credentials cannot be decrypted.
"""
from __future__ import annotations

import json
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

from .. import config

log = logging.getLogger("tamiz")
_fernet: Fernet | None = None


def _load_key() -> bytes:
    cfg = config.get()
    if cfg.secret_key:
        return cfg.secret_key.encode()
    path = cfg.data_dir / "secret.key"
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    log.warning("TAMIZ_SECRET_KEY is not set: generated %s. Back it up with the database.", path)
    return key


def fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        try:
            _fernet = Fernet(_load_key())
        except ValueError as e:
            raise SystemExit(f"TAMIZ_SECRET_KEY is not a valid Fernet key: {e}")
    return _fernet


def reset_for_tests() -> None:
    global _fernet
    _fernet = None


def encrypt(data: dict) -> str | None:
    clean = {k: v for k, v in data.items() if v}
    if not clean:
        return None
    return fernet().encrypt(json.dumps(clean).encode()).decode()


class SecretUnreadable(Exception):
    """Stored credentials were encrypted with another key (secret.key lost
    or TAMIZ_SECRET_KEY changed). The admin has to type them again."""


def decrypt(token: str | None) -> dict:
    if not token:
        return {}
    try:
        return json.loads(fernet().decrypt(token.encode()).decode())
    except (InvalidToken, ValueError):
        raise SecretUnreadable("stored credentials cannot be decrypted: was TAMIZ_SECRET_KEY changed?")


def readable(token: str | None) -> bool:
    try:
        decrypt(token)
        return True
    except SecretUnreadable:
        return False
