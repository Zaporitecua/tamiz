"""SSH transport (paramiko).

Host keys are pinned on first use: the first successful connection stores the
server's key in the target; later connections refuse a different key until an
administrator resets it from the target page. Optionally the connection goes
through a jump host (bastion).
"""
from __future__ import annotations

import io
import json
import socket
import time
from pathlib import Path

import paramiko

from .. import config
from .base import MAX_OUTPUT, CmdResult, Transport, TransportError, decode


def fingerprint(key_line: str) -> str:
    import base64
    import hashlib
    try:
        blob = base64.b64decode(key_line.split()[1])
    except (IndexError, ValueError):
        return key_line
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


class _PinPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str | None):
        self.expected = expected
        self.seen: str | None = None

    def missing_host_key(self, client, hostname, key):
        seen = f"{key.get_name()} {key.get_base64()}"
        self.seen = seen
        if self.expected and self.expected != seen:
            raise TransportError("host_key_mismatch",
                                 "the server presented a different host key",
                                 expected=fingerprint(self.expected), seen=fingerprint(seen))


def load_private_key(text: str | None = None, path: str | None = None,
                     passphrase: str | None = None) -> paramiko.PKey:
    errors = []
    if path:
        p = Path(path)
        if not p.is_absolute():
            p = config.get().keys_dir / p
        if not p.exists():
            raise TransportError("key_not_found", f"key file not found: {p}")
        text = p.read_text()
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text or ""), password=passphrase or None)
        except paramiko.PasswordRequiredException:
            raise TransportError("key_needs_passphrase", "the private key is encrypted")
        except (paramiko.SSHException, ValueError) as e:
            errors.append(str(e))
    raise TransportError("key_invalid", "unsupported or invalid private key")


class SSHTransport(Transport):
    kind = "ssh"

    def __init__(self, target, secret, timeout=60):
        super().__init__(target, secret, timeout)
        self.client: paramiko.SSHClient | None = None
        self.jump: paramiko.SSHClient | None = None
        pins = target.get("host_key") or ""
        try:
            self.pins = json.loads(pins) if pins.startswith("{") else {"target": pins or None}
        except ValueError:
            self.pins = {}
        self.learned: dict[str, str] = {}

    def _connect(self, host: str, port: int, user: str, auth: dict, pin_key: str,
                 sock=None) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        policy = _PinPolicy(self.pins.get(pin_key))
        client.set_missing_host_key_policy(policy)
        kwargs: dict = dict(hostname=host, port=port, username=user, timeout=10,
                            banner_timeout=15, auth_timeout=15, allow_agent=False,
                            look_for_keys=False, sock=sock)
        if auth.get("key_text") or auth.get("key_file"):
            kwargs["pkey"] = load_private_key(auth.get("key_text"), auth.get("key_file"),
                                              auth.get("passphrase"))
        if auth.get("password"):
            kwargs["password"] = auth["password"]
        if "pkey" not in kwargs and "password" not in kwargs:
            raise TransportError("no_credentials", "configure a key or a password")
        try:
            client.connect(**kwargs)
        except TransportError:
            raise
        except paramiko.AuthenticationException:
            raise TransportError("auth_failed", f"authentication failed for {user}@{host}")
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", f"timed out connecting to {host}:{port}")
        except (OSError, paramiko.SSHException) as e:
            raise TransportError("unreachable", f"{host}:{port}: {e}")
        if policy.seen and not self.pins.get(pin_key):
            self.learned[pin_key] = policy.seen
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(20)
        return client

    def open(self) -> None:
        c = self.target.get("conn") or {}
        host = (c.get("host") or "").strip()
        if not host:
            raise TransportError("no_host", "the target has no host")
        port = int(c.get("port") or 22)
        user = (c.get("username") or "").strip()
        auth = {"key_file": c.get("key_file"), "key_text": self.secret.get("private_key"),
                "passphrase": self.secret.get("passphrase"), "password": self.secret.get("password")}
        sock = None
        jump = c.get("jump") or {}
        if jump.get("host"):
            jauth = {"key_file": jump.get("key_file") or c.get("key_file"),
                     "key_text": self.secret.get("jump_private_key") or self.secret.get("private_key"),
                     "passphrase": self.secret.get("jump_passphrase") or self.secret.get("passphrase"),
                     "password": self.secret.get("jump_password")}
            self.jump = self._connect(jump["host"], int(jump.get("port") or 22),
                                      jump.get("username") or user, jauth, "jump")
            try:
                sock = self.jump.get_transport().open_channel("direct-tcpip", (host, port), ("127.0.0.1", 0))
            except paramiko.SSHException as e:
                raise TransportError("unreachable", f"jump host could not reach {host}:{port}: {e}")
        self.client = self._connect(host, port, user, auth, "target", sock=sock)
        if self.learned:
            merged = dict(self.pins)
            merged.update(self.learned)
            if set(merged) == {"target"}:
                self.learned_host_key = merged["target"]
            else:
                self.learned_host_key = json.dumps(merged)

    def close(self) -> None:
        for c in (self.client, self.jump):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
        self.client = self.jump = None

    def _exec(self, command_line: str, stdin: bytes | None, timeout: int) -> CmdResult:
        if self.client is None:
            self.open()
        transport = self.client.get_transport()
        if transport is None or not transport.is_active():
            raise TransportError("disconnected", "the SSH connection was closed")
        chan = transport.open_session(timeout=15)
        chan.settimeout(timeout)
        try:
            chan.exec_command(command_line)
            if stdin:
                chan.sendall(stdin)
            chan.shutdown_write()
            out, err = bytearray(), bytearray()
            deadline = time.monotonic() + timeout
            while True:
                if chan.recv_ready():
                    out += chan.recv(65536)
                    if len(out) > MAX_OUTPUT:
                        raise TransportError("output_too_large", "command output too large")
                    continue
                if chan.recv_stderr_ready():
                    err += chan.recv_stderr(65536)
                    continue
                if chan.exit_status_ready():
                    break
                if time.monotonic() > deadline:
                    raise TransportError("timeout", f"command timed out after {timeout}s")
                time.sleep(0.005)
            # Drain anything that arrived together with the exit status.
            while chan.recv_ready():
                out += chan.recv(65536)
            while chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
            code = chan.recv_exit_status()
        finally:
            chan.close()
        return CmdResult(command_line, code, decode(bytes(out)), decode(bytes(err)), 0, bytes(out))
