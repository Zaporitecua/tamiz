"""Transport interface: how Tamiz reaches a WAF.

A transport only has to provide ``_exec(command_line, stdin, timeout)``: run
a shell command line on the far side and return its exit code and output.
Everything else (reading, writing, globbing, SELinux checks) is built on top
with the scripts in ``scripts.py``, so all transports behave the same way.

Privileges are controlled by the target's ``sudo_mode``:

* ``none``: everything runs as the connecting user. Recommended when that
  user owns the directories Tamiz writes to.
* ``commands``: file operations run as the user; the configured commands
  (validate, reload, discover, reading logs) run with ``sudo``. This allows a
  narrow sudoers rule.
* ``all``: everything runs with ``sudo``.
"""
from __future__ import annotations

import base64
import shlex
import time
from dataclasses import dataclass, field

from . import scripts

MAX_OUTPUT = 32 * 1024 * 1024
# Base64 characters per write command (a multiple of 4, so each part decodes
# on its own). Linux refuses any single argument over 128 KiB.
WRITE_CHUNK_SIZE = 60_000


class TransportError(Exception):
    """Connection-level failure (unreachable, authentication, host key ...)."""

    def __init__(self, code: str, message: str = "", **params):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.params = params


class NotSupported(TransportError):
    def __init__(self, what: str):
        super().__init__("not_supported", f"this transport cannot {what}")


@dataclass
class CmdResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    stdout_bytes: bytes = field(default=b"", repr=False)

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def summary(self, limit: int = 4000) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout[-limit:],
            "stderr": self.stderr[-limit:],
            "duration_ms": self.duration_ms,
        }


@dataclass
class FileRead:
    path: str
    status: str                     # ok | missing | unreadable | notfile
    content: str | None = None      # decoded with surrogateescape

    @property
    def exists(self) -> bool:
        return self.status != "missing"


def decode(data: bytes) -> str:
    # surrogateescape keeps any non-UTF-8 byte (old Latin-1 comments, say)
    # so the file can be written back exactly as it was.
    return data.decode("utf-8", "surrogateescape")


def encode(text: str) -> bytes:
    return text.encode("utf-8", "surrogateescape")


def printable(text: str | None) -> str | None:
    """Text safe to send to the browser (JSON cannot carry surrogates)."""
    if text is None:
        return None
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def check_path(path: str) -> None:
    if not path.startswith("/") or any(c in path for c in "\t\n\r\0") or "/../" in path + "/":
        raise TransportError("invalid_path", f"invalid path: {path!r}")


class Transport:
    kind = "base"
    remote = True          # False for the export transport

    def __init__(self, target: dict, secret: dict, timeout: int = 60):
        self.target = target
        self.secret = secret or {}
        self.timeout = timeout
        cmds = target.get("commands") or {}
        self.sudo_mode = cmds.get("sudo_mode", "none")
        self.prefix = (cmds.get("command_prefix") or "").strip()
        self.learned_host_key: str | None = None
        self.log: list[CmdResult] = []

    # ------------------------------------------------------------ lifecycle
    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self) -> "Transport":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ primitive
    def _exec(self, command_line: str, stdin: bytes | None, timeout: int) -> CmdResult:
        raise NotImplementedError

    def _sudo(self) -> tuple[str, bytes | None]:
        password = self.secret.get("sudo_password")
        if password:
            return "sudo -S -p '' ", (password + "\n").encode()
        return "sudo -n ", None

    def _wrap(self, command_line: str, privileged: bool) -> tuple[str, bytes | None]:
        stdin = None
        line = command_line
        if self.prefix:
            line = f"{self.prefix} {line}"
        if privileged:
            sudo, stdin = self._sudo()
            line = sudo + line
        return line, stdin

    def run_script(self, script: str, args: list[str], privileged: bool | None = None,
                   timeout: int | None = None, label: str = "") -> CmdResult:
        if privileged is None:
            privileged = self.sudo_mode == "all"
        quoted = " ".join(shlex.quote(a) for a in args)
        line, stdin = self._wrap(f"sh -c {shlex.quote(script.strip())} tamiz {quoted}", privileged)
        started = time.monotonic()
        res = self._exec(line, stdin, timeout or self.timeout)
        res.duration_ms = int((time.monotonic() - started) * 1000)
        res.command = label or "sh -c <script>"
        return res

    def run_command(self, command: str, privileged: bool | None = None,
                    timeout: int | None = None) -> CmdResult:
        """Run a command configured by an administrator (validate, reload ...)."""
        if privileged is None:
            privileged = self.sudo_mode in ("commands", "all")
        line, stdin = self._wrap(command, privileged)
        started = time.monotonic()
        res = self._exec(line, stdin, timeout or self.timeout)
        res.duration_ms = int((time.monotonic() - started) * 1000)
        res.command = command
        self.log.append(res)
        return res

    # ------------------------------------------------------------ file ops
    def read_files(self, paths: list[str]) -> dict[str, FileRead]:
        out: dict[str, FileRead] = {}
        if not paths:
            return out
        for p in paths:
            check_path(p)
        res = self.run_script(scripts.READ_FILES, list(paths), label="read files")
        if not res.ok:
            raise TransportError("read_failed", res.stderr.strip() or "could not read files")
        for line in res.stdout_bytes.split(b"\n"):
            if not line:
                continue
            parts = line.split(b"\t", 2)
            if len(parts) < 2:
                continue
            path = decode(parts[0])
            status = parts[1].decode()
            content = None
            if status == "ok":
                content = decode(base64.b64decode(parts[2] if len(parts) > 2 else b""))
            out[path] = FileRead(path, status, content)
        for p in paths:
            out.setdefault(p, FileRead(p, "missing"))
        return out

    def read_file(self, path: str) -> FileRead:
        return self.read_files([path])[path]

    def write_file(self, path: str, content: str, mkdirs: bool = False) -> CmdResult:
        check_path(path)
        b64 = base64.b64encode(encode(content)).decode()
        flag = "1" if mkdirs else "0"
        if len(b64) <= WRITE_CHUNK_SIZE:
            return self.run_script(scripts.WRITE_FILE, [path, b64, flag], label=f"write {path}")
        # Too big for one command line: send it in parts to the temporary
        # file, then let WRITE_FILE do the atomic rename as usual.
        parts = [b64[i:i + WRITE_CHUNK_SIZE] for i in range(0, len(b64), WRITE_CHUNK_SIZE)]
        for n, part in enumerate(parts):
            res = self.run_script(scripts.WRITE_CHUNK, [path, part, "1" if n == 0 else "0", flag],
                                  label=f"write {path} (part {n + 1}/{len(parts)})")
            if not res.ok:
                self.run_script(scripts.DISCARD_TMP, [path], label=f"discard {path}")
                return res
        return self.run_script(scripts.WRITE_FILE, [path, "-", flag], label=f"write {path}")

    def remove_file(self, path: str) -> CmdResult:
        check_path(path)
        return self.run_script(scripts.REMOVE_FILE, [path], label=f"remove {path}")

    def glob(self, patterns: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {p: [] for p in patterns}
        if not patterns:
            return out
        res = self.run_script(scripts.GLOB, patterns, label="glob")
        for line in res.stdout.splitlines():
            pat, _, path = line.partition("\t")
            if pat in out and path:
                out[pat].append(path)
        return out

    def writable(self, paths: list[str], mkdirs: bool) -> dict[str, tuple[str, str]]:
        """Whether each file can be written atomically by the effective user."""
        res = self.run_script(scripts.WRITABLE, ["1" if mkdirs else "0", *paths], label="permissions")
        out: dict[str, tuple[str, str]] = {}
        for line in res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                out[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
        return out

    def selinux_verify(self, paths: list[str]) -> dict:
        res = self.run_script(scripts.SELINUX_VERIFY, paths, privileged=False, label="selinux check")
        lines = res.stdout.splitlines()
        report = {"enabled": bool(lines) and lines[0] == "selinux=on", "files": {}}
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 2:
                report["files"][parts[0]] = {
                    "status": parts[1],
                    "label": parts[2] if len(parts) > 2 else "",
                    "detail": parts[3] if len(parts) > 3 else "",
                }
        return report

    def selinux_scan(self, dirs: list[str]) -> dict:
        res = self.run_script(scripts.SELINUX_SCAN_DIRS, dirs, privileged=False, label="selinux scan")
        lines = res.stdout.splitlines()
        enabled = bool(lines) and lines[-1] == "selinux=on"
        return {"enabled": enabled,
                "mislabeled": [ln for ln in lines[:-1] if ln.strip()] if enabled else []}

    def tail(self, path: str, nbytes: int) -> bytes:
        check_path(path)
        res = self.run_command(f"tail -c {int(nbytes)} -- {shlex.quote(path)}",
                               privileged=self.sudo_mode in ("commands", "all"))
        if not res.ok:
            raise TransportError("log_read_failed", res.stderr.strip() or f"cannot read {path}")
        return res.stdout_bytes

    def diagnose(self, dirs: list[str]) -> dict:
        res = self.run_script(scripts.DIAGNOSE, dirs, privileged=False, label="diagnose")
        info: dict = {"dirs": []}
        for line in res.stdout.splitlines():
            if line.startswith("dir\t"):
                _, d, state, writable, owner = (line.split("\t") + [""] * 5)[:5]
                info["dirs"].append({"path": d, "state": state, "writable": writable == "yes",
                                     "owner": owner})
            elif "=" in line:
                k, _, v = line.partition("=")
                info[k] = v
        info["exit_code"] = res.exit_code
        if res.stderr.strip():
            info["stderr"] = res.stderr.strip()[-1000:]
        return info

    def check_sudo(self) -> CmdResult:
        return self.run_command("true", privileged=True, timeout=15)
