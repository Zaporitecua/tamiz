"""Local transport: the WAF files are mounted into the Tamiz container.

Useful when Tamiz runs on the same host as the WAF and shares the exclusions
directory through a volume. Validate and reload commands run inside the Tamiz
container, so they are typically an HTTP call to the WAF or are left empty
(write-only mode).

For safety, every path must be under one of TAMIZ_LOCAL_ROOTS (default
``/waf``): an administrator cannot point a local target at Tamiz's own
database or keys by mistake.
"""
from __future__ import annotations

import os
import subprocess

from .. import config
from .base import CmdResult, Transport, TransportError, check_path, decode


class LocalTransport(Transport):
    kind = "local"

    def _allowed(self, path: str) -> bool:
        real = os.path.realpath(path)
        for root in config.get().local_roots:
            root = os.path.realpath(root)
            if real == root or real.startswith(root.rstrip("/") + "/"):
                return True
        return False

    def _guard(self, paths) -> None:
        for p in paths:
            check_path(p)
            if any(c in p for c in "*?["):
                probe = p.split("*")[0].split("?")[0].split("[")[0].rsplit("/", 1)[0] or "/"
            else:
                probe = p  # realpath follows symlinks out of the allowed roots
            if not self._allowed(probe):
                raise TransportError("path_not_allowed",
                                     f"{p} is outside TAMIZ_LOCAL_ROOTS")

    def read_files(self, paths):
        self._guard(paths)
        return super().read_files(paths)

    def write_file(self, path, content, mkdirs=False):
        self._guard([path])
        return super().write_file(path, content, mkdirs)

    def remove_file(self, path):
        self._guard([path])
        return super().remove_file(path)

    def glob(self, patterns):
        self._guard(patterns)
        return super().glob(patterns)

    def tail(self, path, nbytes):
        self._guard([path])
        return super().tail(path, nbytes)

    def _exec(self, command_line: str, stdin: bytes | None, timeout: int) -> CmdResult:
        try:
            p = subprocess.run(["sh", "-c", command_line], input=stdin, capture_output=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TransportError("timeout", f"command timed out after {timeout}s")
        return CmdResult(command_line, p.returncode, decode(p.stdout), decode(p.stderr), 0, p.stdout)
