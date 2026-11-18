"""Ways to reach a WAF: SSH, Docker API, local mount, or export only."""
from __future__ import annotations

from .. import config
from .base import CmdResult, FileRead, NotSupported, Transport, TransportError
from .docker import DockerTransport
from .export import ExportTransport
from .local import LocalTransport
from .ssh import SSHTransport

KINDS = {
    "ssh": SSHTransport,
    "docker": DockerTransport,
    "local": LocalTransport,
    "export": ExportTransport,
}


def for_target(target: dict, secret: dict) -> Transport:
    cls = KINDS.get(target.get("transport"))
    if cls is None:
        raise TransportError("invalid_transport", f"unknown transport {target.get('transport')!r}")
    timeout = int((target.get("commands") or {}).get("timeout") or config.get().command_timeout)
    return cls(target, secret, timeout)


__all__ = ["CmdResult", "FileRead", "NotSupported", "Transport", "TransportError", "for_target", "KINDS"]
