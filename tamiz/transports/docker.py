"""Docker transport: run the shell scripts inside a WAF container.

Talks to the Docker Engine API directly (``exec`` endpoints) over the Unix
socket or TCP, so the Tamiz image needs no Docker CLI. Typical use: the
official ``owasp/modsecurity-crs`` images, or any nginx/Apache container
with ModSecurity.

Mounting the Docker socket into Tamiz gives it control over every container
on the host. Prefer the SSH transport with ``command_prefix: docker exec
<container>`` when that is a concern; it reaches the same container through
a user you can restrict.

Files written into the container survive only if their directory is a volume
or bind mount. Otherwise recreating the container loses them; Tamiz then
reports them as missing and writes them again on the next apply.
"""
from __future__ import annotations

import http.client
import json
import socket
import ssl
import struct
import urllib.parse
from pathlib import Path

from .. import config
from .base import MAX_OUTPUT, CmdResult, Transport, TransportError, decode


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
        except OSError as e:
            raise TransportError("unreachable", f"Docker socket {self.socket_path}: {e}")
        self.sock = s


def demux(data: bytes) -> tuple[bytes, bytes]:
    """Split Docker's multiplexed stream (8-byte frame headers) into out/err."""
    out, err = bytearray(), bytearray()
    i = 0
    if len(data) >= 8 and data[0] in (0, 1, 2) and data[1:4] == b"\0\0\0":
        while i + 8 <= len(data):
            stream = data[i]
            size = struct.unpack(">I", data[i + 4:i + 8])[0]
            chunk = data[i + 8:i + 8 + size]
            (err if stream == 2 else out).extend(chunk)
            i += 8 + size
        return bytes(out), bytes(err)
    return data, b""


class DockerTransport(Transport):
    kind = "docker"

    def __init__(self, target, secret, timeout=60):
        super().__init__(target, secret, timeout)
        c = target.get("conn") or {}
        self.container = (c.get("container") or "").strip()
        self.user = (c.get("exec_user") or "").strip()
        self.host = (c.get("docker_host") or config.get().docker_host).strip()
        self.tls = {k: c.get(k) for k in ("tls_ca", "tls_cert", "tls_key")}
        # sudo makes no sense inside a container; the exec user decides.
        self.sudo_mode = "none"
        self.prefix = ""

    def _conn(self, timeout: float) -> http.client.HTTPConnection:
        u = urllib.parse.urlparse(self.host)
        if u.scheme == "unix":
            return _UnixHTTPConnection(u.path, timeout)
        if u.scheme in ("tcp", "http"):
            return http.client.HTTPConnection(u.hostname, u.port or 2375, timeout=timeout)
        if u.scheme == "https":
            ctx = ssl.create_default_context(cafile=self._key_path(self.tls.get("tls_ca")))
            if self.tls.get("tls_cert"):
                ctx.load_cert_chain(self._key_path(self.tls["tls_cert"]),
                                    self._key_path(self.tls.get("tls_key")))
            return http.client.HTTPSConnection(u.hostname, u.port or 2376, timeout=timeout,
                                               context=ctx)
        raise TransportError("invalid_docker_host", f"unsupported Docker host {self.host!r}")

    @staticmethod
    def _key_path(name: str | None) -> str | None:
        if not name:
            return None
        p = Path(name)
        return str(p if p.is_absolute() else config.get().keys_dir / p)

    def _request(self, method: str, path: str, body: dict | None = None,
                 timeout: float = 30) -> tuple[int, bytes]:
        conn = self._conn(timeout)
        try:
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, path, body=json.dumps(body) if body is not None else None,
                         headers=headers)
            resp = conn.getresponse()
            data = bytearray()
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > MAX_OUTPUT:
                    raise TransportError("output_too_large", "command output too large")
            return resp.status, bytes(data)
        except (socket.timeout, TimeoutError):
            raise TransportError("timeout", f"Docker API timed out ({path})")
        except OSError as e:
            raise TransportError("unreachable", f"Docker API: {e}")
        finally:
            conn.close()

    def open(self) -> None:
        if not self.container:
            raise TransportError("no_container", "the target has no container name")
        status, data = self._request("GET", f"/containers/{urllib.parse.quote(self.container)}/json")
        if status == 404:
            raise TransportError("container_not_found", f"container {self.container} not found")
        if status != 200:
            raise TransportError("docker_error", decode(data)[:300])
        info = json.loads(data)
        if not (info.get("State") or {}).get("Running"):
            raise TransportError("container_not_running", f"container {self.container} is not running")

    def _exec(self, command_line: str, stdin: bytes | None, timeout: int) -> CmdResult:
        name = urllib.parse.quote(self.container)
        body = {"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False,
                "Cmd": ["sh", "-c", command_line]}
        if self.user:
            body["User"] = self.user
        status, data = self._request("POST", f"/containers/{name}/exec", body)
        if status != 201:
            raise TransportError("docker_error", decode(data)[:300])
        exec_id = json.loads(data)["Id"]
        status, data = self._request("POST", f"/exec/{exec_id}/start",
                                     {"Detach": False, "Tty": False}, timeout=timeout)
        if status != 200:
            raise TransportError("docker_error", decode(data)[:300])
        out, err = demux(data)
        status, info = self._request("GET", f"/exec/{exec_id}/json")
        code = json.loads(info).get("ExitCode")
        if code is None:
            code = -1
        return CmdResult(command_line, int(code), decode(out), decode(err), 0, out)

    def container_logs(self, lines: int) -> bytes:
        name = urllib.parse.quote(self.container)
        status, data = self._request("GET", f"/containers/{name}/logs?stdout=1&stderr=1&tail={int(lines)}",
                                     timeout=self.timeout)
        if status != 200:
            raise TransportError("docker_error", decode(data)[:300])
        out, err = demux(data)
        return out + err
