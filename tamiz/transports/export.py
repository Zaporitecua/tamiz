"""Export transport: Tamiz never connects; it produces files to download.

For GitOps, configuration management (Ansible, Puppet), Kubernetes ConfigMaps
or air-gapped servers. The "remote" state is what was last exported and
marked as deployed, stored in the database.
"""
from __future__ import annotations

from .base import NotSupported, Transport


class ExportTransport(Transport):
    kind = "export"
    remote = False

    def _exec(self, command_line, stdin, timeout):
        raise NotSupported("run commands")
