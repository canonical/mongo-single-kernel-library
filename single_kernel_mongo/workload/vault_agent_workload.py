#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Vault Agent workloads definition."""

from abc import ABC
from pathlib import Path
from typing import ClassVar

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class VaultAgentPaths(MongoPaths):
    """Vault Agent specific paths."""

    @property
    def vault_config(self) -> Path:
        """Vault configuration file path."""
        return Path(f"{self.etc_path}/vault/agent-config.hcl")

    @property
    def role_id(self) -> Path:
        """Vault configuration file path."""
        return Path(f"{self.etc_path}/vault/role_id")

    @property
    def role_secret_id(self) -> Path:
        """Vault configuration file path."""
        return Path(f"{self.etc_path}/vault/role_secret_id")


class VaultAgentWorkload(WorkloadBase, ABC):
    """MongoDB Workload definition."""

    service: ClassVar[str] = "vault-agent"
    layer_name: ClassVar[str] = "vault-agent"
    bin_cmd: ClassVar[str] = "vault"
    env_var: ClassVar[str] = ""
    snap_param: ClassVar[str] = ""

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths: VaultAgentPaths = VaultAgentPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for Vault Agent."""
        return Layer(
            {
                "summary": "Vault Agent layer",
                "description": "Pebble config layer for vault agent",
                "services": {
                    self.service: {
                        "summary": "vault agent",
                        # Pebble errors out if the command exits too fast (1s).
                        "command": "/bin/bash /bin/start-vault-agent.sh",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: self._env},
                    }
                },
            }
        )
