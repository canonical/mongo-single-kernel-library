#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""PBM service workloads definition."""

from pathlib import Path

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class PBMPaths(MongoPaths):
    """PBM Specific paths."""

    @property
    def pbm_config(self) -> Path:
        """PBM Configuration file path."""
        return Path(f"{self.etc_path}/pbm/pbm_config.yaml")


class PBMWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "pbm-agent"
    layer_name = "pbm-agent"
    bin_cmd = "pbm"
    env_var = "PBM_MONGODB_URI"
    paths: PBMPaths

    def __init__(self, container: Container | None) -> None:
        super().__init__(container)
        self.role = ROLES[self.substrate]
        self.paths = PBMPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB Exporter."""
        environment = self.get_env().get(self.env_var) or self._env

        return Layer(
            {
                "summary": "pbm layer",
                "description": "Pebble config layer for pbm",
                "services": {
                    self.service: {
                        "override": "replace",
                        "summary": "pbm",
                        "command": "/usr/bin/pbm-agent",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: environment},
                    }
                },
            }
        )
