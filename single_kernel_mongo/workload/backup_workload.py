#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""PBM service workloads definition."""

from pathlib import Path
from typing import ClassVar

from ops.model import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase
from single_kernel_mongo.exceptions import WorkloadServiceError


class PBMPaths(MongoPaths):
    """Vault Agent specific paths."""

    @property
    def pbm_agent_config_path(self) -> Path:
        """PBM Agent configuration file path."""
        return Path(f"{self.etc_path}/pbm/pbm-agent.yaml")

    @property
    def pbm_agent_log_file(self) -> Path:
        """PBM Agent log file."""
        return Path(f"{self.pbm_agent_log_dir}/pbm-agent.json")


class PBMWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service: ClassVar[str] = "pbm-agent"
    layer_name: ClassVar[str] = "pbm-agent"
    bin_cmd: ClassVar[str] = "pbm"
    env_var: ClassVar[str] = "PBM_MONGODB_URI"
    snap_param: ClassVar[str] = "pbm-uri"

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths: PBMPaths = PBMPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB Exporter."""
        if self._env == "":
            raise WorkloadServiceError("Impossible to create layer: missing parameter")

        return Layer(
            {
                "summary": "pbm layer",
                "description": "Pebble config layer for pbm",
                "services": {
                    self.service: {
                        "override": "replace",
                        "summary": "pbm",
                        "command": f"/usr/bin/pbm-agent -f {self.paths.pbm_agent_config_path}",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: self._env},
                    }
                },
            }
        )
