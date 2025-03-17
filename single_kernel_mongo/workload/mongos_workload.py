#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB and Mongos workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override
from yaml import safe_load

from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongosWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongos"
    layer_name = "mongos"
    bin_cmd = "mongosh"
    env_var = "MONGOS_ARGS"
    snap_param = "mongos-args"

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns a Pebble configuration layer for Mongos."""
        layer_config = {
            "summary": "mongos layer",
            "description": "Pebble config layer for mongos router",
            "services": {
                self.service: {
                    "override": "replace",
                    "summary": "mongos",
                    "command": "/bin/bash /bin/start-mongos.sh",
                    "startup": "enabled",
                    "user": self.users.user,
                    "group": self.users.group,
                    "environment": {self.env_var: self._env},
                }
            },
        }
        return Layer(layer_config)  # type: ignore

    @property
    def config_server_db(self) -> str | None:
        """The config server DB on the workload."""
        data = "\n".join(self.read(self.paths.mongos_config_file))
        current_content = safe_load(data)
        return current_content.get("sharding", {}).get("configDB", None)
