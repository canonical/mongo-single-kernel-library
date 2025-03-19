#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB and Mongos workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongoDBWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongod"
    layer_name = "mongod"
    bin_cmd = "mongosh"
    env_var = "MONGOD_ARGS"
    snap_param = "mongod-args"

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB."""
        return Layer(
            {
                "summary": "mongod layer",
                "description": "Pebble config layer for replicated mongod",
                "services": {
                    self.service: {
                        "override": "replace",
                        "summary": "mongod",
                        "command": "/bin/bash /bin/start-mongod.sh",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: self._env},
                    }
                },
            }
        )
