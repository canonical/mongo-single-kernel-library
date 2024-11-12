#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB and Mongos workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongoDBWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongod"
    layer_name = "mongod"
    bin_cmd = "mongosh"
    env_var = "MONGOD_ARGS"

    def __init__(self, container: Container | None) -> None:
        super().__init__(container)
        self.role = ROLES[self.substrate]
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB."""
        environment = self.get_env().get(self.env_var) or self._env
        return Layer(
            {
                "summary": "mongod layer",
                "description": "Pebble config layer for replicated mongod",
                "services": {
                    self.service: {
                        "override": "replace",
                        "summary": "mongod",
                        "command": "/usr/bin/mongod ${MONGOD_ARGS}",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: environment},
                    }
                },
            }
        )
