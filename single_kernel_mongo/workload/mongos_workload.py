#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB and Mongos workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongosWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongos"
    layer_name = "mongos"
    bin_cmd = "mongosh"
    env_var = "MONGOS_ARGS"

    def __init__(self, container: Container | None) -> None:
        super().__init__(container)
        self.role = ROLES[self.substrate]
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns a Pebble configuration layer for Mongos."""
        environment = self.get_env()

        layer_config = {
            "summary": "mongos layer",
            "description": "Pebble config layer for mongos router",
            "services": {
                self.service: {
                    "override": "replace",
                    "summary": "mongos",
                    "command": "/usr/bin/mongos ${MONGOS_ARGS}",
                    "startup": "enabled",
                    "user": self.users.user,
                    "group": self.users.group,
                    "environment": {self.env_var: environment.get(self.env_var, "")},
                }
            },
        }
        return Layer(layer_config)  # type: ignore
