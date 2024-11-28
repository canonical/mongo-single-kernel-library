#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB exporter workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongoDBExporterWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongodb-exporter"
    layer_name = "mongodb_exporter"
    bin_cmd = "mongosh"
    env_var = "MONGODB_URI"
    snap_param = "monitor-uri"

    def __init__(self, container: Container | None) -> None:
        super().__init__(container)
        self.role = ROLES[self.substrate]
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB Exporter."""
        environment = self.get_env().get(self.env_var) or self._env

        return Layer(
            {
                "summary": "mongodb_exporter layer",
                "description": "Pebble config layer for mongodb_exporter",
                "services": {
                    self.layer_name: {
                        "override": "replace",
                        "summary": "mongodb_exporter",
                        "command": "mongodb_exporter --collector.diagnosticdata --compatible-mode",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: environment},
                    }
                },
            }
        )
