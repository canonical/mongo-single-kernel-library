#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB exporter workloads definition."""

from typing import Generic, TypeVar

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase, WorkloadProtocol

T = TypeVar("T", bound=WorkloadProtocol)


class MongoDBExporterWorkload(WorkloadBase, Generic[T]):
    """MongoDB Workload definition."""

    service = "mongodb_exporter"
    layer_name = "mongodb_exporter"
    bin_cmd = "mongosh"

    def __init__(self, container: Container | None) -> None:
        super().__init__(container)
        self.role = ROLES[self.substrate]
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB Exporter."""
        environment = self.get_env()

        return Layer(
            {
                "summary": "mongodb_exporter layer",
                "description": "Pebble config layer for mongodb_exporter",
                "services": {
                    self.service: {
                        "override": "replace",
                        "summary": "mongodb_exporter",
                        "command": "mongodb_exporter --collector.diagnosticdata --compatible-mode",
                        "startup": "enabled",
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {
                            "MONGODB_URI": environment.get("MONGODB_URI", "")
                        },
                    }
                },
            }
        )
