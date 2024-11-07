#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""PBM service workloads definition."""

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class PBMWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "pbm-agent"
    layer_name = "pbm-agent"
    bin_cmd = "pbm"

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
                        "environment": {
                            "PBM_MONGODB_URI": environment.get("PBM_MONGODB_URI", "")
                        },
                    }
                },
            }
        )
