#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""MongoDB and Mongos workloads definition."""

import re

from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.models import CharmKind
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase


class MongosWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "mongos"
    layer_name = "mongos"
    bin_cmd = "mongosh"
    env_var = "MONGOS_ARGS"
    snap_param = "mongos-args"

    def __init__(self, role: CharmKind, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths = MongoPaths(self.role)

    @property
    @override
    def layer(self) -> Layer:
        """Returns a Pebble configuration layer for Mongos."""
        environment = self.get_env().get(self.env_var) or self._env

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
                    "environment": {self.env_var: environment},
                }
            },
        }
        return Layer(layer_config)  # type: ignore

    @property
    def config_server_db(self) -> str | None:
        """The config server DB on the workload."""
        regex = re.compile(r"--configdb (\S+)")
        env = self.get_env().get(self.env_var, None)
        if not env:
            return None

        match = regex.search(env)
        if match:
            return match.group(1)
        return None
