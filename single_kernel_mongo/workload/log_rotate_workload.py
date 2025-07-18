#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Logrotate workload definition."""

import jinja2
from ops import Container
from ops.pebble import Layer
from typing_extensions import override

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.models import CharmSpec, LogRotateConfig
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase
from single_kernel_mongo.exceptions import WorkloadServiceError
from single_kernel_mongo.utils.helpers import get_logrotate_uri


class LogRotateWorkload(WorkloadBase):
    """MongoDB Workload definition."""

    service = "logrotate"
    layer_name = "log_rotate"
    bin_cmd = "logrotate"
    env_var = "LOGROTATE_URI"
    snap_param = "logrotate-uri"

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.paths = MongoPaths(self.role)

    def build_template(self) -> None:
        """Builds and renders the template."""
        data = LogRotateConfig.log_rotate_template.read_text()
        template = jinja2.Template(data)

        rendered_template = template.render(
            logs_directory=self.paths.logs_path,
            mongo_user=self.users.user,
            max_log_size=LogRotateConfig.max_log_size,
            max_rotations=LogRotateConfig.max_rotations_to_keep,
            get_uri=get_logrotate_uri(
                Substrates(self.substrate), service_name=self.service, env_variable=self.env_var
            ),
            shell=self.paths.shell_path,
        )

        self.write(path=LogRotateConfig.rendered_template, content=rendered_template)
        # logrotate file needs to be owned by root
        self.exec(["chown", "root:root", f"{LogRotateConfig.rendered_template}"])
        self.exec(["chmod", "644", f"{LogRotateConfig.rendered_template}"])

    @property
    @override
    def layer(self) -> Layer:
        """Returns the Pebble configuration layer for MongoDB."""
        if self._env == "":
            raise WorkloadServiceError("Impossible to create layer: missing parameter")

        return Layer(
            {
                "summary": "Log rotate layer",
                "description": "Pebble config layer for rotating mongodb logs",
                "services": {
                    self.service: {
                        "summary": "log rotate",
                        # Pebble errors out if the command exits too fast (1s).
                        "command": f"sh -c 'logrotate {LogRotateConfig.rendered_template}; sleep 1'",
                        "startup": "enabled",
                        "override": "replace",
                        "backoff-delay": "1m0s",
                        "backoff-factor": 1,
                        "user": self.users.user,
                        "group": self.users.group,
                        "environment": {self.env_var: self._env},
                    }
                },
            }
        )
