#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes workload definition."""

from logging import getLogger
from pathlib import Path

from ops import Container
from ops.pebble import ExecError
from typing_extensions import override

from single_kernel_mongo.config.literals import KubernetesUser, WorkloadUser
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase

logger = getLogger(__name__)


class KubernetesWorkload(WorkloadBase):
    """Wrapper for performing common operations specific to the Kafka container."""

    paths: MongoPaths
    service: str
    layer_name: str
    users: WorkloadUser = KubernetesUser()
    substrate: str = "k8s"
    container: Container  # We always have a container in a Kubernetes Workload

    def __init__(self, container: Container | None) -> None:
        if not container:
            raise AttributeError("Container is required.")

        self.container = container

    @property
    @override
    def container_can_connect(self) -> bool:
        return self.container.can_connect()

    @override
    def start(self) -> None:
        self.container.add_layer(self.layer_name, self.layer, combine=True)
        self.container.restart(self.service)

    @override
    def stop(self) -> None:
        self.container.stop(self.service)

    @override
    def restart(self) -> None:
        self.start()

    @override
    def read(self, path: Path) -> list[str]:
        if not self.container.exists(path):
            return []
        with self.container.pull(path) as f:
            return f.read().split("\n")

    @override
    def write(self, content: str, path: Path, mode: str = "w") -> None:
        self.container.push(
            path,
            content,
            make_dirs=True,
            permissions=0o400,
            user=self.users.user,
            group=self.users.group,
        )

    @override
    def exec(
        self,
        command: list[str],  # type: ignore[override]
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> str:
        try:
            process = self.container.exec(
                command=command,
                environment=env,
                working_dir=working_dir,
                combine_stderr=True,
            )
            output, _ = process.wait_output()
            return output
        except ExecError as e:
            logger.debug(e)
            raise e

    @override
    def run_bin_command(
        self, bin_keyword: str, bin_args: list[str], environment: dict[str, str] = {}
    ) -> str:
        command = [f"{self.paths.binaries_path}/{self.bin_cmd}", bin_keyword, *bin_args]
        return self.exec(command=command, env=environment or None)

    @override
    def active(self) -> bool:
        if not self.container.can_connect():
            return False

        if self.service not in self.container.get_services():
            return False

        return self.container.get_service(self.service).is_running()

    @override
    def setup_cron(self, lines: list[str]) -> None:
        raise NotImplementedError("VM Specific.")
