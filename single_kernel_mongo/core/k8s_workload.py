#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes workload definition."""

from itertools import chain
from logging import getLogger
from pathlib import Path

from ops import Container
from ops.pebble import APIError, ChangeError, ConnectionError, ExecError, TimeoutError
from typing_extensions import override

from single_kernel_mongo.config.literals import KubernetesUser
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.exceptions import WorkloadExecError, WorkloadServiceError
from single_kernel_mongo.utils.helpers import mask_sensitive_information

logger = getLogger(__name__)


class KubernetesWorkload(WorkloadBase):
    """Wrapper for performing common operations specific to the Mongo container."""

    substrate = "k8s"
    container: Container  # We always have a container in a Kubernetes Workload
    users = KubernetesUser()

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        if not container:
            raise AttributeError("Container is required.")

        super().__init__(role, container)

    @property
    @override
    def workload_present(self) -> bool:
        return self.container.can_connect()

    @override
    def install(self, revision: str | None = None, retry_and_raise: bool = True) -> bool:
        return True

    @override
    def start(self) -> None:
        try:
            self.restart()
        except ChangeError as e:
            logger.exception(str(e))
            raise WorkloadServiceError(e.err) from e

    @override
    def stop(self) -> None:
        # If we haven't defined the service yet, do nothing
        if not self.service_exists:
            return
        try:
            self.container.stop(self.service)
        except ChangeError as e:
            logger.exception(str(e))
            raise WorkloadServiceError(e.err) from e

    @override
    def restart(self) -> None:
        try:
            self.container.add_layer(self.layer_name, self.layer, combine=True)
            self.container.restart(self.service)
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def mkdir(self, path: Path, make_parents: bool = False) -> None:
        self.container.make_dir(path, make_parents=make_parents)

    @property
    def service_exists(self) -> bool:
        """Checks if the service is defined in the plan."""
        current_service_config = self.container.get_plan().services
        return self.service in current_service_config.keys()

    @override
    def exists(self, path: Path) -> bool:
        return self.container.exists(path)

    @override
    def read(self, path: Path) -> list[str]:
        if not self.container.exists(path):
            return []
        with self.container.pull(path) as f:
            return f.read().split("\n")

    @override
    def write(self, path: Path, content: str, mode: str = "w") -> None:
        self.container.push(
            path,
            content,
            make_dirs=True,
            permissions=0o400,
            user=self.users.user,
            group=self.users.group,
        )

    @override
    def delete(self, path: Path) -> None:
        self.container.remove_path(path)

    @override
    def copy_to_unit(self, src: Path, destination: Path):
        license_file = self.container.pull(path=src)
        destination.write_text(license_file.read())

    @override
    def get_env(self) -> dict[str, str]:
        return (
            self.container.get_plan()
            .to_dict()
            .get("services", {})
            .get(self.service, {})
            .get("environment", {})
        )

    @override
    def update_env(self, parameters: chain[str]) -> None:
        self._env = " ".join(parameters)

    @override
    def exec(
        self,
        command: list[str],  # type: ignore[override]
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
        input: str | None = None,
    ) -> str:
        masked_cmd = mask_sensitive_information(command)
        try:
            process = self.container.exec(
                command=command,
                environment=env,
                working_dir=working_dir,
                combine_stderr=True,
                stdin=input,
            )
            output, _ = process.wait_output()
            return output
        except ExecError as e:
            logger.error(f"cmd failed - cmd={masked_cmd}, stdout={e.stdout}, stderr={e.stderr}")
            raise WorkloadExecError(
                masked_cmd,
                e.exit_code,
                e.stdout,
                e.stderr,
            ) from e
        except APIError as e:
            logger.error(f"cmd failed - cmd={masked_cmd}, {e.status}: {e.message}")
            raise WorkloadExecError(
                masked_cmd,
                e.code,
                f"{e.status}: {e.message}",
            ) from e
        except ConnectionError as e:
            logger.debug(f"cmd failed - cmd={masked_cmd}, Pebble client can't connect to socket.")
            raise WorkloadExecError(
                masked_cmd, -1, "Pebble client can't connect to the socket."
            ) from e
        except TimeoutError as e:
            logger.debug(f"cmd failed - cmd={masked_cmd}, Pebble client polling timeout.")
            raise WorkloadExecError(masked_cmd, -1, "Pebble client polling timeout.") from e

    @override
    def run_bin_command(
        self,
        bin_keyword: str,
        bin_args: list[str] | None = None,
        environment: dict[str, str] | None = None,
        input: str | None = None,
    ) -> str:
        bin_args = bin_args or []
        environment = environment or {}
        command = [f"{self.paths.binaries_path}/{self.bin_cmd}", bin_keyword, *bin_args]
        return self.exec(command=command, env=environment or None, input=input)

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
