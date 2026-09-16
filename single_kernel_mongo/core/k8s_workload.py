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
    command_user = KubernetesUser()

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
        """Starts the workload service.

        Adds the Pebble layer for the service and restarts it.

        Raises:
            WorkloadServiceError: If the underlying Pebble change fails.
        """
        try:
            self.restart()
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e

    @override
    def stop(self) -> None:
        """Stops the workload service.

        Does nothing if the service hasn't been defined in the Pebble plan yet.

        Raises:
            WorkloadServiceError: If the underlying Pebble change fails or the
                connection to the container is lost.
        """
        try:
            # If we haven't defined the service yet, do nothing
            if not self._service_exists:
                return
            self.container.stop(self.service)
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def restart(self) -> None:
        """Restarts the workload service.

        Adds the Pebble layer for the service, combining it with the
        existing plan, and restarts the service.

        Raises:
            WorkloadServiceError: If the underlying Pebble change fails, times
                out, or the connection to the container is lost.
        """
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
        """Creates a directory in the container's filesystem.

        Args:
            path: The path of the directory to create.
            make_parents: Whether to also create any missing parent
                directories.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            self.container.make_dir(path, make_parents=make_parents)
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @property
    def _service_exists(self) -> bool:
        """Checks if the service is defined in the plan.

        Raises:
            ConnectionError: If the connection to the container is lost.
        """
        current_service_config = self.container.get_plan().services
        return self.service in current_service_config.keys()

    @override
    def exists(self, path: Path) -> bool:
        """Returns whether a path exists in the container's filesystem.

        Args:
            path: The path to check.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            return self.container.exists(path)
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def read(self, path: Path) -> list[str]:
        """Reads the contents of a file in the container's filesystem.

        Args:
            path: The path of the file to read.

        Returns:
            The file's content split into lines, or an empty list if the
            file doesn't exist.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            if not self.container.exists(path):
                return []
            with self.container.pull(path) as f:
                return f.read().split("\n")
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def write(self, path: Path, content: str, mode: str = "w") -> None:
        """Writes content to a file in the container's filesystem.

        Creates any missing parent directories and sets ownership to the
        workload's configured user and group.

        Args:
            path: The path of the file to write.
            content: The content to write to the file.
            mode: Unused.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            self.container.push(
                path,
                content,
                make_dirs=True,
                permissions=0o400,
                user=self.users.user,
                group=self.users.group,
            )
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def delete(self, path: Path) -> None:
        """Deletes a path from the container's filesystem.

        Args:
            path: The path to delete.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            self.container.remove_path(path)
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def copy_to_unit(self, src: Path, destination: Path):
        """Copies a file from the container to the charm unit's filesystem.

        Args:
            src: The path of the file inside the container to copy from.
            destination: The path on the unit's filesystem to copy to.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        try:
            license_file = self.container.pull(path=src)
            destination.write_text(license_file.read())
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except ChangeError as e:
            logger.exception(f"Change Error: {e}")
            raise WorkloadServiceError(e.err) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def get_env(self) -> dict[str, str]:
        """Returns the environment variables configured for the service.

        Returns:
            A mapping of environment variable names to their values, as
            defined in the service's Pebble plan.
        """
        try:
            env = (
                self.container.get_plan()
                .to_dict()
                .get("services", {})
                .get(self.service, {})
                .get("environment", {})
            )
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        return env

    @override
    def update_env(self, parameters: chain[str]) -> None:
        """Updates the stored environment string used for the workload.

        Args:
            parameters: The environment parameters to join into a single
                environment string.
        """
        self._env = " ".join(parameters)

    @override
    def exec(
        self,
        command: list[str],  # type: ignore[override]
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
        input: str | None = None,
        user: str | None = None,
        group: str | None = None,
    ) -> str:
        """Executes a command inside the container.

        Args:
            command: The command and its arguments to execute.
            env: Environment variables to set for the command.
            working_dir: The working directory to run the command in.
            input: Input to pass to the command's stdin.
            user: The user to run the command as.
            group: The group to run the command as.

        Returns:
            The combined stdout/stderr output of the command.

        Raises:
            WorkloadExecError: If the command fails, the Pebble client can't
                connect to the container, or the command times out.
        """
        masked_cmd = mask_sensitive_information(command)
        try:
            process = self.container.exec(
                command=command,
                environment=env,
                working_dir=working_dir,
                combine_stderr=True,
                stdin=input,
                user=user,
                group=group,
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
        """Runs a binary command belonging to the workload.

        Args:
            bin_keyword: The subcommand/keyword to pass to the workload binary.
            bin_args: Additional arguments to pass to the command.
            environment: Environment variables to set for the command.
            input: Input to pass to the command's stdin.

        Returns:
            The combined stdout/stderr output of the command.

        Raises:
            WorkloadExecError: If the command fails, the Pebble client can't
                connect to the container, or the command times out.
        """
        bin_args = bin_args or []
        environment = environment or {}
        command = [f"{self.paths.binaries_path}/{self.bin_cmd}", bin_keyword, *bin_args]
        return self.exec(command=command, env=environment or None, input=input)

    @override
    def active(self) -> bool:
        """Checks whether the workload service is currently running.

        Returns:
            True if the container can be reached, the service is defined,
            and it is running. False otherwise.

        Raises:
            WorkloadServiceError: If the connection to the container is lost.
        """
        if not self.container.can_connect():
            return False
        try:
            if self.service not in self.container.get_services():
                return False

            return self.container.get_service(self.service).is_running()
        except ConnectionError as e:
            logger.exception(f"Connection Error: {e}")
            raise WorkloadServiceError(*e.args) from e
        except TimeoutError as e:
            logger.exception(f"Timeout Error: {e}")
            raise WorkloadServiceError(*e.args) from e

    @override
    def setup_cron(self, lines: list[str]) -> None:
        raise NotImplementedError("VM Specific.")
