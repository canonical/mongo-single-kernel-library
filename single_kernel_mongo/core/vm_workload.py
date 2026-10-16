#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""VM workload definition."""

import subprocess
from collections.abc import Mapping
from itertools import chain
from logging import getLogger
from pathlib import Path
from shutil import copyfile

import charmlibs.snap as snap
from ops import Container
from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    CRON_FILE,
    SNAP,
    VmUser,
)
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.exceptions import (
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.helpers import mask_sensitive_information

logger = getLogger(__name__)


class VMWorkload(WorkloadBase):
    """Wrapper for performing common operations specific to the MongoDB Snap."""

    substrate = "vm"
    container: None
    users = VmUser()

    def __init__(self, role: CharmSpec, container: Container | None) -> None:
        super().__init__(role, container)
        self.snap = SNAP

    @property
    @override
    def workload_present(self) -> bool:
        """Check whether the charmed-mongodb snap is installed.

        Returns:
            True if the snap is installed, False otherwise.

        Raises:
            WorkloadServiceError: if snapd could not be reached or returned an
                unexpected error while querying the snap's state.
        """
        try:
            snap.list_one(self.snap.name)
        except snap.NotInstalledError:
            return False
        except snap.Error as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e
        return True

    @override
    def start(self) -> None:
        """Start the MongoDB snap service and enable it.

        Raises:
            WorkloadServiceError: if the snap has no such service, or the service fails
                to start.
        """
        try:
            snap.start(self.snap.name, self.service, enable=True)
        except (snap.APIError, snap.Error) as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e

    @override
    def get_env(self) -> dict[str, str]:
        """Get the environment variables for the workload.

        Returns:
            A mapping of the environment variable name to its current value, read
            from the snap's configuration parameter. Empty string if unset.

        Raises:
            WorkloadServiceError: if snapd could not be reached or returned an
                unexpected error while reading the configuration.
        """
        try:
            value = snap.get_one(self.snap.name, self.snap_param)
        except snap.OptionNotFoundError:
            value = ""
        except (snap.APIError, snap.Error) as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e
        return {self.env_var: value}

    @override
    def update_env(self, parameters: chain[str]):
        """Update the environment variables for the workload.

        Args:
            parameters (chain[str]): the parameters to join and set as the snap's
                environment variable content. If empty, nothing is set.

        Raises:
            WorkloadServiceError: if the snap is not installed or the configuration
                change fails.
        """
        content = " ".join(parameters)
        if content == "":
            return
        try:
            snap.set(self.snap.name, {self.snap_param: content})
        except (snap.APIError, snap.Error) as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e

    @override
    def stop(self) -> None:
        """Stop the MongoDB snap service and disable it.

        Raises:
            WorkloadServiceError: if snapd could not be reached, the snap has no such
                service, or the service fails to stop.
        """
        try:
            snap.stop(self.snap.name, self.service, disable=True)
        except (snap.APIError, snap.Error) as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e

    @override
    def restart(self) -> None:
        """Restart the MongoDB snap service.

        Raises:
            WorkloadServiceError: if snapd could not be reached, the snap has no such
                service, or the service fails to restart.
        """
        try:
            snap.restart(self.snap.name, self.service)
        except (snap.APIError, snap.Error) as e:
            logger.exception("%s", e)
            raise WorkloadServiceError(f"{e}") from e

    @override
    def exists(self, path: Path) -> bool:
        return path.is_file()

    @override
    def mkdir(self, path: Path, make_parents: bool = False) -> None:
        path.mkdir(exist_ok=True, parents=make_parents)

    @override
    def read(self, path: Path) -> list[str]:
        if not path.is_file():
            return []
        return path.read_text().splitlines()

    @override
    def write(self, path: Path, content: str, mode: str = "w") -> None:  # pragma: nocover
        """Write content to a file on the workload's filesystem.

        Creates any missing parent directories, writes the content, then sets
        restrictive permissions (0o400 for the keyfile, 0o440 for everything else)
        and changes ownership to the workload's user and group.

        Args:
            path (Path): the full filepath to write to.
            content (str): the content to write.
            mode (str): the write mode. Usually "w" for write, or "a" for append.
                Default "w".
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode) as f:
            f.write(content)

        if path == self.paths.keyfile:
            path.chmod(0o400)
        else:
            path.chmod(0o440)

        self.exec(["chown", "-R", f"{self.users.user}:{self.users.group}", f"{path}"])

    @override
    def delete(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            return
        path.unlink()

    @override
    def copy_to_unit(self, src: Path, destination: Path) -> None:  # pragma: nocover
        copyfile(src, destination)

    @override
    def exec(
        self,
        command: list[str] | str,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        input: str | None = None,
    ) -> str:
        """Run a command on the local machine via a subprocess.

        Args:
            command (list[str] | str): the command to run, as a list of args or a
                single string. A string is run through the shell.
            env (Mapping[str, str] | None): environment variables to set for the
                command.
            working_dir (str | None): the working directory to run the command in.
            input (str | None): text to pass to the command's stdin.
            user (str | None): the user to run the command as.
            group (str | None): the group to run the command as.

        Returns:
            The command's stdout output.

        Raises:
            WorkloadExecError: if the command exits with a non-zero return code.
        """
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                shell=isinstance(command, str),
                env=env,
                cwd=working_dir,
                input=input,
            )
            logger.debug("output=%s", output)
            return output
        except subprocess.CalledProcessError as e:
            masked_cmd = mask_sensitive_information(command)
            logger.error(
                "cmd failed - cmd=%s, stdout=%s, stderr=%s", masked_cmd, e.stdout, e.stderr
            )
            raise WorkloadExecError(
                masked_cmd,
                e.returncode,
                e.stdout,
                e.stderr,
            )

    @override
    def run_bin_command(
        self,
        bin_keyword: str,
        bin_args: list[str] = [],
        environment: dict[str, str] = {},
        input: str | None = None,
    ) -> str:
        """Run the charmed-mongodb shell binary with the desired args.

        Args:
            bin_keyword (str): the shell script command to run, e.g `configs`, `topics`.
            bin_args (list[str]): the shell command args.
            environment (dict[str, str]): a dictionary of environment variables.
            input (str | None): text to pass to the command's stdin.

        Returns:
            The command's stdout output.

        Raises:
            WorkloadExecError: if the command exits with a non-zero return code.
        """
        command = [
            f"{self.paths.binaries_path}/charmed-mongodb.{self.bin_cmd}",
            bin_keyword,
            *bin_args,
        ]
        return self.exec(command=command, env=environment, input=input)

    @override
    @retry(
        wait=wait_fixed(1),
        stop=stop_after_attempt(5),
        retry=retry_if_result(lambda result: result is False),
        retry_error_callback=lambda _: False,
    )
    def active(self) -> bool:
        """Check whether the snap's service is currently active.

        Query systemd to determine whether the snap's service is active.
        """
        unit = f"snap.{self.snap.name}.{self.service}.service"
        try:
            output = self.exec(["systemctl", "is-active", unit])
        except WorkloadExecError:
            return False
        return output.strip() == "active"

    @override
    @retry(
        stop=stop_after_attempt(20),
        wait=wait_fixed(1),
        reraise=True,
    )
    def install(self) -> None:
        """Install the charmed-mongodb snap from the snap store."""
        try:
            snap.ensure_installed(self.snap.name, revision=self.snap.revision)
            snap.hold(self.snap.name)
        except (snap.APIError, snap.Error) as err:
            logger.error("Failed to install %s. Reason: %s.", self.snap.name, err)
            raise WorkloadNotReadyError(f"Failed to install {self.snap.name}")

    @override
    def setup_cron(self, lines: list[str]) -> None:  # pragma: nocover
        CRON_FILE.write_text("\n".join(lines))
