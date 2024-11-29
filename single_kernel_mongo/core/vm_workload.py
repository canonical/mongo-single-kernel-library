#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes workload definition."""

import subprocess
from collections.abc import Mapping
from itertools import chain
from logging import getLogger
from pathlib import Path
from shutil import copyfile

from ops import Container
from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    CRON_FILE,
    SNAP,
    VmUser,
)
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.exceptions import WorkloadExecError, WorkloadServiceError
from single_kernel_mongo.lib.charms.operator_libs_linux.v1 import snap

logger = getLogger(__name__)


class VMWorkload(WorkloadBase):
    """Wrapper for performing common operations specific to the Kafka Snap."""

    substrate = "vm"
    container = None
    users = VmUser()

    def __init__(self, container: Container | None) -> None:
        self.snap = SNAP
        self.mongod = snap.SnapCache()[self.snap.name]

    @property
    @override
    def container_can_connect(self) -> bool:
        return True  # Always True on VM

    @property
    @override
    def snap_present(self) -> bool:
        return self.mongod.present

    @override
    def start(self) -> None:
        try:
            self.mongod.start(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))
            raise WorkloadServiceError(str(e)) from e

    @override
    def get_env(self) -> dict[str, str]:
        return {self.env_var: self.mongod.get(self.snap_param)}

    @override
    def update_env(self, parameters: chain[str]):
        content = " ".join(parameters)
        self.mongod.set({self.snap_param: content})

    @override
    def stop(self) -> None:
        try:
            self.mongod.stop(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))
            raise WorkloadServiceError(str(e)) from e

    @override
    def restart(self) -> None:
        try:
            self.mongod.restart(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))
            raise WorkloadServiceError(str(e)) from e

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
    ) -> str:
        try:
            output = subprocess.check_output(
                command,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                shell=isinstance(command, str),
                env=env,
                cwd=working_dir,
            )
            logger.debug(f"{output=}")
            return output
        except subprocess.CalledProcessError as e:
            logger.error(f"cmd failed - cmd={e.cmd}, stdout={e.stdout}, stderr={e.stderr}")
            raise WorkloadExecError(
                e.cmd,
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
    ) -> str:
        command = [
            f"{self.paths.binaries_path}/charmed-mongodb.{self.bin_cmd}",
            bin_keyword,
            *bin_args,
        ]
        return self.exec(command=command, env=environment)

    @override
    @retry(
        wait=wait_fixed(1),
        stop=stop_after_attempt(5),
        retry=retry_if_result(lambda result: result is False),
        retry_error_callback=lambda _: False,
    )
    def active(self) -> bool:
        try:
            return self.mongod.services[self.service]["active"]
        except KeyError:
            return False

    @override
    def install(self) -> bool:
        """Loads the MongoDB snap from LP.

        Returns:
            True if successfully installed. False otherwise.
        """
        try:
            self.mongod.ensure(
                snap.SnapState.Latest,
                channel=self.snap.channel,
                revision=self.snap.revision,
            )
            self.mongod.hold()

            return True
        except snap.SnapError as err:
            logger.error(f"Failed to install {self.snap.name}. Reason: {err}.")
            return False

    @override
    def setup_cron(self, lines: list[str]) -> None:  # pragma: nocover
        CRON_FILE.write_text("\n".join(lines))
