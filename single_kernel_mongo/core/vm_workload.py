#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Kubernetes workload definition."""

import os
import subprocess
from collections.abc import Mapping
from logging import getLogger
from pathlib import Path

from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import Snap
from single_kernel_mongo.core.workload import MongoPaths, WorkloadBase
from single_kernel_mongo.lib.charms.operator_libs_linux.v1 import snap

logger = getLogger(__name__)


class VMWorkload(WorkloadBase):
    """Wrapper for performing common operations specific to the Kafka Snap."""

    paths: MongoPaths
    service: str

    def __init__(self) -> None:
        self.snap = Snap()
        self.mongod = snap.SnapCache()[self.snap.package.name]

    @property
    @override
    def container_can_connect(self) -> bool:
        return True  # Always True on VM

    @override
    def start(self) -> None:
        try:
            self.mongod.start(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def stop(self) -> None:
        try:
            self.mongod.stop(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def restart(self) -> None:
        try:
            self.mongod.restart(services=[self.service])
        except snap.SnapError as e:
            logger.exception(str(e))

    @override
    def read(self, path: Path) -> list[str]:
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return f.read().split("\n")

    @override
    def write(self, content: str, path: Path, mode: str = "w") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, mode) as f:
            f.write(content)

        if path == self.paths.keyfile:
            self.exec(["chmod", "0o400", f"{path}"])
        else:
            self.exec(["chmod", "0o440", f"{path}"])

            self.exec(["chown", "-R", f"{self.snap.user}:{self.snap.group}", f"{path}"])

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
            logger.error(
                f"cmd failed - cmd={e.cmd}, stdout={e.stdout}, stderr={e.stderr}"
            )
            raise e

    @override
    @retry(
        wait=wait_fixed(1),
        stop=stop_after_attempt(5),
        retry=retry_if_result(lambda result: result is False),
        retry_error_callback=lambda _: False,
    )
    def active(self) -> bool:
        try:
            return bool(self.mongod.services[self.service]["active"])
        except KeyError:
            return False

    def install(self) -> bool:
        """Loads the MongoDB snap from LP.

        Returns:
            True if successfully installed. False otherwise.
        """
        try:
            self.mongod.ensure(
                snap.SnapState.Latest,
                channel=self.snap.package.track,
                revision=self.snap.package.revision,
            )
            self.mongod.hold()

            return True
        except snap.SnapError as err:
            logger.error(f"Failed to install {self.snap.package.name}. Reason: {err}.")
            return False