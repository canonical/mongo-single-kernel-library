#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract workload definition for Mongo charms."""
import secrets
import string
from abc import ABC, abstractmethod
from pathlib import Path

from ops.pebble import Layer

from single_kernel_mongo.config.roles import Role


class MongoPaths:
    """Object to store the common paths for a mongodb instance."""

    def __init__(self, role: Role):
        self.conf_path = role.paths["CONF"]
        self.data_path = role.paths["DATA"]
        self.binaries_path = role.paths["BIN"]
        self.logs_path = role.paths["LOGS"]
        self.shell_path = role.paths["SHELL"]

    @property
    def config_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.conf_path}/mongod.conf")

    @property
    def keyfile(self) -> Path:
        """The keyfile of mongod instance."""
        return Path(f"{self.conf_path}/keyFile")

    @property
    def log_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.logs_path}/mongodb.log")

    @property
    def audit_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.conf_path}/audit.log")

    @property
    def ext_pem_file(self) -> Path:
        """External connectivity PEM file."""
        return Path(f"{self.conf_path}/external-cert.pem")

    @property
    def ext_ca_file(self) -> Path:
        """External connectivity CA file."""
        return Path(f"{self.conf_path}/external-ca.pem")

    @property
    def int_pem_file(self) -> Path:
        """Internal connectivity PEM file."""
        return Path(f"{self.conf_path}/internal-cert.pem")

    @property
    def int_ca_file(self) -> Path:
        """Internal connectivity CA file."""
        return Path(f"{self.conf_path}/internal-ca.pem")

    def tls_files(self) -> tuple[Path, Path, Path, Path]:
        """Tuple of all TLS files."""
        return (
            self.ext_pem_file,
            self.ext_ca_file,
            self.int_pem_file,
            self.int_ca_file,
        )


class WorkloadBase(ABC):
    """Base interface for common workload operations."""

    def __init__(self, paths: MongoPaths):
        self.paths = paths

    @abstractmethod
    def start(self) -> None:
        """Starts the workload service."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stops the workload service."""
        ...

    @abstractmethod
    def restart(self) -> None:
        """Restarts the workload service."""
        ...

    @abstractmethod
    def read(self, path: Path) -> list[str]:
        """Reads a file from the workload.

        Args:
            path: the full filepath to read from

        Returns:
            List of string lines from the specified path
        """
        ...

    @abstractmethod
    def write(self, content: str, path: Path, mode: str = "w") -> None:
        """Writes content to a workload file.

        Args:
            content: string of content to write
            path: the full filepath to write to
            mode: the write mode. Usually "w" for write, or "a" for append. Default "w"
        """
        ...

    @abstractmethod
    def exec(
        self,
        command: list[str] | str,
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
    ) -> str:
        """Runs a command on the workload substrate."""
        ...

    @abstractmethod
    def active(self) -> bool:
        """Checks that the workload is active."""

    @abstractmethod
    def run_bin_command(
        self, bin_keyword: str, bin_args: list[str], opts: list[str] = []
    ) -> str:
        """Runs mongod bin command with desired args.

        Args:
            bin_keyword: the mongod shell script to run
                e.g `configs`, `topics` etc
            bin_args: the shell command args
            opts: any additional opts args strings

        Returns:
            String of mongod bin command output
        """
        ...

    def get_version(self) -> str:
        """Get the workload version.

        Returns:
            String of mongo version
        """
        if not self.active:  # type: ignore[truthy-function]
            return ""

        try:
            version = Path("workload_version").read_text().strip()
        except:  # noqa: E722
            version = ""
        return version

    @property
    @abstractmethod
    def layer(self) -> Layer:
        """Gets the Pebble Layer definition for the current workload."""
        ...

    @property
    @abstractmethod
    def container_can_connect(self) -> bool:
        """Flag to check if workload container can connect."""
        ...

    @staticmethod
    def generate_password() -> str:
        """Creates randomized string for use as app passwords.

        Returns:
            String of 32 randomized letter+digit characters
        """
        return "".join(
            [secrets.choice(string.ascii_letters + string.digits) for _ in range(32)]
        )

    @staticmethod
    def generate_keyfile() -> str:
        """Key file used for authentication between replica set peers.

        Returns:
           A maximum allowed random string.
        """
        choices = string.ascii_letters + string.digits
        return "".join([secrets.choice(choices) for _ in range(1024)])
