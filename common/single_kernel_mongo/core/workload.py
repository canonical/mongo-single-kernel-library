#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract workload definition for Mongo charms."""

import secrets
import string
from abc import ABC, abstractmethod
from itertools import chain
from pathlib import Path
from typing import ClassVar

from ops import Container
from ops.pebble import Layer

from single_kernel_mongo.config.literals import WorkloadUser
from single_kernel_mongo.config.models import CharmSpec


class MongoPaths:
    """Object to store the common paths for a mongodb instance."""

    def __init__(self, role: CharmSpec):
        self.conf_path = role.paths["CONF"]
        self.data_path = role.paths["DATA"]
        self.binaries_path = role.paths["BIN"]
        self.var_path: str = role.paths["VAR"]
        self.etc_path: str = role.paths["ETC"]
        self.logs_path = role.paths["LOGS"]
        self.shell_path = role.paths["SHELL"]
        self.licenses_path = role.paths["LICENSES"]

    def __eq__(self, other: object) -> bool:  # noqa: D105
        if not isinstance(other, MongoPaths):
            return NotImplemented  # pragma: nocover
        return self.conf_path == other.conf_path

    @property
    def common_path(self) -> Path:
        """The common path."""
        return Path(self.var_path).parent

    @property
    def config_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.conf_path}/mongod.conf")

    @property
    def mongos_config_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.conf_path}/mongos.conf")

    @property
    def socket_path(self) -> Path:
        """The socket path for internal connectivity."""
        return Path(f"{self.var_path}/mongodb-27018.sock")

    @property
    def keyfile(self) -> Path:
        """The keyfile of mongod instance."""
        return Path(f"{self.conf_path}/keyFile")

    @property
    def log_file(self) -> Path:
        """The main mongodb log file."""
        return Path(f"{self.logs_path}/mongodb.log")

    @property
    def audit_file(self) -> Path:
        """The main mongod config file."""
        return Path(f"{self.logs_path}/audit.log")

    @property
    def ext_pem_file(self) -> Path:
        """External connectivity PEM file."""
        return Path(f"{self.conf_path}/external-cert.pem")

    @property
    def ext_ca_file(self) -> Path:
        """External connectivity CA file."""
        return Path(f"{self.conf_path}/external-ca.crt")

    @property
    def int_pem_file(self) -> Path:
        """Internal connectivity PEM file."""
        return Path(f"{self.conf_path}/internal-cert.pem")

    @property
    def int_ca_file(self) -> Path:
        """Internal connectivity CA file."""
        return Path(f"{self.conf_path}/internal-ca.crt")

    @property
    def tls_files(self) -> set[Path]:
        """Set of all TLS files."""
        return {
            self.ext_pem_file,
            self.ext_ca_file,
            self.int_pem_file,
            self.int_ca_file,
        }

    @property
    def ldap_path(self) -> Path:
        """The LDAP conf path."""
        return Path(f"{self.etc_path}/ldap")

    @property
    def ldap_conf_path(self) -> Path:
        """The LDAP conf path."""
        return Path(f"{self.ldap_path}/ldap.conf")

    @property
    def ldap_certificates_dir(self) -> Path:
        """The LDAP conf path."""
        return Path(f"{self.ldap_path}/certs")

    @property
    def ldap_certificates_file(self) -> Path:
        """The LDAP certificates file path."""
        return Path(f"{self.ldap_certificates_dir}/ldap.crt")


class WorkloadBase(ABC):  # pragma: nocover
    """The protocol for workloads.

    A workload represents a service. This is a bit more generic than the usual spec,
    because we are running multiple services side by side and each one requires some configuration.

    This protocol provides the interface to define all methods used by a
    service and the possible configurations.
    """

    role: CharmSpec
    substrate: ClassVar[str]
    paths: MongoPaths
    service: ClassVar[str]
    layer_name: ClassVar[str]
    container: Container | None
    users: ClassVar[WorkloadUser]
    bin_cmd: ClassVar[str]
    env_var: ClassVar[str]
    snap_param: ClassVar[str]
    _env: str = ""

    def __init__(self, role: CharmSpec, container: Container | None):
        self.container = container
        self.role = role

    @abstractmethod
    def install(self) -> None:
        """Installs the workload snap or raises an error.

        VM-only: on k8s, just returns None.
        """

    @property
    @abstractmethod
    def workload_present(self) -> bool:
        """Flag to check if workload is present and installed."""
        ...

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
    def mkdir(self, path: Path, make_parents: bool = False) -> None:
        """Creates a directory on the filesystem."""
        ...

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """Checks if the given path exists or not."""
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
    def write(self, path: Path, content: str, mode: str = "w") -> None:
        """Writes content to a workload file.

        Args:
            content: string of content to write
            path: the full filepath to write to
            mode: the write mode. Usually "w" for write, or "a" for append. Default "w"
        """
        ...

    @abstractmethod
    def delete(self, path: Path) -> None:
        """Deletes the file from the unit.

        Args:
            path: the full filepath of the file to delete.
        """
        ...

    @abstractmethod
    def copy_to_unit(self, src: Path, destination: Path) -> None:
        """Copy a file from the workload to the unit running the charm.

        In case of VM, copies from the filesystem to itself.
        In case of Substrate, pulls the file and writes it locally.

        Args:
            src: The source path on the workload.
            destination: The destination path on the local filesystem.
        """
        ...

    @abstractmethod
    def exec(
        self,
        command: list[str] | str,
        env: dict[str, str] | None = None,
        working_dir: str | None = None,
        input: str | None = None,
    ) -> str:
        """Runs a command on the workload substrate."""
        ...

    @abstractmethod
    def run_bin_command(
        self,
        bin_keyword: str,
        bin_args: list[str] = [],
        environment: dict[str, str] = {},
        input: str | None = None,
    ) -> str:
        """Runs service bin command with desired args.

        Args:
            bin_keyword: the kafka shell script to run
                e.g `configs`, `topics` etc
            bin_args: the shell command args
            environment: A dictionary of environment variables

        Returns:
            String of service bin command output
        """
        ...

    @abstractmethod
    def active(self) -> bool:
        """Checks that the workload is active."""
        ...

    @abstractmethod
    def get_env(self) -> dict[str, str]:
        """Returns the environment as defined in the substrate backend."""
        ...

    @abstractmethod
    def update_env(self, parameters: chain[str]):
        """Updates the environment with the new values.

        While the name may seem misleading, this interface works for both substrates.
        In the case of VM, it will set the snap config variable, while it the
        case of k8s, it will use the Layer environment mechanism.
        """
        ...

    def get_version(self) -> str:
        """Get the workload version.

        Returns:
            String of mongo version
        """
        try:
            version = Path("workload_version").read_text().strip()
        except:  # noqa: E722
            version = ""
        return version

    def get_internal_revision(self) -> str:
        """Get the internal revision.

        Note: This should be removed soon because we're moving away from `charm
        version` + `internal revision` to `charm_version+git hash`.

        Returns:
            String of charm internal revision
        """
        try:
            version = Path("charm_version").read_text().strip()
        except:  # noqa: E722
            version = ""
        return version

    def get_charm_revision(self) -> str:
        """Get the charm revision.

        Returns:
            String of charm revision
        """
        try:
            version = Path("charm_version").read_text().strip()
        except:  # noqa: E722
            version = ""
        return version

    @property
    @abstractmethod
    def layer(self) -> Layer:
        """Gets the Pebble Layer definition for the current workload."""
        ...

    @abstractmethod
    def setup_cron(self, lines: list[str]) -> None:
        """[VM Specific] Setup a cron."""
        ...

    @staticmethod
    def generate_password() -> str:
        """Creates randomized string for use as app passwords.

        Returns:
            String of 32 randomized letter+digit characters
        """
        return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(32)])

    @staticmethod
    def generate_keyfile() -> str:
        """Key file used for authentication between replica set peers.

        Returns:
           A maximum allowed random string.
        """
        choices = string.ascii_letters + string.digits
        return "".join([secrets.choice(choices) for _ in range(1024)])
