#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling Mongo configuration."""

import logging
import time
from abc import ABC, abstractmethod
from itertools import chain

from ops import Container
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    LOCALHOST,
    PBM_RESTART_DELAY,
    CharmKind,
    MongoPorts,
    Substrates,
)
from single_kernel_mongo.config.models import AuditLogConfig, CharmSpec, LogRotateConfig
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.exceptions import WorkloadServiceError
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongodb_users import BackupUser, MonitorUser
from single_kernel_mongo.workload import (
    get_logrotate_workload_for_substrate,
    get_mongodb_exporter_workload_for_substrate,
    get_pbm_workload_for_substrate,
)
from single_kernel_mongo.workload.log_rotate_workload import LogRotateWorkload

logger = logging.getLogger(__name__)


class CommonConfigManager(ABC):
    """A generic config manager for a workload."""

    config: MongoConfigModel
    workload: WorkloadBase
    state: CharmState

    def set_environment(self):
        """Write all parameters in the environment variable."""
        if self.workload.env_var != "":
            parameters = chain.from_iterable(self.build_parameters())
            self.workload.update_env(parameters)

    def get_environment(self) -> str:
        """Gets the environment for the defined service."""
        env = self.workload.get_env()
        return env.get(self.workload.env_var, "")

    @abstractmethod
    def build_parameters(self) -> list[list[str]]:  # pragma: nocover
        """Builds the parameters list."""
        ...


class BackupConfigManager(CommonConfigManager):
    """Config manager for PBM."""

    def __init__(
        self,
        substrate: Substrates,
        role: CharmSpec,
        config: MongoConfigModel,
        state: CharmState,
        container: Container | None,
    ):
        self.config = config
        self.workload = get_pbm_workload_for_substrate(substrate)(role=role, container=container)
        self.state = state

    @override
    def build_parameters(self) -> list[list[str]]:
        return [
            [
                self.state.backup_config.uri,
            ]
        ]

    def configure_and_restart(self, force: bool = False):
        """Sets up PBM with right configuration and restarts it."""
        if not self.workload.workload_present:
            logger.info("Workload is not present.")
            return
        if not self.state.db_initialised:
            logger.info("DB is not initialised.")
            return

        if self.state.is_role(MongoDBRoles.SHARD) and not self.state.is_shard_added_to_cluster():
            logger.info("Not starting PBM yet. Shard not added to config-server")
            return

        if not self.state.get_user_password(BackupUser):
            logger.info("No password found.")
            return

        if (
            not self.workload.active()
            or self.get_environment() != self.state.backup_config.uri
            or force
        ):
            logger.info("Restarting the PBM agent.")
            try:
                self.workload.stop()
                self.set_environment()
                # Avoid restart errors on PBM.
                time.sleep(PBM_RESTART_DELAY)
                self.workload.start()
            except WorkloadServiceError as e:
                logger.error(f"Failed to restart {self.workload.service}: {e}")
                raise


class LogRotateConfigManager(CommonConfigManager):
    """Config manager for logrotate."""

    def __init__(
        self,
        role: CharmSpec,
        substrate: Substrates,
        config: MongoConfigModel,
        state: CharmState,
        container: Container | None,
    ):
        self.config = config
        self.workload: LogRotateWorkload = get_logrotate_workload_for_substrate(substrate)(
            role=role, container=container
        )
        self.state = state
        self.substrate = substrate

    @override
    def build_parameters(self) -> list[list[str]]:
        return [[]]

    def configure_and_restart(self) -> None:
        """Setup logrotate and cron."""
        self.workload.build_template()
        if self.substrate == Substrates.VM:
            self.workload.setup_cron(
                [
                    f"* 1-23 * * * root logrotate {LogRotateConfig.rendered_template}\n",
                    f"1-59 0 * * * root logrotate {LogRotateConfig.rendered_template}\n",
                ]
            )
        else:
            self.workload.start()


class MongoDBExporterConfigManager(CommonConfigManager):
    """Config manager for mongodb-exporter."""

    def __init__(
        self,
        role: CharmSpec,
        substrate: Substrates,
        config: MongoConfigModel,
        state: CharmState,
        container: Container | None,
    ):
        self.config = config
        self.workload = get_mongodb_exporter_workload_for_substrate(substrate)(
            role=role, container=container
        )
        self.state = state

    @override
    def build_parameters(self) -> list[list[str]]:
        return [[self.state.monitor_config.uri]]

    def configure_and_restart(self):
        """Exposes the endpoint to mongodb_exporter."""
        if not self.state.db_initialised:
            return

        if not self.state.get_user_password(MonitorUser):
            return

        if not self.workload.active() or self.get_environment() != self.state.monitor_config.uri:
            try:
                self.set_environment()
                self.workload.restart()
            except WorkloadServiceError as e:
                logger.error(f"Failed to restart {self.workload.service}: {e}")
                raise


class MongoConfigManager(CommonConfigManager, ABC):
    """The common configuration manager for both MongoDB and Mongos."""

    auth: bool

    @override
    def build_parameters(self) -> list[list[str]]:
        return [
            self.binding_ips,
            self.port_parameter,
            self.auth_parameter,
            self.tls_parameters,
            self.log_options,
            self.audit_options,
        ]

    @property
    @abstractmethod
    def port_parameter(self) -> list[str]:
        """The port parameter."""
        ...

    @property
    def binding_ips(self) -> list[str]:
        """The binding IP parameters.

        For VM Mongos we bind to the socked (if non-external), this gives us
        one less network hop when communicating with the client.
        """
        if (
            self.state.charm_role.name == CharmKind.MONGOS
            and self.state.substrate == Substrates.VM
            and not self.state.app_peer_data.external_connectivity
        ):
            return [
                f"--bind_ip {self.workload.paths.socket_path}",
                "--filePermissions 0766",
            ]
        return ["--bind_ip_all"]

    @property
    def log_options(self) -> list[str]:
        """The arguments for the logging option."""
        return [
            "--setParameter processUmask=037",  # Required for log files permissions
            "--logRotate reopen",
            "--logappend",
            f"--logpath={self.workload.paths.log_file}",
        ]

    @property
    def audit_options(self) -> list[str]:
        """The argument for the audit log options."""
        return [
            f"--auditDestination={AuditLogConfig.destination}",
            f"--auditFormat={AuditLogConfig.format}",
            f"--auditPath={self.workload.paths.audit_file}",
        ]

    @property
    def auth_parameter(self) -> list[str]:
        """The auth mode."""
        cmd = ["--auth"] if self.auth else []
        if self.state.tls.internal_enabled and self.state.tls.external_enabled:
            return cmd + [
                "--clusterAuthMode=x509",
                "--tlsAllowInvalidCertificates",
                f"--tlsClusterCAFile={self.workload.paths.int_ca_file}",
                f"--tlsClusterFile={self.workload.paths.int_pem_file}",
            ]
        return cmd + [
            "--clusterAuthMode=keyFile",
            f"--keyFile={self.workload.paths.keyfile}",
        ]

    @property
    def tls_parameters(self) -> list[str]:
        """The TLS external parameters."""
        if self.state.tls.external_enabled:
            return [
                f"--tlsCAFile={self.workload.paths.ext_ca_file}",
                f"--tlsCertificateKeyFile={self.workload.paths.ext_pem_file}",
                # allow non-TLS configure_and_restartions
                "--tlsMode=preferTLS",
                "--tlsDisabledProtocols=TLS1_0,TLS1_1",
            ]
        return []


class MongoDBConfigManager(MongoConfigManager):
    """MongoDB Specifics config manager."""

    def __init__(self, config: MongoConfigModel, state: CharmState, workload: WorkloadBase):
        self.state = state
        self.workload = workload
        self.config = config
        self.auth = True

    @property
    def db_path_argument(self) -> list[str]:
        """The full path of the data directory."""
        return [f"--dbpath={self.workload.paths.data_path}"]

    @property
    def role_parameter(self) -> list[str]:
        """The role parameter."""
        # First install we don't have the role in databag yet.
        role = (
            self.state.config.role
            if self.state.app_peer_data.role == MongoDBRoles.UNKNOWN
            else self.state.app_peer_data.role
        )
        match role:
            case MongoDBRoles.CONFIG_SERVER:
                return ["--configsvr"]
            case MongoDBRoles.SHARD:
                return ["--shardsvr"]
            case _:
                return []

    @property
    def replset_option(self) -> list[str]:
        """The replSet configuration option."""
        return [f"--replSet={self.state.app_peer_data.replica_set}"]

    @property
    @override
    def port_parameter(self) -> list[str]:
        return [f"--port={MongoPorts.MONGODB_PORT}"]

    @override
    def build_parameters(self) -> list[list[str]]:
        base = super().build_parameters()
        return base + [
            self.replset_option,
            self.role_parameter,
            self.db_path_argument,
        ]


class MongosConfigManager(MongoConfigManager):
    """Mongos Specifics config manager."""

    def __init__(self, config: MongoConfigModel, workload: WorkloadBase, state: CharmState):
        self.state = state
        self.workload = workload
        self.config = config
        self.auth = False

    @property
    def config_server_db_parameter(self) -> list[str]:
        """The config server DB parameter."""
        # In case we are integrated with a config-server, we need to provide
        # it's URI to mongos so it can configure_and_restart to it.
        if uri := self.state.cluster.config_server_uri:
            return [f"--configdb {uri}"]
        return [
            f"--configdb {self.state.app_peer_data.replica_set}/{LOCALHOST}:{MongoPorts.MONGODB_PORT}"
        ]

    @property
    @override
    def port_parameter(self) -> list[str]:
        return [f"--port={MongoPorts.MONGOS_PORT}"]

    @override
    def build_parameters(self) -> list[list[str]]:
        base = super().build_parameters()
        return base + [
            self.config_server_db_parameter,
        ]
