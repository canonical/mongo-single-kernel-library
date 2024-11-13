#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling Mongo configuration."""

from abc import ABC, abstractmethod
from itertools import chain

from typing_extensions import override

from single_kernel_mongo.config.audit_config import AuditLog
from single_kernel_mongo.config.literals import LOCALHOST, MongoPorts
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.workload.backup_workload import PBMWorkload
from single_kernel_mongo.workload.log_rotate_workload import LogRotateWorkload


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

    @abstractmethod
    def build_parameters(self) -> list[list[str]]:
        """Builds the parameters list."""
        ...


class BackupConfigManager(CommonConfigManager):
    """Config manager for PBM."""

    def __init__(self, config: MongoConfigModel, workload: PBMWorkload, state: CharmState):
        self.config = config
        self.workload = workload
        self.state = state

    @override
    def build_parameters(self) -> list[list[str]]:
        return [
            [
                self.state.backup_config.uri,
            ]
        ]


class LogRotateConfigManager(CommonConfigManager):
    """Config manager for logrotate."""

    def __init__(self, config: MongoConfigModel, workload: LogRotateWorkload, state: CharmState):
        self.config = config
        self.workload = workload
        self.state = state

    @override
    def build_parameters(self) -> list[list[str]]:
        return [[]]


class MongoDBExporterConfigManager(CommonConfigManager):
    """Config manager for mongodb-exporter."""

    def __init__(self, config: MongoConfigModel, workload: LogRotateWorkload, state: CharmState):
        self.config = config
        self.workload = workload
        self.state = state

    @override
    def build_parameters(self) -> list[list[str]]:
        return [[self.state.monitor_config.uri]]


class MongoConfigManager(CommonConfigManager, ABC):
    """The common configuration manager for both MongoDB and Mongos."""

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
        """The binding IP parameters."""
        if not self.state.app_peer_data.external_connectivity:
            return [
                f"--bind-ip {self.workload.paths.socket_path}",
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
            f"--auditDestination={AuditLog.destination}",
            f"--auditFormat={AuditLog.format}",
            f"--auditPath={self.workload.paths.audit_file}",
        ]

    @property
    def auth_parameter(self) -> list[str]:
        """The auth mode."""
        if self.state.tls.internal_enabled and self.state.tls.external_enabled:
            return [
                "--auth",
                "--clusterAuthMode=x509",
                "--tlsAllowInvalidCertificates",
                f"--tlsClusterCAFile={self.workload.paths.int_ca_file}",
                f"--tlsClusterFile={self.workload.paths.int_pem_file}",
            ]
        return [
            "--auth",
            "--clusterAuthMode=keyfile",
            f"--keyfile={self.workload.paths.keyfile}",
        ]

    @property
    def tls_parameters(self) -> list[str]:
        """The TLS external parameters."""
        if self.state.tls.external_enabled:
            return [
                f"--tlsCAFile={self.workload.paths.ext_ca_file}",
                f"--tlsCertificateKeyFile={self.workload.paths.ext_pem_file}",
                # allow non-TLS connections
                "--tlsMode=preferTLS",
                "--tlsDisabledProtocols=TLS1_0,TLS1_1",
            ]
        return []


class MongoDBConfigManager(MongoConfigManager):
    """MongoDB Specifics config manager."""

    def __init__(self, state: CharmState, workload: WorkloadBase, config: MongoConfigModel):
        self.state = state
        self.workload = workload
        self.config = config

    @property
    def db_path_argument(self) -> list[str]:
        """The full path of the data directory."""
        return [f"--dbpath={self.workload.paths.data_path}"]

    @property
    def role_parameter(self) -> list[str]:
        """The role parameter."""
        match self.state.app_peer_data.role:
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
        return [f"--port {MongoPorts.MONGODB_PORT}"]

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

    def __init__(self, state: CharmState, workload: WorkloadBase, config: MongoConfigModel):
        self.state = state
        self.workload = workload
        self.config = config

    @property
    def config_server_db_parameter(self) -> list[str]:
        """The config server DB parameter."""
        if uri := self.state.cluster.config_server_uri:
            return [f"--configdb {uri}"]
        return [
            f"--configdb {self.state.app_peer_data.replica_set}/{LOCALHOST}:{MongoPorts.MONGODB_PORT}"
        ]

    @property
    @override
    def port_parameter(self) -> list[str]:
        return [f"--port {MongoPorts.MONGOS_PORT}"]

    @override
    def build_parameters(self) -> list[list[str]]:
        base = super().build_parameters()
        return base + [
            self.config_server_db_parameter,
        ]
