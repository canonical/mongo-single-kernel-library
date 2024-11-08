#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling Mongo configuration."""

from abc import abstractmethod
from itertools import chain

from typing_extensions import override

from single_kernel_mongo.config.audit_config import AuditLog
from single_kernel_mongo.config.literals import LOCALHOST, MongoPorts
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.state.peer_state import AppPeerReplicaSet


class CommonConfigManager:
    """The common configuration manager for both MongoDB and Mongos."""

    config: MongoConfigModel
    workload: WorkloadBase
    state: AppPeerReplicaSet

    def set_environment(self):
        """Write all parameters in the environment variable."""
        parameters = chain.from_iterable(self.build_parameters())
        param_as_str = " ".join(parameters)
        self.workload.update_env({self.workload.env_var: param_as_str})

    def build_parameters(self) -> list[list[str]]:
        """Builds the parameters list."""
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
        if not self.state.external_connectivity:
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
        if self.state.tls_enabled:
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
        if self.state.tls_enabled:
            return [
                f"--tlsCAFile={self.workload.paths.ext_ca_file}",
                f"--tlsCertificateKeyFile={self.workload.paths.ext_pem_file}",
                # allow non-TLS connections
                "--tlsMode=preferTLS",
                "--tlsDisabledProtocols=TLS1_0,TLS1_1",
            ]
        return []


class MongoDBConfigManager(CommonConfigManager):
    """MongoDB Specifics config manager."""

    @property
    def db_path_argument(self) -> list[str]:
        """The full path of the data directory."""
        return [f"--dbpath={self.workload.paths.data_path}"]

    @property
    def role_parameter(self) -> list[str]:
        """The role parameter."""
        match self.state.role:
            case MongoDBRoles.CONFIG_SERVER:
                return ["--configsvr"]
            case MongoDBRoles.SHARD:
                return ["--shardsvr"]
            case _:
                return []

    @property
    def replset_option(self) -> list[str]:
        """The replSet configuration option."""
        return [f"--replSet={self.state.replica_set}"]

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


class MongosConfigManager(CommonConfigManager):
    """Mongos Specifics config manager."""

    @property
    def config_server_db(self) -> list[str]:
        """The config server DB parameter."""
        if self.state.config_server_url:
            return [f"--configdb {self.state.config_server_url}"]
        return [f"--configdb {self.state.replica_set}/{LOCALHOST}:{MongoPorts.MONGODB_PORT}"]

    @property
    @override
    def port_parameter(self) -> list[str]:
        return [f"--port {MongoPorts.MONGOS_PORT}"]

    @override
    def build_parameters(self) -> list[list[str]]:
        base = super().build_parameters()
        return base + [
            self.config_server_db,
        ]
