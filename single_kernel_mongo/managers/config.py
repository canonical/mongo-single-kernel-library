#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling Mongo configuration."""

import logging
import time
from abc import ABC, abstractmethod
from functools import reduce
from itertools import chain
from pathlib import Path
from typing import Any

from deepmerge import always_merger
from ops import Container
from typing_extensions import override
from yaml import safe_dump, safe_load

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
from single_kernel_mongo.utils.mongodb_users import BackupUser, LogRotateUser, MonitorUser
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


class FileBasedConfigManager(CommonConfigManager):
    """A generic file based config manager.

    This is used by services that require to set arguments in the config file.
    It currently supports yaml but more supports could be provided using mixins in the future.
    """

    file: Path

    @abstractmethod
    def build_config(self) -> dict[str, Any]:
        """Builds the config dict."""
        ...

    def set_environment(self):
        """Write update parameters in the file."""
        data = "\n".join(self.workload.read(self.file))
        current_content = safe_load(data)

        new_content = self.build_config()

        if new_content != current_content:
            self.workload.write(self.file, safe_dump(new_content))

    def configure_and_restart(self, force: bool = False) -> None:
        """Re-configure if needed and restart the service if needed."""
        current_config_file = "\n".join(self.workload.read(self.file))
        current_config_file_content = safe_load(current_config_file)

        new_content = self.build_config()

        if force or not self.workload.active() or new_content != current_config_file_content:
            self.workload.write(self.file, safe_dump(new_content))
            self.workload.restart()


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
        return [[self.state.logrotate_config.uri]]

    def configure_and_restart(self) -> None:
        """Setup logrotate and cron."""
        if not self.state.db_initialised:
            logger.info("DB is not initialised.")
            return

        if not self.state.get_user_password(LogRotateUser):
            logger.info("No password found.")
            return

        try:
            self.set_environment()
            self.workload.build_template()
            if self.substrate == Substrates.VM:
                self.workload.setup_cron(
                    [
                        f"* 1-23 * * * root logrotate {LogRotateConfig.rendered_template}\n",
                        f"1-59 0 * * * root logrotate {LogRotateConfig.rendered_template}\n",
                    ]
                )
            else:
                self.workload.restart()
        except WorkloadServiceError as e:
            logger.error(f"Failed to restart {self.workload.service}: {e}")
            raise


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
                # Always enable the service
                self.workload.stop()
                self.set_environment()
                self.workload.start()
            except WorkloadServiceError as e:
                logger.error(f"Failed to restart {self.workload.service}: {e}")
                raise


class MongoConfigManager(FileBasedConfigManager, ABC):
    """The common configuration manager for both MongoDB and Mongos."""

    auth: bool

    @override
    def build_parameters(self) -> list[list[str]]:
        """We aim to pass most config options inside the config file instead of as parameters.

        In earlier charm versions we pass parameters, however for
        security reasons in LDAP params we have now decided to set these in the
        config file.
        We return an empty list of lists so that we don't break interfaces.
        """
        return [[]]

    @override
    def build_config(self) -> dict[str, Any]:
        return reduce(
            always_merger.merge,
            [
                self.binding_ips,
                self.port_parameter,
                self.auth_parameter,
                self.tls_parameters,
                self.log_options,
                self.audit_options,
                self.ldap_parameters,
            ],
        )

    @property
    @abstractmethod
    def port_parameter(self) -> dict[str, Any]:
        """The port parameter."""
        ...

    @property
    def binding_ips(self) -> dict[str, Any]:
        """The binding IP parameters.

        For VM Mongos we bind to the socked (if non-external), this gives us
        one less network hop when communicating with the client.
        """
        if (
            self.state.charm_role.name == CharmKind.MONGOS
            and self.state.substrate == Substrates.VM
            and not self.state.app_peer_data.external_connectivity
        ):
            return {
                "net": {
                    "bindIp": f"{self.workload.paths.socket_path}",
                    "unixDomainSocket": {
                        "filePermissions": "0766",
                    },
                },
            }
        return {"net": {"bindIpAll": True}}

    @property
    def log_options(self) -> dict[str, Any]:
        """The arguments for the logging option."""
        return {
            "setParameter": {"processUmask": "037"},
            "systemLog": {
                "logRotate": "reopen",
                "logAppend": True,
                "path": f"{self.workload.paths.log_file}",
                "destination": "file",
            },
        }

    @property
    def audit_options(self) -> dict[str, Any]:
        """The argument for the audit log options."""
        return {
            "auditLog": {
                "destination": AuditLogConfig.destination,
                "format": AuditLogConfig.format,
                "path": f"{self.workload.paths.audit_file}",
            }
        }

    @property
    def auth_parameter(self) -> dict[str, Any]:
        """The auth mode."""
        cmd = {"security": {"authorization": "enabled"}} if self.auth else {}
        if self.state.tls.internal_enabled and self.state.tls.external_enabled:
            return always_merger.merge(
                cmd,
                {
                    "security": {"clusterAuthMode": "x509"},
                    "net": {
                        "tls": {
                            "allowInvalidCertificates": True,
                            "clusterCAFile": f"{self.workload.paths.int_ca_file}",
                            "clusterFile": f"{self.workload.paths.int_pem_file}",
                        }
                    },
                },
            )
        return always_merger.merge(
            cmd,
            {
                "security": {
                    "clusterAuthMode": "keyFile",
                    "keyFile": f"{self.workload.paths.keyfile}",
                }
            },
        )

    @property
    def tls_parameters(self) -> dict[str, Any]:
        """The TLS external parameters."""
        if self.state.tls.external_enabled:
            return {
                "net": {
                    "tls": {
                        "CAFile": f"{self.workload.paths.ext_ca_file}",
                        "certificateKeyFile": f"{self.workload.paths.ext_pem_file}",
                        "mode": "preferTLS",
                        "disabledProtocols": "TLS1_0,TLS1_1",
                    }
                },
            }
        return {}

    @property
    @abstractmethod
    def ldap_parameters(self) -> dict[str, Any]:
        """The LDAP configuration parameters."""
        ...


class MongoDBConfigManager(MongoConfigManager):
    """MongoDB Specifics config manager."""

    def __init__(self, config: MongoConfigModel, state: CharmState, workload: WorkloadBase):
        self.state = state
        self.workload = workload
        self.config = config
        self.file = self.workload.paths.config_file
        self.auth = True

    @property
    def db_path_argument(self) -> dict[str, Any]:
        """The full path of the data directory."""
        return {
            "storage": {
                "dbPath": f"{self.workload.paths.data_path}",
                "journal": {"enabled": True},
            }
        }

    @property
    def role_parameter(self) -> dict[str, Any]:
        """The role parameter."""
        # First install we don't have the role in databag yet.
        role = (
            self.state.config.role
            if self.state.app_peer_data.role == MongoDBRoles.UNKNOWN
            else self.state.app_peer_data.role
        )
        match role:
            case MongoDBRoles.CONFIG_SERVER:
                return {"sharding": {"clusterRole": "configsvr"}}
            case MongoDBRoles.SHARD:
                return {"sharding": {"clusterRole": "shardsvr"}}
            case _:
                return {}

    @property
    def replset_option(self) -> dict[str, Any]:
        """The replSet configuration option."""
        return {"replication": {"replSetName": self.state.app_peer_data.replica_set}}

    @property
    @override
    def port_parameter(self) -> dict[str, Any]:
        return {"net": {"port": MongoPorts.MONGODB_PORT.value}}

    @property
    @override
    def ldap_parameters(self) -> dict[str, Any]:
        # Don't write any config if we are not fully ready to connect to LDAP
        # (meaning we have the relations + config + certs received)
        if not self.state.ldap_relation or not self.state.ldap_cert_relation:
            return {}
        if not self.state.ldap.is_ready():
            return {}
        # We never configure shards for LDAP, see spec (DA-156).
        if self.state.is_role(MongoDBRoles.SHARD):
            return {}

        # Fallback if no queryTemplate is provided.
        user = "{USER}" if self.state.ldap.ldap_user_to_dn_mapping else "{PROVIDED_USER}"

        ldap_params: dict[str, Any] = {
            "security": {
                "ldap": {
                    "servers": ",".join(self.state.ldap.formatted_ldap_urls),
                    "transportSecurity": "tls",
                    "bind": {
                        "queryUser": self.state.ldap.bind_user,
                        "queryPassword": self.state.ldap.bind_password,
                    },
                    "authz": {
                        "queryTemplate": self.state.ldap.ldap_query_template
                        or f"{self.state.ldap.base_dn}??sub?(&(objectClass=posixGroup)(uniqueMember={user}))",
                    },
                }
            },
            "setParameter": {"authenticationMechanisms": "PLAIN,SCRAM-SHA-256"},
        }
        if self.state.ldap.ldap_user_to_dn_mapping:
            ldap_params["security"]["ldap"]["userToDNMapping"] = (
                self.state.ldap.ldap_user_to_dn_mapping
            )
        return ldap_params

    @override
    def build_config(self) -> dict[str, Any]:
        base = super().build_config()
        return reduce(
            always_merger.merge,
            [base, self.replset_option, self.role_parameter, self.db_path_argument],
        )


class MongosConfigManager(MongoConfigManager):
    """Mongos Specifics config manager."""

    def __init__(self, config: MongoConfigModel, workload: WorkloadBase, state: CharmState):
        self.state = state
        self.workload = workload
        self.config = config
        self.auth = False
        self.file = self.workload.paths.mongos_config_file

    @property
    def config_server_db_parameter(self) -> dict[str, Any]:
        """The config server DB parameter."""
        # In case we are integrated with a config-server, we need to provide
        # it's URI to mongos so it can configure_and_restart to it.
        if uri := self.state.cluster.config_server_uri:
            return {"sharding": {"configDB": uri}}
        return {
            "sharding": {
                "configDB": f"{self.state.app_peer_data.replica_set}/{LOCALHOST}:{MongoPorts.MONGODB_PORT}"
            }
        }

    @property
    @override
    def port_parameter(self) -> dict[str, Any]:
        return {"net": {"port": MongoPorts.MONGOS_PORT.value}}

    @property
    @override
    def ldap_parameters(self) -> dict[str, Any]:
        if not self.state.ldap_relation or not self.state.ldap_cert_relation:
            return {}
        if not self.state.ldap.is_ready():
            return {}

        ldap_params: dict[str, Any] = {
            "security": {
                "ldap": {
                    "servers": ",".join(self.state.ldap.formatted_ldap_urls),
                    "transportSecurity": "tls",
                    "bind": {
                        "queryUser": self.state.ldap.bind_user,
                        "queryPassword": self.state.ldap.bind_password,
                    },
                }
            },
            "setParameter": {"authenticationMechanisms": "PLAIN,SCRAM-SHA-256"},
        }
        if self.state.ldap.ldap_user_to_dn_mapping:
            ldap_params["security"]["ldap"]["userToDNMapping"] = (
                self.state.ldap.ldap_user_to_dn_mapping
            )
        return ldap_params

    @override
    def build_config(self) -> dict[str, Any]:
        base = super().build_config()
        return always_merger.merge(base, self.config_server_db_parameter)
