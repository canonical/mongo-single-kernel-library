#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for MongoDB Related Charms."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING

from ops.model import Container
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import (
    CONTAINER,
    MAX_PASSWORD_LENGTH,
    MongoPorts,
    Scope,
    Substrates,
)
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.roles import K8S_MONGO, VM_MONGO
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.events.backups import INVALID_S3_INTEGRATION_STATUS
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    SetPasswordError,
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.managers.backups import BackupManager
from single_kernel_mongo.managers.config import (
    BackupConfigManager,
    CommonConfigManager,
    LogRotateConfigManager,
    MongoDBConfigManager,
    MongoDBExporterConfigManager,
    MongosConfigManager,
)
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.managers.tls import TLSManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MonitorUser,
    OperatorUser,
    get_user_from_username,
)
from single_kernel_mongo.workload import (
    get_mongodb_workload_for_substrate,
    get_mongos_workload_for_substrate,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

from ops.framework import Object

logger = logging.getLogger(__name__)


class MongoDBOperator(OperatorProtocol, Object):
    """Operator for MongoDB Related Charms."""

    def __init__(self, charm: AbstractMongoCharm):
        super().__init__(charm, "mongodb")
        self.charm = charm
        self.substrate: Substrates = self.charm.substrate
        self.role = VM_MONGO if self.substrate == "vm" else K8S_MONGO
        self.state = CharmState(self.charm, self.role)
        container = self.charm.unit.get_container(CONTAINER) if self.substrate == "k8s" else None

        # Defined workloads and configs
        self.define_workloads_and_config_managers(container)

        self.backup_manager = BackupManager(self.charm, self.substrate, self.state, container)
        self.tls_manager = TLSManager(self.charm, self.workload, self.state, self.substrate)
        self.mongo_manager = MongoManager(self.charm, self.workload, self.state, self.substrate)

    def define_workloads_and_config_managers(self, container: Container | None) -> None:
        """Export all workload and config definition for readability."""
        # BEGIN: Define workloads.
        self.workload = get_mongodb_workload_for_substrate(self.substrate)(container=container)
        self.mongos_workload = get_mongos_workload_for_substrate(self.substrate)(
            container=container
        )
        # END: Define workloads

        # BEGIN Define config managers
        self.config_manager = MongoDBConfigManager(
            self.charm.config,
            self.state,
            self.workload,
        )
        self.mongos_config_manager = MongosConfigManager(
            self.charm.config,
            self.mongos_workload,
            self.state,
        )
        self.backup_config_manager = BackupConfigManager(
            self.substrate,
            self.charm.config,
            self.state,
            container,
        )
        self.logrotate_config_manager = LogRotateConfigManager(
            self.substrate,
            self.charm.config,
            self.state,
            container,
        )
        self.mongodb_exporter_config_manager = MongoDBExporterConfigManager(
            self.substrate,
            self.charm.config,
            self.state,
            container,
        )
        # END: Define config managers

    @property
    def config_managers(self) -> Iterable[CommonConfigManager]:
        """All config managers for iteration."""
        return (
            self.config_manager,
            self.mongos_config_manager,
            self.backup_config_manager,
            self.logrotate_config_manager,
            self.mongodb_exporter_config_manager,
        )

    # BEGIN: Handlers.

    def on_install(self) -> None:
        """Handler on install."""
        if not self.workload.container_can_connect:
            raise ContainerNotReadyError
        self.charm.unit.set_workload_version(self.workload.get_version())

        # Truncate the file.
        self.workload.write(self.workload.paths.config_file, "")

        for config_manager in self.config_managers:
            config_manager.set_environment()

        self.logrotate_config_manager.connect()

    def on_start(self) -> None:
        """Handler on start."""
        if not self.workload.container_can_connect:
            raise ContainerNotReadyError

        self.instantiate_keyfile()
        self.tls_manager.push_tls_files_to_workload()

        try:
            logger.info("Starting MongoDB.")
            self.charm.status_manager.to_maintenance("starting MongoDB")
            self.start_charm_services()
            self.charm.status_manager.to_active(None)
        except WorkloadServiceError as e:
            logger.error(f"An exception occurred when starting mongod agent, error: {e}.")
            self.charm.status_manager.to_blocked("couldn't start MongoDB")
            return

        # Open ports:
        self.open_ports()

        if not self.mongo_manager.mongod_ready():
            self.charm.status_manager.to_waiting("waiting for MongoDB to start")
            raise WorkloadNotReadyError

        self.charm.status_manager.to_active(None)

        try:
            self.mongodb_exporter_config_manager.connect()
        except WorkloadServiceError:
            self.charm.status_manager.to_blocked("couldn't start mongodb exporter")
            return

        self._initialise_replica_set()

    def on_leader_elected(self) -> None:
        """Handles the leader elected event.

        Generates the keyfile and users credentials.
        """
        if not self.state.app_peer_data.keyfile:
            self.state.app_peer_data.keyfile = self.workload.generate_keyfile()

        # Set the password for the Operator User.
        if not self.state.app_peer_data.get_user_password(OperatorUser.username):
            self.state.app_peer_data.set_user_password(
                OperatorUser.username, self.workload.generate_password()
            )

        # Set the password for the Monitor User.
        if not self.state.app_peer_data.get_user_password(MonitorUser.username):
            self.state.app_peer_data.set_user_password(
                MonitorUser.username, self.workload.generate_password()
            )

        # Set the password for the Backup User.
        if not self.state.app_peer_data.get_user_password(BackupUser.username):
            self.state.app_peer_data.set_user_password(
                BackupUser.username, self.workload.generate_password()
            )

    def on_relation_handler(self) -> None:
        """Handle relation changed events."""
        self.mongodb_exporter_config_manager.connect()
        self.backup_config_manager.connect()

        if not self.charm.unit.is_leader() or not self.state.db_initialised:
            return

        try:
            self.mongo_manager.process_added_units()
        except (NotReadyError, PyMongoError) as e:
            logger.error(f"Not reconfiguring: error={e}")
            self.charm.status_manager.to_waiting("waiting to reconfigure replica set")
            raise
        self.charm.status_manager.to_active(None)

    def on_status_update(self) -> None:
        """Status update Handler."""
        if not self.backup_manager.is_valid_s3_integration():
            self.charm.status_manager.to_blocked(INVALID_S3_INTEGRATION_STATUS)
            return
        # TODO: Cluster integration status + Cluster Mismatch revision.
        if not self.state.db_initialised:
            return

        # TODO: TLS + Shard check.

        if not self.mongo_manager.mongod_ready():
            self.charm.status_manager.to_waiting("Waiting for MongoDB to start")

        self.perform_self_healing()

        # TODO: Process statuses.

    def on_set_password_action(self, username: str, password: str | None = None) -> tuple[str, str]:
        """Handler for the set password action."""
        user = get_user_from_username(username)
        new_password = password or self.workload.generate_password()
        if len(new_password) > MAX_PASSWORD_LENGTH:
            raise SetPasswordError(
                f"Password cannot be longer than {MAX_PASSWORD_LENGTH} characters."
            )

        secret_id = self.mongo_manager.set_user_password(user, new_password)
        if user == BackupUser:
            # Update and restart PBM Agent.
            self.backup_config_manager.connect()
        if user == MonitorUser:
            # Update and restart mongodb exporter.
            self.mongodb_exporter_config_manager.connect()
        # Rotate password.
        if user in (OperatorUser, BackupUser):
            pass

        return new_password, secret_id

    def on_get_password_action(self, username: str) -> str:
        """Handler for the get password action."""
        return self.get_password(username)

    # END: Handlers.

    def get_password(self, username: str) -> str:
        """Gets the password for the relevant username."""
        user = get_user_from_username(username)
        return self.state.secrets.get_for_key(Scope.APP, user.password_key_name) or ""

    def perform_self_healing(self) -> None:
        """Reconfigures the replica set if necessary.

        Incidents such as network cuts can lead to new IP addresses and therefore will require a
        reconfigure. Especially in the case that the leader's IP address changed, it will not
        receive a relation event.
        """
        if not self.charm.unit.is_leader():
            logger.debug("Only the leader can perform reconfigurations to the replica set.")
            return

        self.update_hosts()
        self.on_relation_handler()
        # make sure all nodes in the replica set have the same priority for re-election. This is
        # necessary in the case that pre-upgrade hook fails to reset the priority of election for
        # cluster nodes.
        self.mongo_manager.set_election_priority(priority=1)

    def update_hosts(self):
        """Update the replica set hosts and remove any unremoved replica from the config."""
        if not self.state.db_initialised:
            return
        self.mongo_manager.process_unremoved_units()
        self.state.app_peer_data.replica_set_hosts = list(self.state.app_hosts)
        self.update_related_hosts()

    def update_related_hosts(self):
        """Update the app relations that need to be made aware of the new set of hosts."""
        if self.state.is_role(MongoDBRoles.REPLICATION):
            self.mongo_manager.update_app_relation_data(RelationNames.DATABASE)
        # TODO: Update related hosts for config server , cluster.

    def open_ports(self) -> None:
        """Open ports on the workload.

        VM-only.
        """
        if self.substrate != "vm":
            return
        ports = [MongoPorts.MONGODB_PORT]
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            ports.append(MongoPorts.MONGOS_PORT)

        try:
            for port in ports:
                self.workload.exec(["open-port", f"{port}/TCP"])
        except WorkloadExecError as e:
            logger.exception(f"Failed to open port: {e}")
            raise

    def start_charm_services(self):
        """Start the relevant services."""
        self.workload.start()
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.mongos_workload.start()

    def stop_charm_services(self):
        """Start the relevant services."""
        self.workload.stop()
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.mongos_workload.stop()

    def instantiate_keyfile(self):
        """Instantiate the keyfile."""
        if not (keyfile := self.state.app_peer_data.keyfile):
            raise Exception("Waiting for leader unit to generate keyfile contents")

        self.workload.write(self.workload.paths.keyfile, keyfile)

    def _initialise_replica_set(self):
        if not self.model.unit.is_leader():
            return
        if not self.state.db_initialised:
            return
        self.mongo_manager.initialise_replica_set()
        self.mongo_manager.initialise_users()
