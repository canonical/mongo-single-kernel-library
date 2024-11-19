#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for MongoDB Related Charms."""

from __future__ import annotations

import logging
import time
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
from single_kernel_mongo.config.roles import K8S_MONGO, VM_MONGO
from single_kernel_mongo.core.structured_config import MongoDBRoles
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
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
    get_user_from_username,
)
from single_kernel_mongo.workload import (
    get_logrotate_workload_for_substrate,
    get_mongodb_exporter_workload_for_substrate,
    get_mongodb_workload_for_substrate,
    get_mongos_workload_for_substrate,
    get_pbm_workload_for_substrate,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

from ops.framework import Object

logger = logging.getLogger(__name__)


class MongoDBOperator(Object):
    """Operator for MongoDB Related Charms."""

    tls: TLSManager

    def __init__(self, charm: AbstractMongoCharm):
        super().__init__(charm, "mongodb")
        self.charm = charm
        self.substrate: Substrates = self.charm.substrate
        self.role = VM_MONGO if self.substrate == "vm" else K8S_MONGO
        self.state = CharmState(self.charm, self.role)
        container = self.charm.unit.get_container(CONTAINER) if self.substrate == "k8s" else None

        # Defined workloads and configs
        self.define_workloads_and_config_managers(container)

        self.backup_manager = BackupManager(self.charm, self.pbm_workload, self.state)
        self.tls_manager = TLSManager(self.charm, self.workload, self.state, self.substrate)
        self.mongo_manager = MongoManager(self.charm, self.workload, self.state, self.substrate)

    def define_workloads_and_config_managers(self, container: Container | None) -> None:
        """Export all workload and config definition for readability."""
        # BEGIN: Define workloads.
        self.workload = get_mongodb_workload_for_substrate(self.substrate)(container=container)
        self.pbm_workload = get_pbm_workload_for_substrate(self.substrate)(container=container)
        self.log_rotate_workload = get_logrotate_workload_for_substrate(self.substrate)(
            container=container
        )
        self.mongodb_exporter_workload = get_mongodb_exporter_workload_for_substrate(
            self.substrate
        )(container=container)
        self.mongos_workload = get_mongos_workload_for_substrate(self.substrate)(
            container=container
        )
        self.pbm_workload = get_pbm_workload_for_substrate(self.substrate)(container=container)
        # END: Define workloads

        # BEGIN Define config managers
        self.config_manager = MongoDBConfigManager(
            self.charm.config,
            self.state,
            self.workload,
        )
        self.backup_config_manager = BackupConfigManager(
            self.charm.config, self.pbm_workload, self.state
        )
        self.logrotate_config_manager = LogRotateConfigManager(
            self.charm.config, self.log_rotate_workload, self.state
        )
        self.mongodb_exporter_config_manager = MongoDBExporterConfigManager(
            self.charm.config, self.mongodb_exporter_workload, self.state
        )
        self.mongos_config_manager = MongosConfigManager(
            self.charm.config, self.mongos_workload, self.state
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

    def handle_set_password_action(
        self, username: str, password: str | None = None
    ) -> tuple[str, str]:
        """Sets the password."""
        user = get_user_from_username(username)
        new_password = password or self.workload.generate_password()
        if len(new_password) > MAX_PASSWORD_LENGTH:
            raise SetPasswordError(
                f"Password cannot be longer than {MAX_PASSWORD_LENGTH} characters."
            )

        secret_id = self.set_password(user, new_password)
        # Rotate password.
        if username in (OperatorUser.username, BackupUser.username):
            pass

        return new_password, secret_id

    def set_password(self, user: MongoDBUser, password: str) -> str:
        """Sets the password for a given username and return the secret id.

        Raises:
            SetPasswordError
        """
        with MongoConnection(self.state.mongo_config) as mongo:
            try:
                mongo.set_user_password(user.username, password)
            except NotReadyError:
                raise SetPasswordError(
                    "Failed changing the password: Not all members healthy or finished initial sync."
                )
            except PyMongoError as e:
                raise SetPasswordError(f"Failed changing the password: {e}")

        return self.state.secrets.set(
            user.password_key_name,
            password,
            Scope.UNIT,
        ).label

    def get_password(self, username: str) -> str:
        """Gets the password for the relevant username."""
        user = get_user_from_username(username)
        return self.state.secrets.get_for_key(Scope.APP, user.password_key_name) or ""

    def on_install(self):
        """Handler on install."""
        if not self.workload.container_can_connect:
            raise ContainerNotReadyError
        self.charm.unit.set_workload_version(self.workload.get_version())

        for config_manager in self.config_manager:
            config_manager.set_environment()

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
        if self.substrate == "vm":
            self.open_ports()

        if not self.mongo_manager.mongod_ready:
            self.charm.status_manager.to_waiting("waiting for MongoDB to start")
            raise WorkloadNotReadyError

        self.charm.status_manager.to_active(None)

        try:
            self._connect_mongodb_exporter()
        except WorkloadServiceError:
            self.charm.status_manager.to_blocked("couldn't start mongodb exporter")
            return

        self._initialise_replica_set()

    def open_ports(self) -> None:
        """Open ports on the workload.

        VM-only.
        """
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

    def _connect_mongodb_exporter(self) -> None:
        """Exposes the endpoint to mongodb_exporter."""
        if not self.state.app_peer_data.db_initialised:
            return

        if not self.state.app_peer_data.get_user_password(MonitorUser.username):
            return

        current_parameters = [[self.mongodb_exporter_config_manager.get_environment()]]
        if (
            current_parameters != self.mongodb_exporter_config_manager.build_parameters()
            or not self.mongodb_exporter_workload.active()
        ):
            try:
                self.mongodb_exporter_config_manager.set_environment()
                self.mongodb_exporter_workload.restart()
            except WorkloadServiceError as e:
                logger.error(f"Failed to restart {self.mongodb_exporter_workload.service}: {e}")
                raise

    def _connect_pbm_agent(self) -> None:
        """Exposes the endpoint to pbm agent."""
        if not self.pbm_workload.container_can_connect:
            return
        if not self.state.app_peer_data.db_initialised:
            return

        if not self.state.app_peer_data.get_user_password(BackupUser.username):
            return

        current_parameters = [[self.backup_config_manager.get_environment()]]

        if (
            current_parameters != self.backup_config_manager.build_parameters()
            or not self.pbm_workload.active()
        ):
            try:
                self.pbm_workload.stop()
                self.backup_config_manager.set_environment()
                # Avoid restart errors on PBM.
                time.sleep(2)
                self.pbm_workload.start()
            except WorkloadServiceError as e:
                logger.error(f"Failed to restart {self.pbm_workload.service}: {e}")
                raise

    def _initialise_replica_set(self):
        if not self.model.unit.is_leader():
            return
        if not self.state.app_peer_data.db_initialised:
            return
        self.mongo_manager.initialise_replica_set()
        self.mongo_manager.initialise_users()
