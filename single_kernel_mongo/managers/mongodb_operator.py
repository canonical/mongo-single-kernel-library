#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for MongoDB Related Charms."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, final

from ops.charm import RelationDepartedEvent
from ops.framework import Object
from ops.model import Container, Relation, Unit
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError
from tenacity import Retrying, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    CONTAINER,
    MAX_PASSWORD_LENGTH,
    MongoPorts,
    RoleEnum,
    Scope,
    Substrates,
)
from single_kernel_mongo.config.models import ROLES, LogRotateConfig
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.secrets import generate_secret_label
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.events.backups import INVALID_S3_INTEGRATION_STATUS, BackupEventsHandler
from single_kernel_mongo.events.database import DatabaseEventsHandler
from single_kernel_mongo.events.password_actions import PasswordActionEvents
from single_kernel_mongo.events.primary_action import PrimaryActionHandler
from single_kernel_mongo.events.tls import TLSEventsHandler
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    SetPasswordError,
    ShardingMigrationError,
    UpgradeInProgressError,
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.managers.backups import BackupManager
from single_kernel_mongo.managers.config import (
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
    MonitorUser,
    OperatorUser,
    get_user_from_username,
)
from single_kernel_mongo.workload import (
    get_mongodb_workload_for_substrate,
    get_mongos_workload_for_substrate,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm  # pragma: nocover


logger = logging.getLogger(__name__)


@final
class MongoDBOperator(OperatorProtocol, Object):
    """Operator for MongoDB Related Charms."""

    name = RoleEnum.MONGOD
    workload: MongoDBWorkload

    def __init__(self, charm: AbstractMongoCharm):
        super(OperatorProtocol, self).__init__(charm, self.name)
        self.charm = charm
        self.substrate: Substrates = self.charm.substrate
        self.role = ROLES[self.substrate][self.name]
        self.state = CharmState(
            self.charm,
            self.substrate,
            self.role,
        )

        container = (
            self.charm.unit.get_container(CONTAINER) if self.substrate == Substrates.K8S else None
        )

        # Defined workloads and configs
        self.define_workloads_and_config_managers(container)

        # Managers
        self.backup_manager = BackupManager(
            self.charm,
            self.role,
            self.substrate,
            self.state,
            container,
        )
        self.tls_manager = TLSManager(
            self,
            self.workload,
            self.state,
            self.substrate,
        )
        self.mongo_manager = MongoManager(
            self,
            self.workload,
            self.state,
            self.substrate,
        )

        # Event Handlers
        self.password_actions = PasswordActionEvents(self)
        self.backup_events = BackupEventsHandler(self)
        self.tls_events = TLSEventsHandler(self)
        self.primary_events = PrimaryActionHandler(self)
        self.client_events = DatabaseEventsHandler(self, RelationNames.DATABASE)

    @property
    def config(self):
        """Returns the actual config."""
        return self.charm.parsed_config

    def define_workloads_and_config_managers(self, container: Container | None) -> None:
        """Export all workload and config definition for readability."""
        # BEGIN: Define workloads.
        self.workload = get_mongodb_workload_for_substrate(self.substrate)(
            role=self.role, container=container
        )
        self.mongos_workload = get_mongos_workload_for_substrate(self.substrate)(
            role=self.role, container=container
        )
        # END: Define workloads

        # BEGIN Define config managers
        self.config_manager = MongoDBConfigManager(
            self.config,
            self.state,
            self.workload,
        )
        self.mongos_config_manager = MongosConfigManager(
            self.config,
            self.mongos_workload,
            self.state,
        )
        self.logrotate_config_manager = LogRotateConfigManager(
            self.role,
            self.substrate,
            self.config,
            self.state,
            container,
        )
        self.mongodb_exporter_config_manager = MongoDBExporterConfigManager(
            self.role,
            self.substrate,
            self.config,
            self.state,
            container,
        )
        # END: Define config managers

    @property
    def config_managers(self) -> Iterable[CommonConfigManager]:  # pragma: nocover
        """All config managers for iteration."""
        return (
            self.config_manager,
            self.mongos_config_manager,
            self.backup_manager,
            self.logrotate_config_manager,
            self.mongodb_exporter_config_manager,
        )

    # BEGIN: Handlers.

    @override
    def on_install(self) -> None:
        """Handler on install."""
        if not self.workload.workload_present:
            raise ContainerNotReadyError
        self.charm.unit.set_workload_version(self.workload.get_version())

        # Truncate the file.
        self.workload.write(self.workload.paths.config_file, "")

        for config_manager in self.config_managers:
            config_manager.set_environment()

        self.logrotate_config_manager.connect()

    @override
    def on_start(self) -> None:
        """Handler on start."""
        if not self.workload.workload_present:
            logger.debug("mongod installation is not ready yet.")
            raise ContainerNotReadyError

        if any(not storage for storage in self.model.storages.values()):
            logger.debug("Storages not attached yet.")
            raise ContainerNotReadyError

        self.instantiate_keyfile()
        self.tls_manager.push_tls_files_to_workload()
        self.handle_licenses()
        self.set_permissions()

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
        try:
            self.open_ports()
        except WorkloadExecError:
            self.charm.status_manager.to_blocked("failed to open TCP port for MongoDB")
            raise

        if self.substrate == Substrates.K8S:
            if not self.workload.exists(self.workload.paths.socket_path):
                logger.debug("The mongod socket is not ready yet.")
                raise WorkloadNotReadyError

        if not self.mongo_manager.mongod_ready():
            self.charm.status_manager.to_waiting("waiting for MongoDB to start")
            raise WorkloadNotReadyError

        self.charm.status_manager.to_active(None)

        try:
            self.mongodb_exporter_config_manager.connect()
        except WorkloadServiceError:
            self.charm.status_manager.to_blocked("couldn't start mongodb exporter")
            return

        try:
            self.backup_manager.connect()
        except WorkloadServiceError:
            self.charm.status_manager.to_blocked("couldn't start pbm-agent")
            return

        self._initialise_replica_set()
        self.charm.status_manager.to_active(None)

    @override
    def on_stop(self) -> None:  # pragma: nocover
        """Handler for the stop event.

        Does nothing for now.
        """
        # TODO : Implement this when porting upgrades.
        pass

    @override
    def on_config_changed(self) -> None:
        """Listen to changes in application configuration.

        To prevent a user from migrating a cluster, and causing the component to become
        unresponsive therefore causing a cluster failure, error the component. This prevents it
        from executing other hooks with a new role.
        """
        if self.state.is_role(self.config.role):
            return
        if self.state.upgrade_in_progress:
            logger.warning(
                "Changing config options is not permitted during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            raise UpgradeInProgressError

        logger.error(
            f"cluster migration currently not supported, cannot change from {self.state.app_peer_data.role} to {self.config.role}"
        )
        raise ShardingMigrationError(
            f"Migration of sharding components not permitted, revert config role to {self.state.app_peer_data.role}"
        )

    @override
    def on_leader_elected(self) -> None:
        """Handles the leader elected event.

        Generates the keyfile and users credentials.
        """
        if not self.state.get_keyfile():
            self.state.set_keyfile(self.workload.generate_keyfile())

        # Set the password for the Operator User.
        if not self.state.get_user_password(OperatorUser):
            self.state.set_user_password(OperatorUser, self.workload.generate_password())

        # Set the password for the Monitor User.
        if not self.state.get_user_password(MonitorUser):
            self.state.set_user_password(MonitorUser, self.workload.generate_password())

        # Set the password for the Backup User.
        if not self.state.get_user_password(BackupUser):
            self.state.set_user_password(BackupUser, self.workload.generate_password())

    @override
    def on_relation_joined(self) -> None:
        """Handle relation joined events.

        In this event, we first check for status checks (are we leader, is the
        application in upgrade ?). Then we proceed to call the relation changed
        handler and update the list of related hosts.
        """
        if not self.charm.unit.is_leader():
            return
        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding replicas during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
            raise UpgradeInProgressError

        self.on_relation_changed()
        self.update_related_hosts()

    def on_relation_changed(self) -> None:
        """Handle relation changed events.

        Adds the unit as a replica to the MongoDB replica set.
        """
        # Changing the monitor or the backup password will lead to non-leader
        # units receiving a relation changed event. We must update the monitor
        # and pbm URI if the password changes so that COS/pbm can continue to
        # work
        self.mongodb_exporter_config_manager.connect()
        self.backup_manager.connect()

        # only leader should configure replica set and we should do it only if
        # the replica set is initialised.
        if not self.charm.unit.is_leader() or not self.state.db_initialised:
            return

        try:
            # Adds the newly added/updated units.
            self.mongo_manager.process_added_units()
        except (NotReadyError, PyMongoError) as e:
            logger.error(f"Not reconfiguring: error={e}")
            self.charm.status_manager.to_waiting("waiting to reconfigure replica set")
            raise
        self.charm.status_manager.to_active(None)

    @override
    def on_secret_changed(self, secret_label: str, secret_id: str) -> None:
        """Handles secrets changes event.

        When user run set-password action, juju leader changes the password inside the database
        and inside the secret object. This action runs the restart for monitoring tool and
        for backup tool on non-leader units to keep them working with MongoDB. The same workflow
        occurs on TLS certs change.
        """
        if (
            generate_secret_label(self.charm.app.name, self.charm.peer_rel_name, Scope.APP)
            == secret_label
        ):
            scope = Scope.APP
        elif (
            generate_secret_label(self.charm.app.name, self.charm.peer_rel_name, Scope.UNIT)
            == secret_label
        ):
            scope = Scope.UNIT
        else:
            logging.debug("Secret %s changed, but it's unknown", secret_id)
            return
        logging.debug("Secret %s for scope %s changed, refreshing", secret_id, scope)
        self.state.secrets.get(scope)

        # Always update the PBM and mongodb exporter configuration so that if
        # the secret changed, the configuration is updated and will still work
        # afterwards.
        self.mongodb_exporter_config_manager.connect()
        self.backup_manager.connect()

    @override
    def on_relation_departed(self, departing_unit: Unit | None) -> None:
        """Handles the relation departed events."""
        if not self.charm.unit.is_leader() or departing_unit == self.charm.unit:
            return
        if self.state.upgrade_in_progress:
            # do not defer or return here, if a user removes a unit, the config will be incorrect
            # and lead to MongoDB reporting that the replica set is unhealthy, we should make an
            # attempt to fix the replica set configuration even if an upgrade is occurring.
            logger.warning(
                "Removing replicas during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
        self.update_hosts()

    @override
    def on_storage_attached(self) -> None:  # pragma: nocover
        """Handler for `storage_attached` event.

        This should handle fixing the permissions for the data dir.
        """
        if self.substrate == Substrates.VM:
            self.workload.exec(["chmod", "-R", "770", f"{self.workload.paths.common_path}"])
            self.workload.exec(
                [
                    "chown",
                    "-R",
                    f"{self.workload.users.user}:{self.workload.users.group}",
                    f"{self.workload.paths.common_path}",
                ]
            )

    @override
    def on_storage_detaching(self) -> None:
        """Before storage detaches, allow removing unit to remove itself from the set.

        If the removing unit is primary also allow it to step down and elect another unit as
        primary while it still has access to its storage.
        """
        if self.state.upgrade_in_progress:
            # We cannot defer and prevent a user from removing a unit, log a warning instead.
            logger.warning(
                "Removing replicas during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
        # A single replica cannot step down as primary and we cannot reconfigure the replica set to
        # have 0 members.
        # TODO: When we have config server and shard managers.
        # if self._is_removing_last_replica:
        #    pass

        try:
            # retries over a period of 10 minutes in an attempt to resolve race conditions it is
            # not possible to defer in storage detached.
            logger.debug("Removing %s from replica set", self.state.unit_peer_data.host)
            for attempt in Retrying(
                stop=stop_after_attempt(600),
                wait=wait_fixed(1),
                reraise=True,
            ):
                with attempt:
                    # remove_replset_member retries for 60 seconds
                    self.mongo_manager.remove_replset_member()
        except NotReadyError:
            logger.info(
                "Failed to remove %s from replica set, another member is syncing",
                self.charm.unit.name,
            )
        except PyMongoError as e:
            logger.error("Failed to remove %s from replica set, error=%r", self.charm.unit.name, e)

    @override
    def on_update_status(self) -> None:
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

        try:
            self.perform_self_healing()
        except ServerSelectionTimeoutError:
            deployment = (
                "replica set" if self.state.is_role(MongoDBRoles.REPLICATION) else "cluster"
            )
            self.charm.status_manager.to_waiting(
                f"Waiting to sync internal membership across the {deployment}"
            )
        else:
            self.charm.status_manager.to_active(None)
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
            self.backup_manager.connect()
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
        return self.state.get_user_password(user)

    def perform_self_healing(self) -> None:
        """Reconfigures the replica set if necessary.

        Incidents such as network cuts can lead to new IP addresses and therefore will require a
        reconfigure. Especially in the case that the leader's IP address changed, it will not
        receive a relation event.
        """
        if not self.charm.unit.is_leader():
            logger.debug("Only the leader can perform reconfigurations to the replica set.")
            return

        # remove any IPs that are no longer juju hosts & update app data.
        self.update_hosts()
        # Add in any new IPs to the replica set. Relation handlers require a reference to
        # a unit.
        self.on_relation_changed()

        # make sure all nodes in the replica set have the same priority for re-election. This is
        # necessary in the case that pre-upgrade hook fails to reset the priority of election for
        # cluster nodes.
        self.mongo_manager.set_election_priority(priority=1)

    def update_hosts(self):
        """Update the replica set hosts and remove any unremoved replica from the config."""
        if not self.state.db_initialised:
            return
        self.mongo_manager.process_unremoved_units()
        if set(self.state.app_peer_data.replica_set_hosts) != self.state.app_hosts:
            self.state.app_peer_data.replica_set_hosts = list(self.state.app_hosts)
        self.update_related_hosts()

    def update_related_hosts(self):
        """Update the app relations that need to be made aware of the new set of hosts."""
        if self.state.is_role(MongoDBRoles.REPLICATION):
            for relation in self.state.client_relations:
                self.mongo_manager.update_app_relation_data(relation)
        # TODO: Update related hosts for config server , cluster.

    def open_ports(self) -> None:
        """Open ports on the workload.

        VM-only.
        """
        if self.substrate != Substrates.VM:
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

    @property
    def primary(self) -> str | None:
        """Retrieves the primary unit with the primary replica."""
        with MongoConnection(self.state.mongo_config) as connection:
            try:
                primary_ip = connection.primary
            except Exception as e:
                logger.error(f"Unable to get primary: {e}")
                return None

        for unit in self.state.units:
            if primary_ip == unit.host:
                return unit.name
        return None

    @override
    def start_charm_services(self):
        """Start the relevant services.

        If we are running as config-server, we should start both mongod and mongos.
        """
        self.workload.start()
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.mongos_workload.start()

    @override
    def stop_charm_services(self):
        """Stop the relevant services.

        If we are running as config-server, we should stop both mongod and mongos.
        """
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.mongos_workload.stop()
        self.workload.stop()

    @override
    def restart_charm_services(self):
        """Restarts the charm services with updated config.

        If we are running as config-server, we should update both mongod and mongos environments.
        """
        self.stop_charm_services()
        self.config_manager.set_environment()
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.mongos_config_manager.set_environment()
        self.start_charm_services()

    @override
    def is_relation_feasible(self, rel_name: str) -> bool:
        """Checks if the relation is feasible in the current context."""
        if self.state.is_sharding_component and rel_name == RelationNames.DATABASE:
            logger.error(
                "Charm is in sharding role: %s. Does not support %s interface.",
                self.state.app_peer_data.role,
                rel_name,
            )
            return False
        if not self.state.is_sharding_component and rel_name == RelationNames.SHARDING:
            logger.error(
                "Charm is in replication role: %s. Does not support %s interface.",
                self.state.app_peer_data.role,
                rel_name,
            )
            return False
        return True

    @override
    def check_relation_broken_or_scale_down(self, event: RelationDepartedEvent):
        """Checks relation departed event is the result of removed relation or scale down.

        Relation departed and relation broken events occur during scaling down or during relation
        removal, only relation departed events have access to metadata to determine which case.
        """
        departing_name = event.departing_unit.name if event.departing_unit else ""
        scaling_down = self.state.set_scaling_down(
            event.relation.id, departing_unit_name=departing_name
        )

        if scaling_down:
            logger.info(
                "Scaling down the application, no need to process removed relation in broken hook."
            )

    def instantiate_keyfile(self):
        """Instantiate the keyfile."""
        if not (keyfile := self.state.get_keyfile()):
            raise Exception("Waiting for leader unit to generate keyfile contents")

        self.workload.write(self.workload.paths.keyfile, keyfile)

    def handle_licenses(self) -> None:
        """Pull / Push licenses.

        This function runs differently according to the substrate. We do not
        store the licenses at the same location, and we do not handle the same
        licenses.
        """
        licenses = [
            "snap",
            "mongodb-exporter",
            "percona-backup-mongodb",
            "percona-server",
        ]
        prefix = Path("./src/licenses") if self.substrate == Substrates.VM else Path("./")
        # Create the directory if needed.
        if self.substrate == Substrates.VM:
            prefix.mkdir(exist_ok=True)
            file = Path("./LICENSE")
            dst = prefix / "LICENSE-charm"
            self.workload.copy_to_unit(file, dst)
        else:
            name = "LICENSE-rock"
            file = Path(f"{self.workload.paths.licenses_path}/{name}")
            dst = prefix / name
            if not dst.is_file():
                self.workload.copy_to_unit(file, dst)

        for license in licenses:
            name = f"LICENSE-{license}"
            file = Path(f"{self.workload.paths.licenses_path}/{name}")
            dst = prefix / name
            if not dst.is_file():
                self.workload.copy_to_unit(file, dst)

    def set_permissions(self) -> None:
        """Ensure directories and make permissions.

        We must ensure that the log status directory for LogRotate is existing.
        We must also ensure that all data, log and log status directories have
        the correct permissions.
        """
        self.workload.mkdir(LogRotateConfig.log_status_dir, make_parents=True)

        for path in (
            self.workload.paths.data_path,
            self.workload.paths.logs_path,
            LogRotateConfig.log_status_dir,
        ):
            self.workload.exec(
                [
                    "chown",
                    "-R",
                    f"{self.workload.users.user}:{self.workload.users.group}",
                    f"{path}",
                ]
            )

    def _initialise_replica_set(self):
        """Helpful method to initialise the replica set and the users.

        This is executed only by the leader.
        This function first initialises the replica set, and then the three charm users.
        Finally, if there are any integrated clients (direct clients in the
        case of replication, or mongos clients in case of config-server),
        oversee the relation to create the associated users.
        At the very end, it sets the `db_initialised` flag to True.
        """
        if not self.model.unit.is_leader():
            return
        self.mongo_manager.initialise_replica_set()
        self.mongo_manager.initialise_users()
        logger.info("Manage client relation users")
        if self.state.is_role(MongoDBRoles.REPLICATION):
            for relation in self.state.client_relations:
                self.mongo_manager.oversee_relation(relation)
        elif self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            for relation in self.state.cluster_relations:
                self.mongo_manager.oversee_relation(relation)

        self.state.app_peer_data.db_initialised = True

    @property
    def is_removing_last_replica(self) -> bool:
        """Returns True if the last replica (juju unit) is getting removed."""
        return self.state.planned_units == 0 and len(self.state.peers_units) == 0

    def assert_proceed_on_broken_event(self, relation: Relation):
        """Runs some checks on broken relation event."""
        if not self.state.has_departed_run(relation.id):
            raise DeferrableFailedHookChecksError(
                "must wait for relation departed hook to decide if relation should be removed"
            )

        if self.state.is_scaling_down(relation.id):
            raise NonDeferrableFailedHookChecksError(
                "Relation broken event occurring during scale down, do not proceed to remove users."
            )
