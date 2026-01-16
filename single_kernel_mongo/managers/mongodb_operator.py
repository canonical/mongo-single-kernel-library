#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for MongoDB Related Charms."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, final

from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope as DPHScope
from data_platform_helpers.version_check import (
    CrossAppVersionChecker,
    get_charm_revision,
)
from ops.framework import Object
from ops.model import Container, Unit
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError
from tenacity import Retrying, stop_after_attempt, wait_fixed
from typing_extensions import override

from single_kernel_mongo.config.literals import (
    MAX_PASSWORD_LENGTH,
    OS_REQUIREMENTS,
    CharmKind,
    MongoPorts,
    Scope,
    Substrates,
    UnitState,
)
from single_kernel_mongo.config.models import ROLES, BackupState
from single_kernel_mongo.config.relations import ExternalRequirerRelations, RelationNames
from single_kernel_mongo.config.statuses import (
    BackupStatuses,
    CharmStatuses,
    LdapStatuses,
    MongoDBStatuses,
    MongodStatuses,
    ShardStatuses,
)
from single_kernel_mongo.core.kubernetes_upgrades import KubernetesUpgrade
from single_kernel_mongo.core.machine_upgrades import MachineUpgrade
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.secrets import generate_secret_label
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.core.version_checker import VersionChecker
from single_kernel_mongo.events.backups import (
    BackupEventsHandler,
)
from single_kernel_mongo.events.cluster import ClusterConfigServerEventHandler
from single_kernel_mongo.events.database import DatabaseEventsHandler
from single_kernel_mongo.events.ldap import LDAPEventHandler
from single_kernel_mongo.events.password_actions import PasswordActionEvents
from single_kernel_mongo.events.primary_action import PrimaryActionHandler
from single_kernel_mongo.events.sharding import (
    ConfigServerEventHandler,
    ShardEventHandler,
)
from single_kernel_mongo.events.tls import TLSEventsHandler
from single_kernel_mongo.events.upgrades import UpgradeEventHandler
from single_kernel_mongo.exceptions import (
    ContainerNotReadyError,
    EarlyRemovalOfConfigServerError,
    FailedToElectNewPrimaryError,
    InvalidConfigRoleError,
    InvalidLdapQueryTemplateError,
    InvalidLdapUserToDnMappingError,
    NonDeferrableFailedHookChecksError,
    NotDrainedError,
    SetPasswordError,
    ShardAuthError,
    ShardingMigrationError,
    UpgradeInProgressError,
    WaitingForLeaderError,
    WorkloadExecError,
    WorkloadNotReadyError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.operator_libs_linux.v0 import sysctl
from single_kernel_mongo.managers.backups import BackupManager
from single_kernel_mongo.managers.cluster import ClusterProvider
from single_kernel_mongo.managers.config import (
    LogRotateConfigManager,
    MongoDBConfigManager,
    MongoDBExporterConfigManager,
    MongosConfigManager,
)
from single_kernel_mongo.managers.ldap import LDAPManager
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.managers.observability import ObservabilityManager
from single_kernel_mongo.managers.sharding import ConfigServerManager, ShardManager
from single_kernel_mongo.managers.tls import TLSManager
from single_kernel_mongo.managers.upgrade import MongoDBUpgradeManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.helpers import (
    is_valid_ldap_options,
    is_valid_ldapusertodnmapping,
    unit_number,
)
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    LogRotateUser,
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

    name = CharmKind.MONGOD.value
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
            self.charm.unit.get_container(self.role.name)
            if self.substrate == Substrates.K8S
            else None
        )

        # Defined workloads and configs
        self.define_workloads_and_config_managers(container)

        self.cross_app_version_checker = CrossAppVersionChecker(
            self.charm,
            version=get_charm_revision(
                self.charm.unit, local_version=self.workload.get_internal_revision()
            ),
            relations_to_check=[
                RelationNames.SHARDING.value,
                RelationNames.CONFIG_SERVER.value,
            ],
        )
        self.cluster_version_checker = VersionChecker(self)

        # Managers
        self.backup_manager = BackupManager(
            self,
            self.role,
            self.substrate,
            self.state,
            container,
        )
        self.tls_manager = TLSManager(
            self,
            self.workload,
            self.state,
        )
        self.mongo_manager = MongoManager(
            self,
            self.workload,
            self.state,
            self.substrate,
        )
        self.config_server_manager = ConfigServerManager(
            self,
            self.workload,
            self.state,
            self.substrate,
            RelationNames.CONFIG_SERVER,
        )
        self.shard_manager = ShardManager(
            self,
            self.workload,
            self.state,
            self.substrate,
            RelationNames.SHARDING,
        )
        self.cluster_manager = ClusterProvider(
            self, self.state, self.substrate, RelationNames.CLUSTER
        )
        upgrade_backend = MachineUpgrade if self.substrate == Substrates.VM else KubernetesUpgrade
        self.upgrade_manager = MongoDBUpgradeManager(
            self, upgrade_backend, key=RelationNames.UPGRADE_VERSION.value
        )

        # LDAP Manager, which covers both send-ca-cert interface and ldap interface.
        self.ldap_manager = LDAPManager(
            self,
            self.state,
            self.substrate,
            ExternalRequirerRelations.LDAP,
            ExternalRequirerRelations.LDAP_CERT,
        )

        self.sysctl_config = sysctl.Config(name=self.charm.app.name)

        self.observability_manager = ObservabilityManager(self, self.state, self.substrate)

        # Event Handlers
        self.password_actions = PasswordActionEvents(self)
        self.backup_events = BackupEventsHandler(self)
        self.tls_events = TLSEventsHandler(self)
        self.primary_events = PrimaryActionHandler(self)
        self.client_events = DatabaseEventsHandler(self, RelationNames.DATABASE)
        self.upgrade_events = UpgradeEventHandler(self)
        self.config_server_events = ConfigServerEventHandler(self)
        self.sharding_event_handlers = ShardEventHandler(self)
        self.cluster_event_handlers = ClusterConfigServerEventHandler(self)
        self.ldap_events = LDAPEventHandler(self)

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
    def components(self) -> tuple[ManagerStatusProtocol, ...]:
        """The ordered list of components for this operator."""
        return (
            self,
            self.mongo_manager,
            self.shard_manager,
            self.config_server_manager,
            self.backup_manager,
            self.ldap_manager,
            self.upgrade_manager,
        )

    # BEGIN: Handlers.

    @override
    def install_workloads(self) -> None:
        """Handler on install."""
        if not self.workload.workload_present:
            raise ContainerNotReadyError

        if self.substrate == Substrates.VM:
            self._set_os_config()

        self.charm.unit.set_workload_version(self.workload.get_version())

        # Truncate the file.
        self.workload.write(self.workload.paths.config_file, "")

    def _run_startup_checks(self):
        """Runs the startup checks.

        None of those steps should fail otherwise the service is not yet allowed to start.
        """
        if not self.workload.workload_present:
            logger.debug("mongod installation is not ready yet.")
            raise ContainerNotReadyError("Mongo DB installation not ready yet")

        if any(not storage for storage in self.model.storages.values()):
            logger.debug("Storages not attached yet.")
            raise ContainerNotReadyError("Missing storage")

        if self.state.is_role(MongoDBRoles.UNKNOWN):
            raise InvalidConfigRoleError()

    @override
    def prepare_for_startup(self) -> None:
        """Handler on start."""
        # Ensure we're allowed to run.
        try:
            self._run_startup_checks()
        except InvalidConfigRoleError:
            if self.charm.unit.is_leader():
                self.state.statuses.add(
                    MongoDBStatuses.INVALID_ROLE.value,
                    scope="app",
                    component=self.name,
                )
                raise

        if self.charm.unit.is_leader():
            self.state.statuses.clear(scope="app", component=self.name)

        # Configure the workload. This requires a valid role!
        # In the _run_startup_checks method, we ensure that we have a valid role before
        # allowing that event to run.
        self._configure_workloads()

        logger.info("Starting MongoDB.")
        self.charm.status_handler.set_running_status(
            MongoDBStatuses.STARTING_MONGODB.value, scope="unit"
        )

        for attempt in Retrying(
            stop=stop_after_attempt(5),
            wait=wait_fixed(5),
            reraise=True,
        ):
            with attempt:
                self.start_charm_services()
                self.open_ports()

        # This seems unnecessary
        # if self.substrate == Substrates.K8S:
        #    if not self.workload.exists(self.workload.paths.socket_path):
        #        logger.debug("The mongod socket is not ready yet.")
        #        raise WorkloadNotReadyError

        if not self.mongo_manager.mongod_ready():
            raise WorkloadNotReadyError

        self.state.statuses.set(CharmStatuses.ACTIVE_IDLE.value, scope="unit", component=self.name)

        try:
            self._initialise_replica_set()
        except (NotReadyError, PyMongoError, WorkloadExecError) as e:
            logger.error(f"Deferring on start: error={e}")
            self.state.statuses.add(
                MongodStatuses.WAITING_REPL_SET_INIT.value, scope="unit", component=self.name
            )
            raise

        try:
            self._restart_related_services()
        except WorkloadServiceError:
            logger.error("Could not restart the related services.")
            return

        self.state.statuses.set(CharmStatuses.ACTIVE_IDLE.value, scope="unit", component=self.name)

        if self.substrate == Substrates.K8S:
            # K8S upgrades result in the start hook getting fired following this pattern
            # https://juju.is/docs/sdk/upgrade-charm-event#heading--emission-sequence
            self.upgrade_manager._reconcile_upgrade()

    @override
    def prepare_for_shutdown(self) -> None:  # pragma: nocover
        """Handler for the stop event.

        On VM:
         * Remove the overrides files.
        On K8S:
         * First: Raise partition to prevent other units from restarting if an
         upgrade is in progress. If an upgrade is not in progress, the leader
         unit will reset the partition to 0.
         * Second: Sets the unit state to RESTARTING and step down from replicaset.

        Note that with how Juju currently operates, we only have at most 30
        seconds until SIGTERM command, so we are by no means guaranteed to have
        stepped down before the pod is removed.
        Upon restart, the upgrade will still resume because all hooks run the
        `_reconcile_upgrade` handler.
        """
        if self.substrate == Substrates.VM:
            self.remove_systemd_overrides()
            return

        # Raise partition to prevent other units from restarting if an upgrade is in progress.
        # If an upgrade is not in progress, the leader unit will reset the partition to 0.
        current_unit_number = unit_number(self.state.unit_upgrade_peer_data)
        if self.state.k8s_manager.get_partition() < current_unit_number:
            self.state.k8s_manager.set_partition(value=current_unit_number)
            logger.debug(f"Partition set to {current_unit_number} during stop event")

        if not self.upgrade_manager._upgrade:
            logger.debug("Upgrade Peer relation missing during stop event")
            return

        # We update the state to set up the unit as restarting
        self.upgrade_manager._upgrade.unit_state = UnitState.RESTARTING

        # According to the MongoDB documentation, before upgrading the primary, we must ensure a
        # safe primary re-election.
        try:
            if self.charm.unit.name == self.primary_unit_name:
                logger.debug("Stepping down current primary, before upgrading service...")
                self.upgrade_manager.step_down_primary_and_wait_reelection()
        except FailedToElectNewPrimaryError:
            logger.error("Failed to reelect primary before upgrading unit.")
            return

    @override
    def update_config_and_restart(self) -> None:
        """Listen to changes in application configuration.

        To prevent a user from migrating a cluster, and causing the component to become
        unresponsive therefore causing a cluster failure, error the component. This prevents it
        from executing other hooks with a new role.
        """
        if self.state.is_role(MongoDBRoles.UNKNOWN):  # We haven't run the leader elected event yet.
            logger.info("We haven't elected a leader yet.")
            raise WaitingForLeaderError

        if not is_valid_ldapusertodnmapping(self.config.ldap_user_to_dn_mapping):
            logger.error("Invalid LDAP Config - Please refer to the config option description.")
            raise InvalidLdapUserToDnMappingError(
                "Invalid LdapUserToDnMapping, please update your config."
            )

        if not is_valid_ldap_options(
            self.config.ldap_user_to_dn_mapping, self.config.ldap_query_template
        ):
            logger.info("Invalid LDAP Config - Please refer to the config option description.")
            raise InvalidLdapQueryTemplateError(
                "Invalid LDAP Query template, please update your config."
            )

        if self.state.upgrade_in_progress:
            logger.warning(
                "Changing config options is not permitted during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            raise UpgradeInProgressError

        if self.config.role == MongoDBRoles.INVALID:
            logger.error(
                f"Invalid role config - Please revert the config role to {self.state.app_peer_data.role}"
            )
            raise InvalidConfigRoleError("Invalid role")

        if not self.state.is_role(self.config.role):
            logger.error(
                f"cluster migration currently not supported, cannot change from {self.state.app_peer_data.role} to {self.config.role}"
            )
            raise ShardingMigrationError(
                f"Migration of sharding components not permitted, revert config role to {self.state.app_peer_data.role}"
            )

        if self.charm.unit.is_leader():
            self._handle_ldap_config_changes()

    def _handle_ldap_config_changes(self):
        """Helpful method to handle the ldap changes and a restart if necessary."""
        # Store in the databag so we never miss it.
        if self.config.ldap_user_to_dn_mapping:
            self.state.ldap.ldap_user_to_dn_mapping = self.config.ldap_user_to_dn_mapping
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.cluster_manager.update_ldap_user_to_dn_mapping()

        if self.config.ldap_query_template:
            self.state.ldap.ldap_query_template = self.config.ldap_query_template

        # This will restart only if the config was changed.
        self.ldap_events.restart_if_ready_event.emit()

    @override
    def new_leader(self) -> None:
        """Handles the leader elected event.

        Generates the keyfile and users credentials.
        """
        if not self.state.get_keyfile():
            self.state.set_keyfile(self.workload.generate_keyfile())

        # Sets the password for the system users
        for user in (OperatorUser, BackupUser, MonitorUser, LogRotateUser):
            if not self.state.get_user_password(user):
                self.state.set_user_password(user, self.workload.generate_password())

    @override
    def new_peer(self) -> None:
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

        self.peer_changed()
        self.update_related_hosts()

    def peer_changed(self) -> None:
        """Handle relation changed events.

        Adds the unit as a replica to the MongoDB replica set.
        """
        if self.substrate == Substrates.K8S:
            # K8S Upgrades requires to reconcile the upgrade on lifecycle event.
            self.upgrade_manager._reconcile_upgrade()

        # Changing the monitor or the backup password will lead to non-leader
        # units receiving a relation changed event. We must update the monitor
        # and pbm URI if the password changes so that COS/pbm can continue to
        # work.
        if self.state.db_initialised and self.workload.active():
            self.mongodb_exporter_config_manager.configure_and_restart()
            self.backup_manager.configure_and_restart()

        # only leader should configure replica set and we should do it only if
        # the replica set is initialised.
        if not self.charm.unit.is_leader() or not self.state.db_initialised:
            return

        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding replicas during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
            raise UpgradeInProgressError

        try:
            # Adds the newly added/updated units.
            self.mongo_manager.process_added_units()
        except (NotReadyError, PyMongoError) as e:
            logger.error(f"Not reconfiguring: error={e}")
            self.state.statuses.add(
                MongodStatuses.WAITING_RECONFIG.value, scope="unit", component=self.name
            )
            raise

    @override
    def update_secrets_and_restart(self, secret_label: str, secret_id: str) -> None:
        """Handles secrets changes event.

        When user run set-password action, juju leader changes the password inside the database
        and inside the secret object. This action runs the restart for monitoring tool and
        for backup tool on non-leader units to keep them working with MongoDB. The same workflow
        occurs on TLS certs change.
        """
        if generate_secret_label(self.charm.app.name, Scope.APP) == secret_label:
            scope = Scope.APP
        elif generate_secret_label(self.charm.app.name, Scope.UNIT) == secret_label:
            scope = Scope.UNIT
        else:
            logging.debug("Secret %s changed, but it's unknown", secret_id)
            return
        logging.debug("Secret %s for scope %s changed, refreshing", secret_id, scope)
        self.state.secrets.get(scope)

        # Always update the PBM and mongodb exporter configuration so that if
        # the secret changed, the configuration is updated and will still work
        # afterwards.
        if self.workload.active():
            self.mongodb_exporter_config_manager.configure_and_restart()
            self.backup_manager.configure_and_restart()

        # Always process the statuses.

    @override
    def peer_leaving(self, departing_unit: Unit | None) -> None:
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
    def prepare_storage(self) -> None:  # pragma: nocover
        """Handler for `storage_attached` event.

        This should handle fixing the permissions for the data dir.
        """
        if self.substrate == Substrates.K8S:
            return

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
    def prepare_storage_for_shutdown(self) -> None:
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
        if self.is_removing_last_replica:
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER) and self.state.config_server_relation:
                current_shards = [
                    relation.app.name for relation in self.state.config_server_relation
                ]
                early_removal_message = f"Cannot remove config-server, still related to shards {', '.join(current_shards)}"
                logger.error(early_removal_message)
                raise EarlyRemovalOfConfigServerError(early_removal_message)
            if self.state.is_role(MongoDBRoles.SHARD) and self.state.shard_relation is not None:
                logger.info("Wait for shard to drain before detaching storage.")
                self.charm.status_handler.set_running_status(
                    ShardStatuses.DRAINING_SHARD.value, scope="unit"
                )
                mongos_hosts = self.state.shard_state.mongos_hosts
                self.shard_manager.wait_for_draining(mongos_hosts)
                logger.info("Shard successfully drained storage.")
            return

        try:
            # retries over a period of 10 minutes in an attempt to resolve race conditions it is
            # not possible to defer in storage detached.
            logger.debug(
                "Removing %s from replica set",
                self.state.unit_peer_data.internal_address,
            )
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
            logger.error(
                "Failed to remove %s from replica set, error=%r",
                self.charm.unit.name,
                e,
            )

    @override
    def update_status(self) -> None:
        """Status update Handler."""
        # TODO update the usage of this once the spec is approved and we have a consistent way of
        # handling statuses
        if self.basic_statuses():
            logger.info("Early return invalid statuses.")
            return

        if self.state.is_role(MongoDBRoles.SHARD):
            shard_has_tls, config_server_has_tls = self.shard_manager.tls_status()
            if config_server_has_tls and not shard_has_tls:
                logger.info("Shard is missing TLS.")
                return

        if not self.mongo_manager.mongod_ready():
            logger.info("Mongod not ready.")
            return

        if self.substrate == Substrates.K8S:
            self.upgrade_manager._reconcile_upgrade()

        # It's useless to try to perform self healing if upgrade is in progress
        # as the handlers would raise an UpgradeInProgressError anyway so
        # better skip it when possible.
        if not self.state.upgrade_in_progress:
            try:
                self.perform_self_healing()
            except (ServerSelectionTimeoutError, OperationFailure) as e:
                logger.warning(f"Failed to perform self healing: {e}")
            except ShardAuthError:
                logger.warning("Failed to add shard")
            except NotDrainedError:
                logger.warning("Still draining shard.")

    def set_password(self, username: str, password: str | None = None) -> tuple[str, str]:
        """Handler for the set password action."""
        self.assert_pass_password_checks()

        user = get_user_from_username(username)
        new_password = password or self.workload.generate_password()
        if len(new_password) > MAX_PASSWORD_LENGTH:
            raise SetPasswordError(
                f"Password cannot be longer than {MAX_PASSWORD_LENGTH} characters."
            )

        secret_id = self.mongo_manager.set_user_password(user, new_password)
        if user == BackupUser:
            # Update and restart PBM Agent.
            self.backup_manager.configure_and_restart()
        if user == MonitorUser:
            # Update and restart mongodb exporter.
            self.mongodb_exporter_config_manager.configure_and_restart()
        if user == LogRotateUser:
            # Update and restart logrotate.
            self.logrotate_config_manager.configure_and_restart()
        if user in (OperatorUser, BackupUser) and self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            self.config_server_manager.update_credentials(
                user.password_key_name,
                new_password,
            )

        return new_password, secret_id

    # END: Handlers.

    def assert_pass_password_checks(self) -> None:
        """Sanity checks to run before password changes."""
        if not self.model.unit.is_leader():
            raise NonDeferrableFailedHookChecksError(
                "Password rotation must be called on leader unit."
            )
        if self.state.upgrade_in_progress:
            raise NonDeferrableFailedHookChecksError(
                "Cannot set passwords while an upgrade is in progress"
            )
        if self.state.is_role(MongoDBRoles.SHARD):
            raise NonDeferrableFailedHookChecksError(
                "Cannot set password on shard, please set password on config-server."
            )
        pbm_status = self.backup_manager.backup_state()
        if pbm_status in (BackupState.BACKUP_RUNNING, BackupState.RESTORE_RUNNING):
            raise NonDeferrableFailedHookChecksError(
                "Cannot change a password while a backup/restore is in progress."
            )

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
        # All nodes should restart PBM and MongoDBExporter if it's not running
        if self.workload.active():
            self.mongodb_exporter_config_manager.configure_and_restart()
            self.backup_manager.configure_and_restart()

        if not self.charm.unit.is_leader():
            logger.debug("Only the leader can perform reconfigurations to the replica set.")
            return

        # remove any IPs that are no longer juju hosts & update app data.
        self.update_hosts()
        # Add in any new IPs to the replica set. Relation handlers require a reference to
        # a unit.
        self.peer_changed()

        # make sure all nodes in the replica set have the same priority for re-election. This is
        # necessary in the case that pre-upgrade hook fails to reset the priority of election for
        # cluster nodes.
        self.mongo_manager.set_election_priority(priority=1)

    def update_hosts(self) -> None:
        """Update the replica set hosts and remove any unremoved replica from the config."""
        if not self.state.db_initialised:
            return
        self.mongo_manager.process_unremoved_units()
        self.update_related_hosts()

    def update_related_hosts(self) -> None:
        """Update the app relations that need to be made aware of the new set of hosts."""
        if self.state.is_role(MongoDBRoles.REPLICATION):
            for relation in self.state.client_relations:
                self.mongo_manager.update_app_relation_data(relation)
            return

        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            # Update the mongos host in the sharded deployment
            self.config_server_manager.update_mongos_hosts()
            # Try to add shards that failed to add earlier
            self.config_server_manager.add_shards()
            # Try to remove shards so it goes on getting processed.
            self.config_server_manager.remove_shards()
            # Update the config server DB URI on the remote mongos
            self.cluster_manager.update_config_server_db()

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

    def _set_os_config(self) -> None:
        """Sets sysctl config for mongodb."""
        try:
            self.sysctl_config.configure(OS_REQUIREMENTS)
        except (sysctl.ApplyError, sysctl.ValidationError, sysctl.CommandError) as e:
            # we allow events to continue in the case that we are not able to correctly configure
            # sysctl config, since we can  still run the workload with wrong sysctl parameters
            # even if it is not optimal.
            logger.error(f"Error setting values on sysctl: {e.message}")
            # containers share the kernel with the host system, and some sysctl parameters are
            # set at kernel level.
            logger.warning("sysctl params cannot be set. Is the machine running on a container?")

    @property
    def primary_unit_name(self) -> str | None:
        """Retrieves the primary unit with the primary replica."""
        with MongoConnection(self.state.mongo_config) as connection:
            try:
                primary_ip = connection.primary()
            except Exception as e:
                logger.error(f"Unable to get primary: {e}")
                return None

        for unit in self.state.units:
            if primary_ip == unit.internal_address:
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
    def restart_charm_services(self, force: bool = False):
        """Restarts the charm services with updated config.

        If we are running as config-server, we should update both mongod and mongos environments.
        """
        try:
            self.config_manager.configure_and_restart(force=force)
            if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
                self.mongos_config_manager.configure_and_restart(force=force)
        except WorkloadServiceError as e:
            logger.error("An exception occurred when starting mongod agent, error: %s.", str(e))
            self.charm.state.statuses.add(
                MongoDBStatuses.WAITING_FOR_MONGODB_START.value, scope="unit", component=self.name
            )
            raise

    def _restart_related_services(self) -> None:
        """Restarts mongodb exporter and backup manager."""
        try:
            self.mongodb_exporter_config_manager.configure_and_restart()
        except WorkloadServiceError:
            self.state.statuses.add(
                MongoDBStatuses.WAITING_FOR_EXPORTER_START.value,
                scope="unit",
                component=self.name,
            )
            raise

        try:
            self.backup_manager.configure_and_restart()
        except WorkloadServiceError:
            self.state.statuses.add(
                BackupStatuses.WAITING_FOR_PBM_START.value, scope="unit", component=self.name
            )
            raise

        self.logrotate_config_manager.configure_and_restart()

    @override
    def get_relation_feasible_status(self, rel_name: str) -> StatusObject | None:
        """Checks if the relation is feasible in the current context.

        Invalid relations are such:
         * any sharding component on the database endpoint.
         * shard on the config-server endpoints.
         * config-server on the shard endpoint.
         * database on sharding endpoints.

        TODO: in the future expand this to a handle other non-feasible
        relations (i.e. mongos-shard, shard-s3)

        """
        if self.state.is_sharding_component and rel_name == RelationNames.DATABASE:
            logger.error(
                "Charm is in sharding role: %s. Does not support %s interface.",
                self.state.app_peer_data.role,
                rel_name,
            )
            return MongoDBStatuses.INVALID_DB_REL.value
        if not self.state.is_sharding_component and rel_name in {
            RelationNames.SHARDING,
            RelationNames.CONFIG_SERVER,
        }:
            logger.error(
                "Charm is in replication role: %s. Does not support %s interface.",
                self.state.app_peer_data.role,
                rel_name,
            )
            return MongoDBStatuses.INVALID_SHARDING_REL.value
        if self.state.is_role(MongoDBRoles.SHARD) and rel_name == RelationNames.CONFIG_SERVER:
            logger.error("Charm is in sharding mode. Does not support %s interface.", rel_name)
            return MongoDBStatuses.INVALID_CFG_SRV_ON_SHARD_REL.value
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER) and rel_name == RelationNames.SHARDING:
            logger.error("Charm is in config-server mode. Does not support %s interface.", rel_name)
            return MongoDBStatuses.INVALID_SHARD_ON_CFG_SRV_REL.value
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER) and rel_name == RelationNames.CLUSTER:
            logger.error("Charm is not a config-server, cannot integrate mongos")
            return MongoDBStatuses.INVALID_MONGOS_REL.value
        return None

    def _configure_workloads(self) -> None:
        """Handle filesystem interactions for charm configuration."""
        # Configure the workloads
        self.config_manager.set_environment()
        self.mongos_config_manager.set_environment()

        # Instantiate the keyfile
        self.instantiate_keyfile()

        # Push TLS files if necessary
        self.tls_manager.push_tls_files_to_workload()
        self.ldap_manager.save_certificates(self.state.ldap.chain)

        # Setup systemd overrides to prevent mongos/mongodb from cutting connections
        self.setup_systemd_overrides()

        # Update licenses
        self.handle_licenses()

        # Sets directory permissions
        self.set_permissions()

    def instantiate_keyfile(self):
        """Instantiate the keyfile."""
        if not (keyfile := self.state.get_keyfile()):
            raise Exception("Waiting for leader unit to generate keyfile contents")

        self.workload.write(self.workload.paths.keyfile, keyfile)

    def _initialise_replica_set(self):
        """Helpful method to initialise the replica set and the users.

        This is executed only by the leader.
        This function first initialises the replica set, and then the three charm users.
        Finally, if there are any integrated clients (direct clients in the
        case of replication, or mongos clients in case of config-server),
        oversee the relation to create the associated users.
        At the very end, it sets the `db_initialised` flag to True.
        """
        if self.state.db_initialised:
            # The replica set should be initialised only once. Check should be
            # external (e.g., check initialisation inside peer relation). We
            # shouldn't rely on MongoDB response because the data directory
            # can be corrupted.
            return
        if not self.model.unit.is_leader():
            return
        self.mongo_manager.initialise_replica_set()
        self.mongo_manager.initialise_charm_admin_users()
        logger.info("Manage client relation users")
        if self.state.is_role(MongoDBRoles.REPLICATION):
            for relation in self.state.client_relations:
                self.mongo_manager.reconcile_mongo_users_and_dbs(relation)
        elif self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            for relation in self.state.cluster_relations:
                self.mongo_manager.reconcile_mongo_users_and_dbs(relation)

        self.state.app_peer_data.db_initialised = True

    @property
    def is_removing_last_replica(self) -> bool:
        """Returns True if the last replica (juju unit) is getting removed."""
        return self.state.planned_units == 0 and len(self.state.peers_units) == 0

    def basic_statuses(self) -> list[StatusObject]:
        """Basic checks."""
        statuses = []
        if not self.backup_manager.is_valid_s3_integration():
            statuses.append(MongoDBStatuses.INVALID_S3_REL.value)
        # Add valid statuses for all invalid integrated relations
        for relation_name in [
            RelationNames.DATABASE,
            RelationNames.SHARDING,
            RelationNames.CONFIG_SERVER,
            RelationNames.CLUSTER,
        ]:
            if (
                self.model.relations[relation_name.value]
                and (status := self.get_relation_feasible_status(relation_name)) is not None
            ):
                statuses.append(status)

        if not self.state.is_sharding_component and self.state.has_sharding_integration:
            # don't bother checking revision mismatch on sharding interface if replica
            return statuses

        if rev_status := self.cluster_version_checker.get_cluster_mismatched_revision_status():
            statuses.append(rev_status)

        return statuses

    def get_statuses(self, scope: DPHScope, recompute: bool = False) -> list[StatusObject]:  # noqa: C901 # We know, this function is complex.
        """Returns the statuses of the charm manager."""
        charm_statuses: list[StatusObject] = []

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if scope == "unit" and not self.workload.workload_present:
            return [CharmStatuses.MONGODB_NOT_INSTALLED.value]

        if self.config.role == MongoDBRoles.INVALID:
            charm_statuses.append(MongoDBStatuses.INVALID_ROLE.value)

        if not is_valid_ldapusertodnmapping(self.config.ldap_user_to_dn_mapping):
            logger.error("Invalid LDAP Config - Please refer to the config option description.")
            charm_statuses.append(LdapStatuses.INVALID_LDAP_USER_MAPPING.value)

        if not is_valid_ldap_options(
            self.config.ldap_user_to_dn_mapping, self.config.ldap_query_template
        ):
            logger.info("Invalid LDAP Config - Please refer to the config option description.")
            charm_statuses.append(LdapStatuses.INVALID_LDAP_QUERY_TEMPLATE.value)

        charm_statuses += self.basic_statuses()

        if scope == "app":
            return charm_statuses

        if not self.state.db_initialised:
            charm_statuses.append(MongoDBStatuses.WAITING_FOR_MONGODB_START.value)

        if not self.mongodb_exporter_config_manager.workload.active():
            charm_statuses.append(MongoDBStatuses.WAITING_FOR_EXPORTER_START.value)

        # PBM does not start until the shard is integrated with a config-server
        # So if we're everything BUT a shard or not added to cluster, let's check PBM as well
        if not self.state.is_role(MongoDBRoles.SHARD) or self.state.is_shard_added_to_cluster():
            if not self.backup_manager.workload.active():
                charm_statuses.append(BackupStatuses.WAITING_FOR_PBM_START.value)

        return charm_statuses
