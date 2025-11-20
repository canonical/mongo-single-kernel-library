# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class, we implement managers for config-servers and shards.

This class handles the sharing of secrets between sharded components, adding shards, and removing
shards.
"""

from __future__ import annotations

import json
import time
from logging import getLogger
from typing import TYPE_CHECKING

from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object
from ops.model import (
    Relation,
)
from pymongo.errors import (
    NotPrimaryError,
    OperationFailure,
    PyMongoError,
    ServerSelectionTimeoutError,
)
from tenacity import Retrying, stop_after_delay, wait_fixed

from single_kernel_mongo.config.literals import (
    TRUST_STORE_PATH,
    MongoPorts,
    Substrates,
    TrustStoreFiles,
)
from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import (
    ConfigServerStatuses,
    ShardStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    BalancerNotEnabledError,
    DeferrableFailedHookChecksError,
    FailedToUpdateCredentialsError,
    NonDeferrableFailedHookChecksError,
    NotDrainedError,
    RemoveLastShardError,
    ShardAuthError,
    ShardNotInClusterError,
    ShardNotPlannedForRemovalError,
    WaitingForCertificatesError,
    WaitingForSecretsError,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.config_server_state import AppShardingComponentKeys
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    OperatorUser,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = getLogger(__name__)


class ConfigServerManager(Object, ManagerStatusProtocol):
    """Manage relations between the config server and the shard, on the config-server's side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.CONFIG_SERVER,
    ):
        self.name = relation_name.value
        super().__init__(parent=dependent, key=self.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = self.state.config_server_data_interface

    def prepare_sharding_config(self, relation: Relation) -> None:
        """Handles the database requested event.

        It shares the different credentials and necessary files with the shard.
        """
        self.assert_pass_hook_checks(relation)

        if self.data_interface.fetch_relation_field(relation.id, "requested-secrets") is None:
            raise DeferrableFailedHookChecksError(
                f"Database Requested event has not run yet for relation {relation.id}"
            )
        relation_data = {
            AppShardingComponentKeys.OPERATOR_PASSWORD.value: self.state.get_user_password(
                OperatorUser
            ),
            AppShardingComponentKeys.BACKUP_PASSWORD.value: self.state.get_user_password(
                BackupUser
            ),
            AppShardingComponentKeys.KEY_FILE.value: self.state.get_keyfile(),
            AppShardingComponentKeys.HOST.value: json.dumps(sorted(self.state.internal_hosts)),
        }

        if self.state.s3_relation:
            credentials = self.dependent.backup_events.s3_client.get_s3_connection_info()
            if cert_chain_list := credentials.get("tls-ca-chain", None):
                relation_data[AppShardingComponentKeys.BACKUP_CA_SECRET.value] = json.dumps(
                    cert_chain_list
                )

        if int_tls_ca := self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL):
            relation_data[AppShardingComponentKeys.INT_CA_SECRET.value] = int_tls_ca

        self.data_interface.update_relation_data(relation.id, relation_data)
        self.data_interface.set_credentials(
            relation.id, "unused", "unused"
        )  # Triggers the database created event

    def reconcile_shards_for_relation(self, relation: Relation, is_leaving: bool = False) -> None:
        """Handles adding and removing shards.

        Updating of shards is done automatically via MongoDB change-streams.
        """
        self.assert_pass_hook_checks(relation, is_leaving)

        if self.data_interface.fetch_relation_field(relation.id, "requested-secrets") is None:
            logger.info("Waiting for secrets requested")
            return

        if not self.data_interface.fetch_relation_field(relation.id, "auth-updated") == "true":
            logger.info(f"Waiting for shard {relation.app.name} to update its authentication")
            return

        try:
            logger.info("Adding/Removing shards not present in cluster.")
            if is_leaving:
                self.remove_shard_from_relation(relation)
            else:
                self.add_shard(relation)
        except NotDrainedError:
            # it is necessary to removeShard multiple times for the shard to be removed.
            logger.info(
                "Shard is still present in the cluster after removal, will remove again during update status events."
            )
        except OperationFailure as e:
            if e.code == MongoErrorCodes.ILLEGAL_OPERATION:
                # TODO Future PR, allow removal of last shards that have no data. This will be
                # tricky since we are not allowed to update the mongos config in this way.
                logger.error(
                    "Cannot not remove the last shard from cluster, this is forbidden by mongos."
                )
                # we should not lose connection with the shard, prevent other hooks from executing.
                raise RemoveLastShardError

            logger.error("Deferring _on_relation_event for shards interface since: error=%r", e)
            raise
        except (PyMongoError, NotReadyError, BalancerNotEnabledError) as e:
            logger.error(f"Deferring _on_relation_event for shards interface since: error={e}")
            raise

    def assert_pass_sanity_hook_checks(self) -> None:
        """Runs some sanity hook checks.

        Raises:
            NonDeferrableFailedHookChecksError, DeferrableFailedHookChecksError
        """
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            raise NonDeferrableFailedHookChecksError("is only executed by config-server")
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("db is not initialised.")
        if status := self.dependent.get_relation_feasible_status(self.relation_name):
            self.dependent.state.statuses.add(status, scope="unit", component=self.dependent.name)
            raise NonDeferrableFailedHookChecksError("relation is not feasible")
        if not self.charm.unit.is_leader():
            raise NonDeferrableFailedHookChecksError

        # Note: we permit this logic based on status since we aren't checking
        # self.charm.unit.status`, instead `get_cluster_mismatched_revision_status` directly
        # computes the revision check.
        if (
            rev_status
            := self.dependent.cluster_version_checker.get_cluster_mismatched_revision_status()
        ):
            self.state.statuses.add(rev_status, scope="unit", component=self.dependent.name)
            raise DeferrableFailedHookChecksError("Mismatched versions in the cluster")

    def assert_pass_hook_checks(self, relation: Relation, leaving: bool = False) -> None:
        """Runs pre hooks checks and raises the appropriate error if it fails.

        Raises:
            NonDeferrableFailedHookChecksError, DeferrableFailedHookChecksError
        """
        self.assert_pass_sanity_hook_checks()

        pbm_status = self.dependent.backup_manager.backup_state()

        if pbm_status in (BackupState.BACKUP_RUNNING, BackupState.RESTORE_RUNNING):
            raise DeferrableFailedHookChecksError(
                "Cannot add/remove shards while a backup/restore is in progress."
            )

        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding/Removing shards is not supported during an upgrade. The charm may be in a broken, unrecoverable state"
            )
            if not leaving:
                raise DeferrableFailedHookChecksError("Upgrade is in progress")
        if leaving:
            if not self.state.has_departed_run(relation.id):
                raise DeferrableFailedHookChecksError(
                    "must wait for relation departed hook to decide if relation should be removed"
                )
            self.dependent.assert_proceed_on_broken_event(relation)

    def update_credentials(self, key: str, value: str) -> None:
        """Sends new credentials for a new key value pair across all shards."""
        for relation in self.state.config_server_relation:
            if self.data_interface.fetch_relation_field(relation.id, "requested-secrets") is None:
                logger.info(f"Database Requested event has not run yet for relation {relation.id}")
                continue
            self.data_interface.update_relation_data(relation.id, {key: value})

    def update_mongos_hosts(self) -> None:
        """Updates the hosts for mongos on the relation data."""
        for relation in self.state.config_server_relation:
            if self.data_interface.fetch_relation_field(relation.id, "requested-secrets") is None:
                logger.info(f"Database Requested event has not run yet for relation {relation.id}")
                continue
            self.data_interface.update_relation_data(
                relation.id,
                {
                    AppShardingComponentKeys.HOST.value: json.dumps(
                        sorted(self.state.internal_hosts)
                    )
                },
            )

    def skip_config_server_status(self) -> bool:
        """Returns true if the status check should be skipped."""
        if self.state.is_role(MongoDBRoles.SHARD):
            logger.info("skipping config server status check, charm is running as a shard")
            return True

        if not self.state.db_initialised:
            logger.info("No status for shard to report, waiting for db to be initialised.")
            return True

        if self.state.is_role(MongoDBRoles.REPLICATION) and not self.state.config_server_relation:
            return True

        if self.state.is_role(MongoDBRoles.REPLICATION) and self.state.config_server_relation:
            logger.error("Cannot operate as a config-server when deployed as a bare replica set")
            return True

        if self.state.client_relations:
            logger.error("Cannot operate as a config-server when deployed as a bare replica set")
            return True

        return False

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:  # noqa: C901
        """Returns the current status of the config-server."""
        charm_statuses: dict[Scope, list[StatusObject]] = {"app": [], "unit": []}

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if scope == "app":
            return []

        if self.skip_config_server_status():
            return charm_statuses[scope]

        if self.dependent.cluster_version_checker.get_cluster_mismatched_revision_status():
            return charm_statuses[scope]

        uri = f"mongodb://{self.state.unit_peer_data.internal_address}:{MongoPorts.MONGOS_PORT}"
        if not self.dependent.mongo_manager.mongod_ready(uri):
            charm_statuses["unit"].append(ConfigServerStatuses.MONGOS_NOT_RUNNING.value)

        if not self.state.config_server_relation:
            charm_statuses["unit"].append(ConfigServerStatuses.MISSING_CONF_SERVER_REL.value)
            charm_statuses["app"].append(ConfigServerStatuses.MISSING_CONF_SERVER_REL.value)
            # return as other statuses require shard(s) to compute
            return charm_statuses[scope]

        if not self.cluster_password_synced():
            charm_statuses["unit"].append(ConfigServerStatuses.SYNCING_PASSWORDS.value)

        try:
            with MongoConnection(self.state.mongos_config) as mongo:
                cluster_shards = mongo.get_shard_members()

            relation_shards = {relation.app.name for relation in self.state.config_server_relation}
            if shard_draining := (cluster_shards - relation_shards):
                draining = ",".join(shard_draining)
                status = ConfigServerStatuses.draining_shard(draining)
                charm_statuses["unit"].append(status)
                charm_statuses["app"].append(status)

            if unreachable_shards := self.get_unreachable_shards():
                charm_statuses["unit"].append(
                    ConfigServerStatuses.unreachable_shards(unreachable_shards)
                )
        except (ServerSelectionTimeoutError, OperationFailure):
            return []

        return (
            charm_statuses[scope]
            if charm_statuses[scope]
            else [ConfigServerStatuses.ACTIVE_IDLE.value]
        )

    def add_shards(self):
        """Add shards on all relations."""
        with MongoConnection(self.state.mongos_config) as mongo:
            cluster_shards = mongo.get_shard_members()
        for relation in self.state.config_server_relation:
            if relation.app.name not in cluster_shards:
                self.add_shard(relation)

    def add_shard(self, relation: Relation) -> None:
        """Adds a shard to the cluster."""
        shard_name = relation.app.name

        hosts = []
        for unit in relation.units:
            unit_state = self.state.unit_peer_data_for(unit, relation)
            hosts.append(unit_state.internal_address)
        if not len(hosts):
            logger.info(f"host info for shard {shard_name} not yet added, skipping")
            return

        self.state.statuses.delete(
            ConfigServerStatuses.MISSING_CONF_SERVER_REL.value, scope="unit", component=self.name
        )

        self.charm.status_handler.set_running_status(
            ConfigServerStatuses.adding_shard(shard_name), scope="unit"
        )

        with MongoConnection(self.state.mongos_config) as mongo:
            try:
                mongo.add_shard(shard_name, hosts)
            except OperationFailure as e:
                if e.code == MongoErrorCodes.AUTHENTICATION_FAILED:
                    logger.error(
                        f"{shard_name} shard does not have the same auth as the config server."
                    )
                    raise ShardAuthError(shard_name)
                logger.warning(f"Unhandled Operation Error {e.code}: {e}")
                raise
            except PyMongoError as e:
                logger.error(f"Failed to add {shard_name} to cluster")
                raise e

    def remove_shards(self) -> None:
        """During update-status, remove shards until they are removed completely.

        Attempts to remove shards from the sharded cluster that weren't removed
        during the relation-broken event.

        This is necessary, because removing a shard requires it to be drained
        (which takes a long time) and the remove-shard command sometimes needs
        to be ran several times (mongodb specific). We do not want to block the
        config-server from running additional operations. Furthermore we cannot
        defer relation-broken events.
        """
        with MongoConnection(self.state.mongos_config) as mongo:
            cluster_shards = mongo.get_shard_members()

        relation_shards = {relation.app.name for relation in self.state.config_server_relation}

        for shard_name in cluster_shards - relation_shards:
            try:
                logger.info(f"Attempting to remove shard: {shard_name}")
                self.remove_shard(shard_name)
            except NotReadyError:
                logger.info(f"Unable to remove shard: {shard_name}, another shard is draining")
            except ShardNotInClusterError:
                logger.info(
                    "Shard to remove is not in sharded cluster. It has been successfully removed."
                )

    def remove_shard_from_relation(self, relation: Relation) -> None:
        """Removes a shard from the cluster."""
        shard_name = relation.app.name

        self.remove_shard(shard_name)

    def remove_shard(self, shard_name: str) -> None:
        """Actually removes a shard based on the shard name."""
        with MongoConnection(self.state.mongos_config) as mongo:
            try:
                self.charm.status_handler.set_running_status(
                    ConfigServerStatuses.draining_shard(shard_name),
                    scope="unit",
                    statuses_state=self.state.statuses,
                    component_name=self.name,
                )
                logger.info("Attempting to removing shard: %s", shard_name)
                mongo.pre_remove_shard_checks(shard_name)
                mongo.remove_shard(shard_name)
                mongo.move_primary_after_draining_shard(shard_name)
            except NotReadyError:
                logger.info("Unable to remove shard: %s another shard is draining", shard_name)
                # to guarantee that shard that the currently draining shard, gets re-processed,
                # do not raise immediately, instead at the end of removal processing.
                raise
            except ShardNotInClusterError:
                logger.info(
                    "Shard to remove is not in sharded cluster. It has been successfully removed."
                )

    def cluster_password_synced(self) -> bool:
        """Returns True if the cluster password is synced."""
        # base case: not config-server
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return True

        try:
            # check our ability to use connect to mongos
            with MongoConnection(self.state.mongos_config) as mongos:
                mongos.get_shard_members()
            # check our ability to use connect to mongod
            with MongoConnection(self.state.mongo_config) as mongod:
                mongod.get_replset_status()
        except OperationFailure as e:
            if e.code in (
                MongoErrorCodes.UNAUTHORIZED,
                MongoErrorCodes.AUTHENTICATION_FAILED,
            ):
                return False
            logger.error(f"Invalid operation failure when checking if cluster password synced: {e}")
            raise
        except ServerSelectionTimeoutError:
            # Connection refused, - this occurs when internal membership is not in sync across the
            # cluster (i.e. TLS + KeyFile).
            return False

        return True

    def get_unreachable_shards(self) -> list[str]:
        """Returns a list of unreable shard hosts."""
        unreachable_hosts: list[str] = []
        if not self.state.config_server_relation:
            logger.info("shards are not reachable, none related to config-sever")
            return unreachable_hosts

        for relation in self.state.config_server_relation:
            shard_name = relation.app.name
            hosts = []
            for unit in relation.units:
                unit_state = self.state.unit_peer_data_for(unit, relation)
                hosts.append(unit_state.internal_address)
            if not hosts:
                return unreachable_hosts

            # use a URI that is not dependent on the operator password, as we are not guaranteed
            # that the shard has received the password yet.
            # To check if the shard is ready, we check the entire replica set for readiness
            uri = f"mongodb://{','.join(hosts)}"
            if not self.dependent.mongo_manager.mongod_ready(uri, direct=False):
                unreachable_hosts.append(shard_name)

        return unreachable_hosts


class ShardManager(Object, ManagerStatusProtocol):
    """Manage relations between the config server and the shard, on the shard's side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.SHARDING,
    ):
        self.name = relation_name.value
        super().__init__(dependent, self.name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_requirer = self.state.shard_state_interface

    def assert_pass_sanity_hook_checks(self, is_leaving: bool) -> None:
        """Returns True if all the sanity hook checks for sharding pass."""
        if not self.state.is_role(MongoDBRoles.SHARD):
            raise NonDeferrableFailedHookChecksError("is only executed by shards")
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("db is not initialised.")
        if (status := self.dependent.get_relation_feasible_status(self.relation_name)) is not None:
            self.dependent.state.statuses.add(status, scope="unit", component=self.dependent.name)
            raise NonDeferrableFailedHookChecksError("relation is not feasible")
        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding/Removing shards is not supported during an upgrade. The charm may be in a broken, unrecoverable state"
            )
            if not is_leaving:
                raise DeferrableFailedHookChecksError("Upgrade in progress")

        # Note: we permit this logic based on status since we aren't checking
        # self.charm.unit.status`, instead `get_cluster_mismatched_revision_status` directly
        # computes the revision check.
        if (
            rev_status
            := self.dependent.cluster_version_checker.get_cluster_mismatched_revision_status()
        ):
            self.state.statuses.add(rev_status, scope="unit", component=self.dependent.name)
            raise DeferrableFailedHookChecksError("Mismatched versions in the cluster")

    def assert_pass_hook_checks(self, relation: Relation, is_leaving: bool = False) -> None:
        """Runs the pre-hooks checks, returns True if all pass."""
        self.assert_pass_sanity_hook_checks(is_leaving=is_leaving)

        # Edge case for DPE-4998
        # TODO: Remove this when https://github.com/canonical/operator/issues/1306 is fixed.
        if relation.app is None:
            raise NonDeferrableFailedHookChecksError("Missing app information in event, skipping.")

        if is_leaving and not self.state.app_peer_data.mongos_hosts:
            raise NonDeferrableFailedHookChecksError(
                "Config-server never set up, no need to process broken event."
            )

        if tls_status := self.get_tls_status():
            self.state.statuses.add(tls_status, scope="unit", component=self.name)
            exception_msg = f"{tls_status.message} {tls_status.action}"
            raise DeferrableFailedHookChecksError(exception_msg)

        if is_leaving:
            self.dependent.assert_proceed_on_broken_event(relation)

    def prepare_to_add_shard(self) -> None:
        """Sets status and flags in relation data relevant to sharding."""
        # if reusing an old shard, re-set flags.
        self.state.unit_peer_data.drained = False

        self.state.statuses.delete(
            ShardStatuses.MISSING_CONF_SERVER_REL.value, scope="unit", component=self.name
        )
        self.state.statuses.add(
            ShardStatuses.ADDING_TO_CLUSTER.value, scope="unit", component=self.name
        )

    def synchronise_cluster_secrets(self, relation: Relation, leaving: bool = False) -> None:
        """Retrieves secrets from config-server and updates them within the shard."""
        try:
            self.assert_pass_hook_checks(relation=relation, is_leaving=leaving)
        except:
            logger.info("Skipping relation changed event: hook checks did not pass.")
            raise

        operator_password = self.state.shard_state.operator_password
        backup_password = self.state.shard_state.backup_password
        if not operator_password or not backup_password:
            logger.info("Missing secrets, returning.")
            return

        keyfile = self.state.shard_state.keyfile
        tls_ca = self.state.shard_state.internal_ca_secret

        if keyfile is None:
            logger.info("Waiting for secrets from config-server")
            raise WaitingForSecretsError("Missing keyfile")

        self.update_member_auth(keyfile, tls_ca)

        if not self.dependent.mongo_manager.mongod_ready():
            raise NotReadyError

        # By setting the status we ensure that the former statuses of this component are removed.
        self.state.statuses.set(ShardStatuses.ACTIVE_IDLE.value, scope="unit", component=self.name)

        # Add the certificate if it is present
        if (
            backup_tls_chain := self.state.shard_state.backup_ca_secret
        ) and not self.workload.exists(TRUST_STORE_PATH / TrustStoreFiles.PBM.value):
            logger.debug("Adding certificate for PBM")
            self.dependent.save_ca_cert_to_trust_store(TrustStoreFiles.PBM, backup_tls_chain)
            # We updated the configuration, so we restart PBM.
            self.dependent.backup_manager.configure_and_restart(force=True)
        elif (self.state.shard_state.backup_ca_secret is None) and self.workload.exists(
            TRUST_STORE_PATH / TrustStoreFiles.PBM.value
        ):
            logger.debug("Removing certificate for PBM")
            # If it is not in the databag, always remove it, it won't change a
            # thing if the file is not present, remove_ca_cert_from_trust_store will early return.
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
            # We updated the configuration, so we restart PBM.
            self.dependent.backup_manager.configure_and_restart(force=True)

        if not self.charm.unit.is_leader():
            return

        # Fix the former charms state if needed.
        if not self.data_requirer.fetch_my_relation_field(relation.id, "database"):
            logger.info("Repairing missing database field in DB")
            self.data_requirer.update_relation_data(
                relation.id, {"database": self.data_requirer.database}
            )

        self.sync_cluster_passwords(operator_password, backup_password)

        # We have updated our auth, config-server can add the shard.
        self.data_requirer.update_relation_data(relation.id, {"auth-updated": "true"})
        self.state.app_peer_data.mongos_hosts = self.state.shard_state.mongos_hosts

    def handle_secret_changed(self, secret_label: str | None) -> None:
        """Update operator and backup user passwords when rotation occurs.

        Changes in secrets do not re-trigger a relation changed event, so it is necessary to listen
        to secret changes events.
        """
        if not secret_label:
            return
        if not (relation := self.state.shard_relation):
            return
        # many secret changed events occur, only listen to those related to our interface with the
        # config-server
        sharding_secretes_label = f"{self.relation_name}.{relation.id}.extra.secret"
        if secret_label != sharding_secretes_label:
            logger.info(
                f"Secret unrelated to this sharding relation {relation.id} is changing, ignoring event."
            )
            return

        if self.charm.unit.is_leader():
            if self.data_requirer.fetch_my_relation_field(relation.id, "auth-updated") != "true":
                return

            operator_password = self.state.shard_state.operator_password
            backup_password = self.state.shard_state.backup_password

            if not operator_password or not backup_password:
                raise WaitingForSecretsError("Missing operator password or backup password")
            self.sync_cluster_passwords(operator_password, backup_password)

        # Add the certificate if it is present
        if (
            backup_tls_chain := self.state.shard_state.backup_ca_secret
        ) and not self.workload.exists(TRUST_STORE_PATH / TrustStoreFiles.PBM.value):
            logger.debug("Adding certificate for PBM")
            self.dependent.save_ca_cert_to_trust_store(TrustStoreFiles.PBM, backup_tls_chain)
            # We updated the configuration, so we restart PBM.
            self.dependent.backup_manager.configure_and_restart(force=True)
        elif (self.state.shard_state.backup_ca_secret is None) and self.workload.exists(
            TRUST_STORE_PATH / TrustStoreFiles.PBM.value
        ):
            logger.debug("Removing certificate for PBM")
            # If it is not in the databag, always remove it, it won't change a
            # thing if the file is not present, remove_ca_cert_from_trust_store will early return.
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
            # We updated the configuration, so we restart PBM.
            self.dependent.backup_manager.configure_and_restart(force=True)

    def drain_shard_from_cluster(self, relation: Relation) -> None:
        """Waits for the shard to be fully drained from the cluster."""
        self.assert_pass_hook_checks(relation, is_leaving=True)

        if not (mongos_hosts := self.state.app_peer_data.mongos_hosts):
            return

        self.wait_for_draining(mongos_hosts)

        self.state.app_peer_data.mongos_hosts = []

        self.state.statuses.set(
            ShardStatuses.SHARD_DRAINED.value, scope="unit", component=self.name
        )

    def update_member_auth(self, keyfile: str, tls_ca: str | None) -> None:
        """Updates the shard to have the same membership auth as the config-server."""
        cluster_auth_tls = tls_ca is not None
        tls_integrated = self.state.tls_relation is not None

        # Edge case: shard has TLS enabled before having connected to the config-server. For TLS in
        # sharded MongoDB clusters it is necessary that the subject and organisation name are the
        # same in their CSRs. Re-requesting a cert after integrated with the config-server
        # regenerates the cert with the appropriate configurations needed for sharding.
        if cluster_auth_tls and tls_integrated and self._should_request_new_certs():
            logger.info("Cluster implements internal membership auth via certificates")
            for internal in (True, False):
                csr = self.dependent.tls_manager.generate_certificate_request(
                    param=None, internal=internal
                )
                self.dependent.tls_events.certs_client.request_certificate_creation(
                    certificate_signing_request=csr
                )
                self.dependent.tls_manager.set_waiting_for_cert_to_update(
                    internal=internal, waiting=True
                )
        else:
            logger.info("Cluster implements internal membership auth via keyFile")

        # Copy over keyfile regardless of whether the cluster uses TLS or or KeyFile for internal
        # membership authentication. If TLS is disabled on the cluster this enables the cluster to
        # have the correct cluster KeyFile readily available.
        self.workload.write(path=self.workload.paths.keyfile, content=keyfile)

        # Sets the keyfile anyway
        if self.charm.unit.is_leader():
            self.state.set_keyfile(keyfile)

        # Prevents restarts if we haven't received certificates
        if tls_ca is not None and self.dependent.tls_manager.is_waiting_for_both_certs():
            logger.info("Waiting for requested certs before restarting and adding to cluster.")
            raise WaitingForCertificatesError

        self.dependent.restart_charm_services(force=True)

    def update_mongos_hosts(self):
        """Updates the hosts for mongos on the relation data."""
        if (hosts := self.state.shard_state.mongos_hosts) != self.state.app_peer_data.mongos_hosts:
            self.state.app_peer_data.mongos_hosts = hosts

    def sync_cluster_passwords(self, operator_password: str, backup_password: str) -> None:
        """Update shared cluster passwords."""
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
            with attempt:
                if self.dependent.primary_unit_name is None:
                    logger.info(
                        "Replica set has not elected a primary after restarting, cannot update passwords."
                    )
                    raise NotReadyError

        try:
            self.update_password(user=OperatorUser, new_password=operator_password)
            self.update_password(user=BackupUser, new_password=backup_password)
        except (NotReadyError, PyMongoError, ServerSelectionTimeoutError):
            # RelationChangedEvents will only update passwords when the relation is first joined,
            # otherwise all other password changes result in a Secret Changed Event.
            logger.error(
                "Failed to sync cluster passwords from config-server to shard. Deferring event and retrying."
            )
            raise FailedToUpdateCredentialsError
        try:
            # after updating the password of the backup user, restart pbm with correct password
            self.dependent.backup_manager.configure_and_restart()
        except NotPrimaryError:
            logger.info("Will retry to start pbm later.")

    def update_password(self, user: MongoDBUser, new_password: str) -> None:
        """Updates the password for the given user."""
        if not new_password or not self.charm.unit.is_leader():
            return

        current_password = self.state.get_user_password(user)

        if new_password == current_password:
            logger.info("Not updating password: password not changed.")
            return

        # updating operator password, usually comes after keyfile was updated, hence, the mongodb
        # service was restarted. Sometimes this requires units getting insync again.
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
            with attempt:
                with MongoConnection(self.state.mongo_config) as mongo:
                    try:
                        mongo.set_user_password(user.username, new_password)
                    except NotReadyError:
                        logger.error(
                            "Failed changing the password: Not all members healthy or finished initial sync."
                        )
                        raise
                    except PyMongoError as e:
                        logger.error(f"Failed changing the password: {e}")
                        raise
        self.state.set_user_password(user, new_password)

    def _should_request_new_certs(self) -> bool:
        """Returns if the shard has already requested the certificates for internal-membership.

        Sharded components must have the same subject names in their certs.
        """
        int_subject = self.state.unit_peer_data.get("int_certs_subject") or None
        ext_subject = self.state.unit_peer_data.get("ext_certs_subject") or None
        return {int_subject, ext_subject} != {self.state.config_server_name}

    def tls_status(self) -> tuple[bool, bool]:
        """Returns the TLS integration status for shard and config-server."""
        shard_relation = self.state.shard_relation
        if shard_relation:
            shard_has_tls = self.state.tls_relation is not None
            config_server_has_tls = self.state.shard_state.internal_ca_secret is not None
            return shard_has_tls, config_server_has_tls

        return False, False

    def is_ca_compatible(self) -> bool:
        """Returns true if both the shard and the config server use the same CA."""
        shard_relation = self.state.shard_relation
        if not shard_relation:
            return True
        config_server_tls_ca = self.state.shard_state.internal_ca_secret
        shard_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)
        if not config_server_tls_ca or not shard_tls_ca:
            return True

        return config_server_tls_ca == shard_tls_ca

    def wait_for_draining(self, mongos_hosts: list[str]) -> None:
        """Waits for shards to be drained from sharded cluster."""
        drained = False

        # Blocking status
        self.charm.status_handler.set_running_status(
            ShardStatuses.DRAINING_SHARD.value, scope="unit"
        )
        while not drained:
            try:
                # no need to continuously check and abuse resources while shard is draining
                time.sleep(60)
                drained = self.drained(mongos_hosts, self.charm.app.name)
                draining_status = (
                    "Shard is still draining" if not drained else "Shard is fully drained."
                )
                self.charm.status_handler.set_running_status(
                    ShardStatuses.DRAINING_SHARD.value, scope="unit"
                )
                logger.debug(draining_status)
            except PyMongoError as e:
                logger.error("Error occurred while draining shard: %s", e)
                self.charm.status_handler.set_running_status(
                    ShardStatuses.FAILED_TO_DRAIN.value, scope="unit"
                )
            except ShardNotPlannedForRemovalError:
                logger.info(
                    "Shard %s has not been identified for removal. Must wait for mongos cluster-admin to remove shard.",
                    self.charm.app.name,
                )
                self.charm.status_handler.set_running_status(
                    ShardStatuses.WAITING_TO_REMOVE.value, scope="unit"
                )
            except ShardNotInClusterError:
                logger.info(
                    "Shard to remove is not in sharded cluster. It has been successfully removed."
                )
                self.state.unit_peer_data.drained = True
                break

    def drained(self, mongos_hosts: list[str], shard_name: str) -> bool:
        """Returns whether a shard has been drained from the cluster or not.

        Raises:
            ConfigurationError, OperationFailure, ShardNotInClusterError,
            ShardNotPlannedForRemovalError
        """
        if not self.state.is_role(MongoDBRoles.SHARD):
            logger.info(
                "Component %s is not a shard, has no draining status.",
                self.state.app_peer_data.role,
            )
            return False

        config = self.state.mongos_config_for_user(OperatorUser, set(mongos_hosts))

        drained = shard_name not in self.dependent.mongo_manager.get_draining_shards(
            config=config, shard_name=shard_name
        )

        self.state.unit_peer_data.drained = drained
        return drained

    def cluster_password_synced(self) -> bool:
        """Returns True if the cluster password is synced."""
        # base case: not config-server
        if not self.state.is_role(MongoDBRoles.SHARD):
            return True

        try:
            # check our ability to use connect to mongos
            with MongoConnection(self.state.remote_mongos_config) as mongos:
                mongos.get_shard_members()
            # check our ability to use connect to mongod
            with MongoConnection(self.state.mongo_config) as mongod:
                mongod.get_replset_status()
        except OperationFailure as e:
            if e.code in (
                MongoErrorCodes.UNAUTHORIZED,
                MongoErrorCodes.AUTHENTICATION_FAILED,
                MongoErrorCodes.FAILED_TO_SATISFY_READ_PREFERENCE,
            ):
                return False
            raise
        except ServerSelectionTimeoutError:
            # Connection refused, - this occurs when internal membership is not in sync across the
            # cluster (i.e. TLS + KeyFile).
            return False

        return True

    def _is_shard_aware(self) -> bool:
        """Returns True if provided shard is shard aware."""
        with MongoConnection(self.state.remote_mongos_config) as mongo:
            return mongo.is_shard_aware(self.state.app_peer_data.replica_set)

    def should_skip_shard_status(self) -> bool:
        """Returns true if the status check should be skipped."""
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            logger.info("Skipping shard status check, charm is running as a config-server")
            return True

        if not self.state.db_initialised:
            logger.info("No status for shard to report, waiting for db to be initialised.")
            return True

        if self.state.is_role(MongoDBRoles.REPLICATION) and not self.state.shard_relation:
            return True

        if self.state.is_role(MongoDBRoles.REPLICATION) and self.state.shard_relation:
            logger.error("Cannot use a replica as a shard.")
            return True

        if self.state.client_relations:
            logger.error("")
            return True

        return False

    def get_tls_status(self) -> StatusObject | None:
        """Returns the TLS status of the sharded deployment."""
        shard_has_tls, config_server_has_tls = self.tls_status()
        match (shard_has_tls, config_server_has_tls):
            case False, True:
                return ShardStatuses.REQUIRES_TLS.value
            case True, False:
                return ShardStatuses.REQUIRES_NO_TLS.value
            case _:
                pass

        if not self.is_ca_compatible():
            logger.error(
                "Shard is integrated to a different CA than the config server. Please use the same CA for all cluster components."
            )
            return ShardStatuses.CA_MISMATCH.value
        return None

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:  # noqa: C901
        """Returns the current status of the shard."""
        charm_statuses: list[StatusObject] = []

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if scope == "app":
            return []

        if self.should_skip_shard_status():
            return charm_statuses

        # return in these cases as other statuses require a config-server to compute
        if not self.state.shard_relation:
            if self.state.unit_peer_data.drained:
                return [ShardStatuses.SHARD_DRAINED.value]

            if not self.state.unit_peer_data.drained:
                return [ShardStatuses.MISSING_CONF_SERVER_REL.value]

        if self.dependent.cluster_version_checker.get_cluster_mismatched_revision_status():
            # No need to go further if the revision is invalid
            return charm_statuses

        if tls_status := self.get_tls_status():
            charm_statuses.append(tls_status)
            # if TLS is misconfigured we will get redherrings on the remaining messages
            return charm_statuses

        if not self.state.is_shard_added_to_cluster():
            charm_statuses.append(ShardStatuses.ADDING_TO_CLUSTER.value)
            # the rest of the statuses need mongos information which occurs after being added
            # to the clusters
            return charm_statuses

        if not self.cluster_password_synced():
            charm_statuses.append(ShardStatuses.SYNCING_PASSWORDS.value)

        try:
            if not self._is_shard_aware():
                charm_statuses.append(ShardStatuses.SHARD_NOT_AWARE.value)
        except (ServerSelectionTimeoutError, OperationFailure):
            # A status is already raised by mongo manager.
            return []

        return charm_statuses or [ShardStatuses.ACTIVE_IDLE.value]
