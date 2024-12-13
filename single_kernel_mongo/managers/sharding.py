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

from ops import StatusBase
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, Relation, WaitingStatus
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError
from tenacity import Retrying, stop_after_delay, wait_fixed

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.relations import RelationNames
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
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
    DatabaseRequirerData,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.config_server_state import SECRETS_FIELDS, ConfigServerKeys
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongodb_users import BackupUser, MongoDBUser, OperatorUser
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = getLogger(__name__)


class ConfigServerManager(Object):
    """Manage relations between the config server and the shard, on the config-server's side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.CONFIG_SERVER,
    ):
        super().__init__(parent=dependent, key=relation_name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = DatabaseProviderData(
            self.model, relation_name=self.relation_name.value
        )

    def prepare_sharding_config(self, relation: Relation):
        """Handles the database requested event.

        It shares the different credentials and necessary files with the shard.
        """
        self.assert_pass_hook_checks(relation)

        if self.data_interface.fetch_relation_field(relation.id, "database") is None:
            raise DeferrableFailedHookChecksError(
                f"Database Requested event has not run yet for relation {relation.id}"
            )
        relation_data = {
            ConfigServerKeys.operator_password.value: self.state.get_user_password(OperatorUser),
            ConfigServerKeys.backup_password.value: self.state.get_user_password(BackupUser),
            ConfigServerKeys.key_file.value: self.state.get_keyfile(),
            ConfigServerKeys.host.value: json.dumps(sorted(self.state.app_hosts)),
        }

        int_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)
        if int_tls_ca:
            relation_data[ConfigServerKeys.int_ca_secret.value] = int_tls_ca

        self.data_interface.update_relation_data(relation.id, relation_data)
        self.data_interface.set_credentials(
            relation.id, "unused", "unused"
        )  # Triggers the database created event

    def reconcile_shards_for_relation(self, relation: Relation, is_leaving: bool = False):
        """Handles adding and removing shards.

        Updating of shards is done automatically via MongoDB change-streams.
        """
        logger.info("Running Relation Changed hook.")
        self.assert_pass_hook_checks(relation, is_leaving)

        if self.data_interface.fetch_relation_field(relation.id, "database") is None:
            logger.info("Waiting for secrets requested")
            return

        if not self.data_interface.fetch_relation_field(relation.id, "auth-updated") == "true":
            logger.info(f"Waiting for shard {relation.app.name} to update its authentication")
            return

        try:
            logger.info("Adding/Removing shards not present in cluster.")
            match is_leaving:
                case False:
                    self.add_shard(relation)
                case True:
                    self.remove_shards(relation)
        except NotDrainedError:
            # it is necessary to removeShard multiple times for the shard to be removed.
            logger.info(
                "Shard is still present in the cluster after removal, will defer and remove again."
            )
            raise
        except OperationFailure as e:
            if e.code == 20:
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
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("db is not initialised.")
        if not self.dependent.is_relation_feasible(self.relation_name):
            raise NonDeferrableFailedHookChecksError("relation is not feasible")
        # TODO: revision checks.
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            raise NonDeferrableFailedHookChecksError("is only executed by config-server")
        if not self.charm.unit.is_leader():
            raise NonDeferrableFailedHookChecksError

    def assert_pass_hook_checks(self, relation: Relation, leaving: bool = False) -> None:
        """Runs pre hooks checks and raises the appropriate error if it fails.

        Raises:
            NonDeferrableFailedHookChecksError, DeferrableFailedHookChecksError
        """
        self.assert_pass_sanity_hook_checks()

        pbm_status = self.dependent.backup_manager.get_status()
        if isinstance(pbm_status, MaintenanceStatus):
            raise DeferrableFailedHookChecksError(
                "Cannot add/remove shards while a backup/restore is in progress."
            )

        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding/Removing shards is not supported during an upgrade. The charm may be in a broken, unrecoverable state"
            )
            if not leaving:
                raise DeferrableFailedHookChecksError
            if self.state.has_departed_run(relation.id):
                raise DeferrableFailedHookChecksError(
                    "must wait for relation departed hook to decide if relation should be removed"
                )
            self.dependent.assert_proceed_on_broken_event(relation)

    def update_credentials(self, key: str, value: str) -> None:
        """Sends new credentials for a new key value pair across all shards."""
        for relation in self.state.config_server_relation:
            if self.data_interface.fetch_relation_field(relation.id, "database") is None:
                logger.info("Database Requested event has not run yet for relation {relation.id}")
                continue
            self.data_interface.update_relation_data(relation.id, {key: value})

    def update_mongos_hosts(self):
        """Updates the hosts for mongos on the relation data."""
        for relation in self.state.config_server_relation:
            self.data_interface.update_relation_data(
                relation.id, {ConfigServerKeys.host.value: sorted(self.state.app_hosts)}
            )

    def update_ca_secret(self, new_ca: str | None) -> None:
        """Updates the new CA for all related shards."""
        for relation in self.state.config_server_relation:
            if self.data_interface.fetch_relation_field(relation.id, "database") is None:
                logger.info("Database Requested event has not run yet for relation {relation.id}")
                continue
            if new_ca is None:
                self.data_interface.delete_relation_data(
                    relation.id, [ConfigServerKeys.int_ca_secret.value]
                )
                continue
            self.data_interface.update_relation_data(
                relation.id, {ConfigServerKeys.int_ca_secret.value: new_ca}
            )

    def skip_config_server_status(self) -> bool:
        """Returns true if the status check should be skipped."""
        if self.state.is_role(MongoDBRoles.SHARD):
            logger.info("skipping config server status check, charm is  running as a shard")
            return True

        if not self.state.db_initialised:
            logger.info("No status for shard to report, waiting for db to be initialised.")
            return True

        return False

    def get_status(self) -> StatusBase | None:
        """Returns the current status of the config-server."""
        if self.skip_config_server_status():
            return None

        if self.state.is_role(MongoDBRoles.REPLICATION) and self.state.config_server_relation:
            return BlockedStatus("sharding interface cannot be used by replicas")

        if self.state.client_relations:
            return BlockedStatus(
                f"Sharding roles do not support {RelationNames.DATABASE.value} interface."
            )

        uri = f"mongodb://{','.join(self.state.app_hosts)}"
        if not self.dependent.mongo_manager.mongod_ready(uri):
            return BlockedStatus("Internal mongos is not running.")

        if not self.cluster_password_synced():
            return WaitingStatus("Waiting to sync passwords across the cluster")

        shard_draining = self.dependent.mongo_manager.get_draining_shards()
        if shard_draining:
            draining = ",".join(shard_draining)
            return MaintenanceStatus(f"Draining shard {draining}")

        if not self.state.config_server_relation:
            return BlockedStatus("missing relation to shard(s)")

        unreachable_shards = self.get_unreachable_shards()

        if unreachable_shards:
            unreachable = ", ".join(unreachable_shards)
            return BlockedStatus(f"shards {unreachable} are unreachable.")

        return ActiveStatus()

    def add_shard(self, relation: Relation):
        """Adds a shard to the cluster."""
        shard_name = relation.app.name

        hosts = []
        for unit in relation.units:
            if self.substrate == "k8s":
                unit_name = unit.name.split("/")[0]
                unit_id = unit.name.split("/")[1]
                host_name = f"{unit_name}-{unit_id}.{unit_name}-endpoints"
                hosts.append(host_name)
            else:
                if not (address := relation.data[unit].get("private-address")):
                    raise Exception("Missing host")
                hosts.append(address)
        if not len(hosts):
            logger.info(f"host info for shard {shard_name} not yet added, skipping")
            return

        self.charm.status_manager.to_maintenance(f"Adding shard {shard_name} to config-server")
        config = self.state.mongos_config_for_user(
            OperatorUser,
            self.state.app_hosts,
        )
        with MongoConnection(config) as mongo:
            try:
                mongo.add_shard(shard_name, hosts)
            except OperationFailure as e:
                if e.code == 18:
                    logger.error(
                        f"{shard_name} shard does not have the same auth as the config server."
                    )
                    raise ShardAuthError(shard_name)
            except PyMongoError as e:
                logger.error(f"Failed to add {shard_name} to cluster")
                raise e
        self.charm.status_manager.to_active(None)

    def remove_shards(self, relation: Relation):
        """Removes a shard from the cluster."""
        shard_name = relation.app.name

        config = self.state.mongos_config_for_user(
            OperatorUser,
            self.state.app_hosts,
        )
        with MongoConnection(config) as mongo:
            try:
                self.charm.status_manager.to_maintenance(f"Draining shard {shard_name}")
                logger.info("Attempting to removing shard: %s", shard_name)
                mongo.pre_remove_checks(shard_name)
                mongo.remove_shard(shard_name)
                mongo.move_primary_after_draining_shard(shard_name)
            except NotReadyError:
                logger.info("Unable to remove shard: %s another shard is draining", shard_name)
                # to guarantee that shard that the currently draining shard, gets re-processed,
                # do not raise immediately, instead at the end of removal processing.
                raise ShardNotInClusterError
            except ShardNotInClusterError:
                logger.info(
                    "Shard to remove is not in sharded cluster. It has been successfully removed."
                )

    def cluster_password_synced(self) -> bool:
        """Returns True if the cluster password is synced."""
        # base case: not config-server
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return True

        config = self.state.mongos_config_for_user(
            OperatorUser,
            self.state.app_hosts,
        )
        try:
            # check our ability to use connect to mongos
            with MongoConnection(config) as mongos:
                mongos.get_shard_members()
            # check our ability to use connect to mongod
            with MongoConnection(self.state.mongo_config) as mongod:
                mongod.get_replset_status()
        except OperationFailure as e:
            if e.code in [13, 18]:
                return False
            raise
        except ServerSelectionTimeoutError:
            # Connection refused, - this occurs when internal membership is not in sync across the
            # cluster (i.e. TLS + KeyFile).
            return False

        return True

    def get_unreachable_shards(self) -> list[str]:
        """Returns a list of unreable shard hosts."""
        unreachable_hosts: list[str] = []
        if not self.model.relations[self.relation_name]:
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
            uri = f"mongodb://{','.join(hosts)}"
            if not self.dependent.mongo_manager.mongod_ready(uri):
                unreachable_hosts.append(shard_name)

        return unreachable_hosts


class ShardManager(Object):
    """Manage relations between the config server and the shard, on the shard's side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.SHARDING,
    ):
        super().__init__(dependent, relation_name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_requirer = DatabaseRequirerData(
            self.model,
            relation_name=self.relation_name,
            additional_secret_fields=SECRETS_FIELDS,
            database_name="unused",  # Needed for relation events
        )

    def assert_pass_sanity_hook_checks(self):
        """Returns True if all the sanity hook checks for sharding pass."""
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("db is not initialised.")
        if not self.dependent.is_relation_feasible(self.relation_name):
            raise NonDeferrableFailedHookChecksError("relation is not feasible")
        # TODO: revision checks.
        if not self.state.is_role(MongoDBRoles.SHARD):
            raise NonDeferrableFailedHookChecksError("is only executed by shards")

    def assert_pass_hook_checks(self, relation: Relation, is_leaving: bool = False):
        """Runs the pre-hooks checks, returns True if all pass."""
        self.assert_pass_sanity_hook_checks()

        # Edge case for DPE-4998
        # TODO: Remove this when https://github.com/canonical/operator/issues/1306 is fixed.
        if relation.app is None:
            raise NonDeferrableFailedHookChecksError("Missing app information in event, skipping.")

        mongos_hosts = self.state.shard_state.mongos_hosts

        if is_leaving and not mongos_hosts:
            raise NonDeferrableFailedHookChecksError(
                "Config-server never set up, no need to process broken event."
            )

        if self.state.upgrade_in_progress:
            logger.warning(
                "Adding/Removing shards is not supported during an upgrade. The charm may be in a broken, unrecoverable state"
            )
            if not is_leaving:
                raise DeferrableFailedHookChecksError

        shard_has_tls, config_server_has_tls = self.tls_status()
        match (shard_has_tls, config_server_has_tls):
            case False, True:
                raise DeferrableFailedHookChecksError(
                    "Config-Server uses TLS but shard does not. Please synchronise encryption method."
                )
            case True, False:
                raise DeferrableFailedHookChecksError(
                    "Shard uses TLS but config-server does not. Please synchronise encryption method."
                )
            case _:
                pass

        if not self.is_ca_compatible():
            raise DeferrableFailedHookChecksError(
                "Shard is integrated to a different CA than the config server. Please use the same CA for all cluster components.",
            )

    def prepare_to_add_shard(self):
        """Sets status and flags in relation data relevant to sharding."""
        # if re-using an old shard, re-set flags.
        self.state.unit_peer_data.drained = False
        self.charm.status_manager.to_maintenance("Adding shard to config-server")

    def synchronise_cluster_secrets(self, relation: Relation, leaving: bool = False):
        """Retrieves secrets from config-server and updates them within the shard."""
        try:
            self.assert_pass_hook_checks(relation=relation, is_leaving=leaving)
        except:
            logger.info("Skipping relation changed event: hook checks did not pass.")
            raise

        keyfile = self.state.shard_state.keyfile
        tls_ca = self.state.shard_state.internal_ca_secret

        if keyfile is None:
            logger.info("Waiting for secrets from config-server")
            raise WaitingForSecretsError

        self.update_member_auth(keyfile, tls_ca)

        if tls_ca is not None and self.dependent.tls_manager.is_waiting_for_both_certs():
            logger.info("Waiting for requested certs before restarting and adding to cluster.")
            raise WaitingForCertificatesError

        if not self.dependent.mongo_manager.mongod_ready():
            raise NotReadyError

        if not self.charm.unit.is_leader():
            return

        operator_password = self.state.shard_state.operator_password
        backup_password = self.state.shard_state.backup_password
        if not operator_password or not backup_password:
            raise WaitingForSecretsError

        self.sync_cluster_passwords(operator_password, backup_password)

        # We have updated our auth, config-server can add the shard.
        self.data_requirer.update_relation_data(relation.id, {"auth-updated": "true"})
        self.state.app_peer_data.mongos_hosts = self.state.shard_state.mongos_hosts

    def handle_secret_changed(self, secret_label: str | None):
        """Update operator and backup user passwords when rotation occurs.

        Changes in secrets do not re-trigger a relation changed event, so it is necessary to listen
        to secret changes events.
        """
        if not self.charm.unit.is_leader():
            return
        if not secret_label:
            return
        if not (relation := self.state.shard_relation):
            return
        if self.data_requirer.fetch_my_relation_field(relation.id, "auth-updated") != "true":
            return

        # many secret changed events occur, only listen to those related to our interface with the
        # config-server
        sharding_secretes_label = f"{self.relation_name}.{relation.id}.extra.secret"
        if secret_label != sharding_secretes_label:
            logger.info(
                f"Secret unrelated to this sharding relation {relation.id} is changing, ignoring event."
            )
            return

        operator_password = self.state.shard_state.operator_password
        backup_password = self.state.shard_state.backup_password

        if not operator_password or not backup_password:
            raise WaitingForSecretsError
        self.sync_cluster_passwords(operator_password, backup_password)

    def drain_shard_from_cluster(self, relation: Relation) -> None:
        """Waits for the shard to be fully drained from the cluster."""
        self.assert_pass_hook_checks(relation, is_leaving=True)

        self.charm.status_manager.to_maintenance("Draining shard from cluster.")

        mongos_hosts = self.state.app_peer_data.mongos_hosts

        self.wait_for_draining(mongos_hosts)

        self.charm.status_manager.to_active("Shard drained from cluster, ready for removal")

    def update_member_auth(self, keyfile: str, tls_ca: str | None):
        """Updates the shard to have the same membership auth as the config-server."""
        cluster_auth_tls = tls_ca is not None
        tls_integrated = self.state.tls_relation is not None

        # Edge case: shard has TLS enabled before having connected to the config-server. For TLS in
        # sharded MongoDB clusters it is necessary that the subject and organisation name are the
        # same in their CSRs. Re-requesting a cert after integrated with the config-server
        # regenerates the cert with the appropriate configurations needed for sharding.
        if cluster_auth_tls and tls_integrated and self._should_request_new_certs():
            logger.info("Cluster implements internal membership auth via certificates")
            self.dependent.tls_manager.generate_certificate_request(param=None, internal=True)
            self.dependent.tls_manager.generate_certificate_request(param=None, internal=False)
        else:
            logger.info("Cluster implements internal membership auth via keyFile")

        # Copy over keyfile regardless of whether the cluster uses TLS or or KeyFile for internal
        # membership authentication. If TLS is disabled on the cluster this enables the cluster to
        # have the correct cluster KeyFile readily available.
        self.workload.write(path=self.workload.paths.keyfile, content=keyfile)
        self.dependent.restart_charm_services()
        if self.charm.unit.is_leader():
            self.state.app_peer_data.keyfile = keyfile

    def sync_cluster_passwords(self, operator_password: str, backup_password: str) -> None:
        """Update shared cluster passwords."""
        for attempt in Retrying(stop=stop_after_delay(60), wait=wait_fixed(3), reraise=True):
            with attempt:
                if self.dependent.primary is None:
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
        # after updating the password of the backup user, restart pbm with correct password
        self.dependent.backup_manager.configure_and_restart()

    def update_password(self, user: MongoDBUser, new_password: str):
        """Updates the password for the given user."""
        if not new_password or not self.charm.unit.is_leader():
            return

        current_password = self.state.get_user_password(user)

        if new_password == current_password:
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
        """Returns if the shard has already requested the certificates for internal-membership."""
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

    def wait_for_draining(self, mongos_hosts: list[str]):
        """Waits for shards to be drained from sharded cluster."""
        drained = False

        while not drained:
            try:
                # no need to continuously check and abuse resources while shard is draining
                time.sleep(60)
                drained = self.drained(mongos_hosts, self.charm.app.name)
                draining_status = (
                    "Shard is still draining" if not drained else "Shard is fully drained."
                )
                self.charm.status_manager.to_maintenance("Draining shard from cluster.")
                logger.debug(draining_status)
            except PyMongoError as e:
                logger.error("Error occurred while draining shard: %s", e)
                self.charm.status_manager.to_blocked("Failed to drain shard from cluster")
            except ShardNotPlannedForRemovalError:
                logger.info(
                    "Shard %s has not been identifies for removal. Must wait for mongos cluster-admin to remove shard."
                )
                self.charm.status_manager.to_waiting("Waiting for config-server to remove shard")
            except ShardNotInClusterError:
                logger.info(
                    "Shard to remove is not in sharded cluster. It has been successfully removed."
                )
                self.state.unit_peer_data.drained = True
                break

    def drained(self, mongos_hosts: list[str], shard_name: str):
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

        drained = shard_name not in self.dependent.mongo_manager.get_draining_shards(config=config)

        self.state.unit_peer_data.drained = drained
        return drained
