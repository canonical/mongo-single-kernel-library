# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the cluster relation between config-server and mongos."""

from __future__ import annotations

import json
from logging import getLogger
from typing import TYPE_CHECKING, final

from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.framework import Object
from ops.model import Relation
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import (
    RollingOpsCallbackId,
    Substrates,
)
from single_kernel_mongo.config.models import MongosTLSState
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import (
    CharmStatuses,
    MongoDBStatuses,
    MongosStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DatabaseRequestedHasNotRunYetError,
    DeferrableError,
    DeferrableFailedHookChecksError,
    FailedToGetHostsError,
    IncompatibleMongosTLSError,
    InvalidMongosTLSError,
    MissingMongosTLSError,
    NonDeferrableFailedHookChecksError,
    WaitingForACertError,
    WaitingForSecretsError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator
    from single_kernel_mongo.managers.mongos_operator import MongosOperator

logger = getLogger(__name__)


@final
class ClusterProvider(Object):
    """Manage relations between the config server and mongos router on the config-server side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.CLUSTER,
    ):
        super().__init__(parent=dependent, key=relation_name.value)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = self.state.cluster_provider_data_interface

    def assert_pass_hook_checks(self, initial_event: bool = False) -> None:
        """Runs the pre hook checks, raises if it fails."""
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")

        if not self.is_valid_mongos_integration():
            self.state.statuses.add(
                MongoDBStatuses.INVALID_MONGOS_REL.value,
                scope="unit",
                component=self.dependent.name,
            )
            raise NonDeferrableFailedHookChecksError(
                "ClusterProvider is only executed by a config-server"
            )

        if not self.charm.unit.is_leader():
            raise NonDeferrableFailedHookChecksError("Not leader")

        if self.dependent.refresh_in_progress and initial_event:
            raise DeferrableFailedHookChecksError(
                "Processing mongos applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )

    def is_valid_mongos_integration(self) -> bool:
        """Returns True if the integration to mongos is valid."""
        # The integration is valid if and only if we are a config server or if
        # we don't have any cluster relation.
        return self.state.is_role(MongoDBRoles.CONFIG_SERVER) or not self.state.cluster_relations

    def share_secret_to_mongos(self, relation: Relation, initial_event: bool = False) -> None:
        """Handles the database requested event.

        The first time secrets are written to relations should be on this event.
        """
        self.assert_pass_hook_checks(initial_event=initial_event)

        config_server_db = self.state.generate_config_server_db(relation)
        try:
            self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(relation)
        except (PyMongoError, FailedToGetHostsError, DatabaseRequestedHasNotRunYetError):
            # Failed to get hosts error is unique to mongos-k8s charm. In other charms we do not
            # foresee issues to retrieve hosts. However in external mongos-k8s, the leader can
            # attempt to retrieve hosts while non-leader units are still enabling node port
            # resulting in an exception.
            raise DeferrableError(
                "Failed to add user for mongos."
            ) from DatabaseRequestedHasNotRunYetError

        relation_data = {
            ClusterStateKeys.KEYFILE.value: self.state.get_keyfile(),
            ClusterStateKeys.CONFIG_SERVER_DB.value: config_server_db,
            ClusterStateKeys.REPLICA_SET.value: self.state.app_peer_data.replica_set,
        }

        if int_tls_ca := self.state.tls.get_secret(label_name=SECRET_CA_LABEL, internal=True):
            relation_data[ClusterStateKeys.INT_CA_SECRET.value] = int_tls_ca

        if ext_tls_ca := self.state.tls.get_secret(label_name=SECRET_CA_LABEL, internal=False):
            relation_data[ClusterStateKeys.EXT_CA_SECRET.value] = ext_tls_ca

        if hashed_data := self.dependent.ldap_manager.get_hash():
            relation_data[ClusterStateKeys.LDAP_HASH.value] = hashed_data

        # We want to avoid having to configure both applications with the exact
        # same string so the config-server shares it with the client.
        if ldap_user_to_dn_mapping := self.state.ldap.ldap_user_to_dn_mapping:
            relation_data[ClusterStateKeys.LDAP_USER_TO_DN_MAPPING.value] = ldap_user_to_dn_mapping

        if cluster_id := self.state.get_cluster_id():
            relation_data[ClusterStateKeys.CLUSTER_ID.value] = cluster_id

        self.data_interface.update_relation_data(relation.id, relation_data)

    def update_keyfile_and_hosts_on_mongos(self, relation: Relation) -> None:
        """Handles providing mongos with keyfile and hosts."""
        # First we need to ensure that the database requested event has run
        # otherwise we risk the chance of writing secrets in plain sight.
        if not self.data_interface.fetch_relation_field(relation.id, "database"):
            logger.info("Database Requested has not run yet, skipping.")
            return

        self.share_secret_to_mongos(relation)

    def cleanup_users(self, relation: Relation) -> None:
        """Handles the relation broken event.

        If the relation has not departed yet, we raise a DeferrableError to
        handle the relation broken event in the future.
        If it has departed, we run some checks and if we are a VM charm, we
        proceed to reconcile the users and DB and cleanup mongoDB.
        """
        if self.dependent.refresh_in_progress:
            logger.warning(
                "Removing integration to mongos is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )

        if not self.state.has_departed_run(relation.id):
            raise DeferrableError(
                "must wait for relation departed hook to decide if relation should be removed."
            )

        self.assert_pass_hook_checks()

        self.dependent.assert_proceed_on_broken_event(relation)

        if self.substrate == Substrates.VM:
            try:
                self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(
                    relation, relation_departing=True
                )
            except (PyMongoError, FailedToGetHostsError, DatabaseRequestedHasNotRunYetError):
                # Failed to get hosts error is unique to mongos-k8s charm. In other charms we do not
                # foresee issues to retrieve hosts. However in external mongos-k8s, the leader can
                # attempt to retrieve hosts while non-leader units are still enabling node port
                # resulting in an exception.
                raise DeferrableError("Failed to remove user for mongos.")

    def update_config_server_db(self) -> None:
        """Updates the config server DB URI in the mongos relation."""
        self.assert_pass_hook_checks()

        for relation in self.state.cluster_relations:
            if not self.data_interface.fetch_relation_field(relation.id, "database"):
                logger.info("Database Requested has not run yet, skipping.")
                continue
            config_server_db = self.state.generate_config_server_db(relation)
            self.data_interface.update_relation_data(
                relation.id,
                {
                    ClusterStateKeys.CONFIG_SERVER_DB.value: config_server_db,
                },
            )

    def update_ldap_hash_to_mongos(self, hashed_data: str) -> None:
        """Sends the hash to mongos to confirm we are integrated with the same units."""
        try:
            self.assert_pass_hook_checks()
        except (DeferrableFailedHookChecksError, NonDeferrableFailedHookChecksError):
            logger.info("Not updating ldap hash now, not ready.")
            return

        if not self.charm.unit.is_leader():
            return

        for relation in self.state.cluster_relations:
            if not self.data_interface.fetch_relation_field(relation.id, "database"):
                logger.info("Database Requested has not run yet, skipping.")
                continue
            self.data_interface.update_relation_data(
                relation.id,
                {ClusterStateKeys.LDAP_HASH.value: hashed_data},
            )

    def remove_ldap_hash(self) -> None:
        """Removes the hash from all relations."""
        try:
            self.assert_pass_hook_checks()
        except (DeferrableFailedHookChecksError, NonDeferrableFailedHookChecksError):
            logger.info("Not removing ldap hash now, not ready.")
            return

        if not self.charm.unit.is_leader():
            return

        for relation in self.state.cluster_relations:
            if not self.data_interface.fetch_relation_field(relation.id, "database"):
                logger.info("Database Requested has not run yet, skipping.")
                continue
            self.data_interface.delete_relation_data(
                relation.id,
                [ClusterStateKeys.LDAP_HASH.value],
            )

    def update_ldap_user_to_dn_mapping(self) -> None:
        """Updates the ldap user to dn mapping value in the databag."""
        try:
            self.assert_pass_hook_checks()
        except (DeferrableFailedHookChecksError, NonDeferrableFailedHookChecksError):
            logger.info("Not updating ldap user to dn mapping now, not ready.")
            return

        if not self.charm.unit.is_leader():
            return

        for relation in self.state.cluster_relations:
            if not self.data_interface.fetch_relation_field(relation.id, "database"):
                logger.info("Database Requested has not run yet, skipping.")
                continue
            self.data_interface.update_relation_data(
                relation.id,
                {
                    ClusterStateKeys.LDAP_USER_TO_DN_MAPPING.value: self.state.ldap.ldap_user_to_dn_mapping
                },
            )


@final
class ClusterRequirer(Object):
    """Manage relations between the config server and mongos router on the mongos side."""

    def __init__(
        self,
        dependent: MongosOperator,
        workload: MongosWorkload,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.CLUSTER,
    ):
        super().__init__(parent=dependent, key=relation_name.value)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = self.state.cluster_requirer_data_interface

    def assert_pass_hook_checks(self) -> None:
        """Runs pre-hook checks, raises if one fails."""
        if not self.state.cluster.has_received_credentials():
            raise WaitingForSecretsError

        internal_tls_state = self.get_tls_state(internal=True)
        external_tls_state = self.get_tls_state(internal=False)

        tls_flag = internal_tls_state | external_tls_state

        if internal_tls_status := self.map_tls_state_to_status(internal_tls_state):
            self.state.statuses.add(internal_tls_status, scope="all", component=self.dependent.name)
        if external_tls_status := self.map_tls_state_to_status(external_tls_state):
            self.state.statuses.add(external_tls_status, scope="all", component=self.dependent.name)

        if MongosTLSState.any_missing(tls_flag):
            raise MissingMongosTLSError("Invalid TLS integration, check logs.")

        if MongosTLSState.any_invalid(tls_flag):
            raise InvalidMongosTLSError("Invalid TLS integration, check logs.")

        if MongosTLSState.any_incompatible(tls_flag):
            raise IncompatibleMongosTLSError("Invalid TLS integration, check logs.")

        if self.dependent.tls_manager.is_waiting_for_a_cert():
            raise WaitingForACertError(
                "Mongos was waiting for config-server to enable TLS. Wait for TLS to be enabled until starting mongos."
            )

        if self.dependent.refresh_in_progress:
            logger.warning(
                "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )

    def set_relation_created_status(self) -> None:
        """Just sets a status on relation created."""
        logger.info("Integrating to config-server")
        self.state.statuses.set(
            MongosStatuses.CONNECTING_TO_CONFIG_SERVER.value,
            scope="unit",
            component=self.dependent.name,
        )

    def share_credentials_to_clients(self, username: str | None, password: str | None) -> None:
        """Database created event.

        Stores credentials in secrets and share it with clients.
        """
        if not username or not password:
            raise WaitingForSecretsError
        if self.dependent.refresh_in_progress:
            logger.warning(
                "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            raise DeferrableFailedHookChecksError

        if not self.charm.unit.is_leader():
            return

        logger.info("Database and user created for mongos application.")
        self.state.set_user_credentials(username=username, password=password)

    def _set_cluster_id(self):
        """Take the cluster ID from the cluster state and set it in the charm state."""
        if not self.charm.unit.is_leader():
            return
        if not (new_cluster_id := self.state.cluster.cluster_id):
            return
        self.state.set_cluster_id(new_cluster_id)

    def _set_ldap_user_to_dn(self):
        """Take the LDAP User to DN Mapping and set it in the charm state."""
        if self.charm.unit.is_leader():
            if ldap_user_to_dn_mapping := self.state.cluster.ldap_user_to_dn_mapping:
                logger.debug("Received a userToDNMapping, storing it in databag.")
                self.state.ldap.ldap_user_to_dn_mapping = ldap_user_to_dn_mapping

    def update_mongos_and_restart(self, force: bool = False) -> None:
        """Start/restarts mongos with config server information.

        It is important that this is called through a callback so that whatever event asks for a
        start/restart, we can do it.
        """
        if self.state.db_initialised:
            self._restart_mongos(force=force)
        else:
            self._start_mongos()

    def _start_mongos(self) -> None:
        """Runs the initial start of mongos.

        All subsequent restarts will be handled by `_restart_mongos`.
        """
        self.assert_pass_hook_checks()

        key_file_contents = self.state.cluster.keyfile
        config_server_db_uri = self.state.cluster.config_server_uri

        self._set_ldap_user_to_dn()
        self._set_cluster_id()

        if not key_file_contents or not config_server_db_uri:
            raise WaitingForSecretsError("Waiting for keyfile or config server db uri")

        updated_keyfile = self.dependent.update_keyfile(key_file_contents)
        updated_config = self.dependent.update_config_server_db(config_server_db_uri)

        if updated_keyfile or updated_config or not self.dependent.is_mongos_running():
            logger.info("Restarting mongos with new secrets.")
            self.dependent.config_manager.configure_and_restart(force=True)

        if not self.dependent.is_mongos_running():
            logger.info("Mongos has not started yet, deferring")
            self.state.statuses.set(
                MongosStatuses.WAITING_FOR_MONGOS_START.value,
                scope="unit",
                component=self.dependent.name,
            )
            raise WorkloadServiceError("Mongos is not running.")

        self.state.statuses.set(
            CharmStatuses.ACTIVE_IDLE.value, scope="unit", component=self.dependent.name
        )
        if self.charm.unit.is_leader():
            # Mongos handles also app statuses
            self.state.statuses.set(
                CharmStatuses.ACTIVE_IDLE.value, scope="app", component=self.dependent.name
            )
            self.state.app_peer_data.db_initialised = True
            # In the K8S case, create the user
            self.update_users_for_k8s_routers()

        self.dependent.share_connection_info()
        self.dependent.ldap_manager.update_hash_status()

    def _restart_mongos(self, force: bool = False) -> None:
        """Runs a restart of mongos.

        It first validates the hook checks, but still restarts in some cases if an invalid state is
        reached.

        It runs a few updates such as the LDAP User to DN field and the Cluster ID field.
        If the keyfile or the config server URI has changed, always restart.

        This is for security reasons, and it happens on TLS CA incompatibility or missing TLS on
        mongos.
        """
        self.charm.status_handler.set_running_status(MongosStatuses.RESTARTING.value, scope="unit")
        try:
            self.assert_pass_hook_checks()
        except (InvalidMongosTLSError, WaitingForSecretsError):
            logger.info("Not restart mongos: mongos has TLS but not config-server.")
            raise
        except (MissingMongosTLSError, IncompatibleMongosTLSError):
            logger.info(
                "Restarting mongos for security reasons: missing mongos certificate or incompatible CA."
            )

        key_file_contents = self.state.cluster.keyfile
        config_server_db_uri = self.state.cluster.config_server_uri

        self._set_ldap_user_to_dn()
        self._set_cluster_id()

        if not key_file_contents or not config_server_db_uri:
            raise WaitingForSecretsError("Waiting for keyfile or config server db uri")

        updated_keyfile = self.dependent.update_keyfile(key_file_contents)
        updated_config = self.dependent.update_config_server_db(config_server_db_uri)

        force = force or updated_keyfile or updated_config

        self.dependent.config_manager.configure_and_restart(force=force)

    def async_update_mongos_and_restart(self, force: bool = False):
        """Async update mongos and restart.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
        """
        self.assert_pass_hook_checks()

        self.state.statuses.delete(
            MongosStatuses.CONNECTING_TO_CONFIG_SERVER.value,
            scope="unit",
            component=self.dependent.name,
        )
        self.state.statuses.add(
            MongosStatuses.WAITING_FOR_MONGOS_START.value,
            scope="unit",
            component=self.dependent.name,
        )

        # This is the config server CA certificate. We'll use it to connect to the config server.
        if external_tls_ca := self.state.cluster.external_ca_secret:
            self.workload.paths.config_server_ext_ca_file.write_text(external_tls_ca)
        else:  # if we don't have a cert, we'll remove it
            self.workload.paths.config_server_ext_ca_file.unlink(missing_ok=True)

        self.dependent.rollingops_manager.request_async_lock(
            callback_id=RollingOpsCallbackId.RESTART_CHARM_SERVICES, kwargs={"force": force}
        )
        logger.info("Requested and async lock to update Mongos and restart.")

    def handle_secret_changed(self, secret_label: str | None) -> None:
        """If the certificates are rotated for example, handle it immediately.

        Changes in secrets do not re-trigger a relation changed event, so it is necessary to listen
        to secret changes events.

        Raises:
            RollingOpsNoRelationError: If an async lock is requested too early.
        """
        if not secret_label:
            return
        if not self.state.db_initialised:
            return
        if not (relation := self.state.mongos_cluster_relation):
            return
        # many secret changed events occur,only listen to the ones related to our interface
        # with the config server.
        cluster_extra_secret_label = f"{self.relation_name.value}.{relation.id}.extra.secret"
        cluster_user_secret_label = f"{self.relation_name.value}.{relation.id}.user.secret"
        if secret_label not in (cluster_extra_secret_label, cluster_user_secret_label):
            logger.info(
                f"Secret unrelated to this sharding relation {relation.id} is changing, ignoring event."
            )
            return

        # This will take care of updating everything that needs updating
        self.async_update_mongos_and_restart()

    def remove_users_and_cleanup_mongo(self, relation: Relation) -> None:
        """Proceeds on relation broken.

        Raises:
            DeferrableError
            RelationBrokenDuringScaleDownError
            DeferrableFailedHookChecksError
            WorkloadServiceError
        """
        self.dependent.assert_proceed_on_broken_event(relation)
        try:
            self.remove_users_for_k8s_routers(relation)
        except PyMongoError:
            raise DeferrableError("Trouble removing router users")

        self.dependent.ldap_manager.update_hash_status()

        self.dependent.stop_charm_services()
        logger.info("Stopped mongos daemon")

        if not self.charm.unit.is_leader():
            return

        logger.info("Cleaning database and user removed for mongos application")
        self.state.cleanup_user_credentials()

        if self.substrate == Substrates.VM:
            self.dependent.remove_connection_info()
        else:
            self.state.db_initialised = False

    def cleanup_cluster_id(self) -> None:
        """On relation-broken event, the cluster ID is removed."""
        if not self.charm.unit.is_leader():
            return
        self.state.remove_cluster_id()

    def update_users_for_k8s_routers(self) -> None:
        """Updates users after being initialised."""
        # VM Mongos Charm is not in charge of its users because it is a
        # subordinate charm so we delegate everything to the MongoDB config
        # server.
        if self.substrate != Substrates.K8S:
            return

        if not self.state.has_credentials():
            # This happens if we haven't received yet credentials.
            logger.info("We haven't received credentials yet, exiting early.")
            raise DeferrableError("Credentials not received yet, can't reconcile users for mongos.")

        # We are a Kubernetes Mongos Charm so we are in charge of our client
        # applications and their users and we proceed to update the users and their DBs.
        try:
            for relation in self.state.client_relations:
                self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(relation)
        except (PyMongoError, FailedToGetHostsError, DatabaseRequestedHasNotRunYetError):
            raise DeferrableError("Failed to add users on mongos-k8s router.")

    def remove_users_for_k8s_routers(self, relation: Relation) -> None:
        """Handles the removal of all client mongos-k8s users and the mongos-k8s admin user.

        Raises:
            PyMongoError
        """
        # VM Mongos Charm is not in charge of its users because it is a
        # subordinate charm so we delegate everything to the MongoDB config
        # server.
        if self.substrate != Substrates.K8S:
            return

        if not self.charm.unit.is_leader():
            return

        if not self.state.has_credentials():
            # This happens in case of invalid integration, for example if it
            # was integrated with a shard instead of a config-server
            logger.info("No credentials found, not cleaning users.")
            return

        # We are a Kubernetes Mongos Charm so we are in charge of our client
        # applications and their users and we proceed to remove the users we manage and their DBs.
        for relation in self.state.client_relations:
            self.dependent.mongo_manager.remove_user(relation)
            data_interface = DatabaseProviderData(self.model, relation.name)
            fields = data_interface.fetch_my_relation_data([relation.id])[relation.id]

            data_str = relation.data[next(iter(relation.units))].get("data", "{}")
            secret_id = json.loads(data_str).get("secret-user")

            data_interface.delete_relation_data(relation.id, list(fields.keys()))

            if secret_id:
                user_secrets = self.charm.model.get_secret(id=secret_id)
                user_secrets.remove_all_revisions()
                user_secrets.get_content(refresh=True)
            relation.data[self.charm.app].clear()

        # Also remove the local user.
        with MongoConnection(self.state.mongo_config) as mongo:
            mongo.drop_user(mongo.config.username)

    def is_peer_ca_compatible(self) -> bool:
        """Returns true if both the mongos and the config-server use the same peer CA.

        Using the same peer CA is a requirement for sharded clusters.
        """
        if not self.state.mongos_cluster_relation:
            return True
        config_server_tls_ca = self.state.cluster.internal_ca_secret
        mongos_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)
        if not config_server_tls_ca or not mongos_tls_ca:
            return True

        return config_server_tls_ca == mongos_tls_ca

    def is_client_ca_compatible(self) -> bool:
        """Returns true if both the mongos and the config-server use the same client CA.

        Using the same client CA is a requirement for sharded clusters.
        """
        if not self.state.mongos_cluster_relation:
            return True
        config_server_tls_ca = self.state.cluster.external_ca_secret
        mongos_tls_ca = self.state.tls.get_secret(internal=False, label_name=SECRET_CA_LABEL)
        if not config_server_tls_ca or not mongos_tls_ca:
            return True

        return config_server_tls_ca == mongos_tls_ca

    def mongos_and_config_server_peer_tls_status(self) -> tuple[bool, bool]:
        """Returns the peer TLS integration status for mongos and config-server."""
        if self.state.mongos_cluster_relation:
            mongos_has_tls = self.state.tls.peer_enabled
            config_server_has_tls = self.state.cluster.internal_ca_secret is not None
            return mongos_has_tls, config_server_has_tls

        return False, False

    def mongos_and_config_server_client_tls_status(self) -> tuple[bool, bool]:
        """Returns the client TLS integration status for mongos and config-server."""
        if self.state.mongos_cluster_relation:
            mongos_has_tls = self.state.tls.client_enabled
            config_server_has_tls = self.state.cluster.external_ca_secret is not None
            return mongos_has_tls, config_server_has_tls

        return False, False

    def get_tls_state(self, internal: bool):
        """Computes the state of TLS for mongos.

        Args:
            internal: (bool) if true, represents the internal TLS, otherwise external TLS.
        """
        if internal:
            shard_tls, config_server_tls = self.mongos_and_config_server_peer_tls_status()
            is_ca_compatible = self.is_peer_ca_compatible()
        else:
            shard_tls, config_server_tls = self.mongos_and_config_server_client_tls_status()
            is_ca_compatible = self.is_client_ca_compatible()

        match (shard_tls, config_server_tls):
            case False, True:
                logger.warning(
                    "Config-Server uses peer TLS but mongos does not. Please synchronise encryption method."
                )
                return MongosTLSState.missing(internal=internal)
            case True, False:
                logger.warning(
                    "Mongos uses peer TLS but config-server does not. Please synchronise encryption method."
                )
                return MongosTLSState.invalid(internal=internal)
            case _:
                pass

        if not is_ca_compatible:
            logger.error(
                "Mongos is integrated to a different CA than the config server. Please use the same CA for all cluster components."
            )
            return MongosTLSState.incompatible(internal=internal)

        return MongosTLSState.VALID

    def get_tls_status(self, internal: bool) -> StatusObject | None:
        """Computes the TLS status for the scope.

        Args:
            internal: (bool) if true, represents the internal TLS, otherwise external TLS.
        """
        state = self.get_tls_state(internal=internal)

        return self.map_tls_state_to_status(state)

    def map_tls_state_to_status(self, state: MongosTLSState) -> StatusObject | None:
        """Maps the state to a status."""
        match state:
            case MongosTLSState.INTERNAL_MISSING:
                return MongosStatuses.missing_tls(internal=True)
            case MongosTLSState.EXTERNAL_MISSING:
                return MongosStatuses.missing_tls(internal=False)
            case MongosTLSState.INTERNAL_INVALID:
                return MongosStatuses.invalid_tls(internal=True)
            case MongosTLSState.EXTERNAL_INVALID:
                return MongosStatuses.invalid_tls(internal=False)
            case MongosTLSState.INTERNAL_INCOMPATIBLE:
                return MongosStatuses.incompatible_ca(internal=True)
            case MongosTLSState.EXTERNAL_INCOMPATIBLE:
                return MongosStatuses.incompatible_ca(internal=False)
            case _:
                return None

    def tls_statuses(self) -> list[StatusObject]:
        """Return statuses relevant to TLS."""
        statuses = []
        for internal in True, False:
            if status := self.get_tls_status(internal=internal):
                statuses.append(status)
        return statuses
