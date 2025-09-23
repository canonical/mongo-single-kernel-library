# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the cluster relation between config-server and mongos."""

from __future__ import annotations

import json
from logging import getLogger
from typing import TYPE_CHECKING

from data_platform_helpers.advanced_statuses.models import StatusObject
from ops.framework import Object
from ops.model import Relation
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import Scope, Substrates
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import CharmStatuses, MongoDBStatuses, MongosStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.app_peer_state import AppPeerDataKeys
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator
    from single_kernel_mongo.managers.mongos_operator import MongosOperator

logger = getLogger(__name__)


class ClusterProvider(Object):
    """Manage relations between the config server and mongos router on the config-server side."""

    def __init__(
        self,
        dependent: MongoDBOperator,
        state: CharmState,
        substrate: Substrates,
        relation_name: RelationNames = RelationNames.CLUSTER,
    ):
        super().__init__(parent=dependent, key=relation_name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = self.state.cluster_provider_data_interface

    def assert_pass_hook_checks(self) -> None:
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

        if self.state.upgrade_in_progress:
            raise DeferrableFailedHookChecksError(
                "Processing mongos applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )

    def is_valid_mongos_integration(self) -> bool:
        """Returns True if the integration to mongos is valid."""
        # The integration is valid if and only if we are a config server or if
        # we don't have any cluster relation.
        return self.state.is_role(MongoDBRoles.CONFIG_SERVER) or not self.state.cluster_relations

    def share_secret_to_mongos(self, relation: Relation) -> None:
        """Handles the database requested event.

        The first time secrets are written to relations should be on this event.
        """
        self.assert_pass_hook_checks()

        config_server_db = self.state.generate_config_server_db()
        self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(relation)
        relation_data = {
            ClusterStateKeys.KEYFILE.value: self.state.get_keyfile(),
            ClusterStateKeys.CONFIG_SERVER_DB.value: config_server_db,
        }

        if int_tls_ca := self.state.tls.get_secret(label_name=SECRET_CA_LABEL, internal=True):
            relation_data[ClusterStateKeys.INT_CA_SECRET.value] = int_tls_ca

        if hashed_data := self.dependent.ldap_manager.get_hash():
            relation_data[ClusterStateKeys.LDAP_HASH.value] = hashed_data

        # We want to avoid having to configure both applications with the exact
        # same string so the config-server shares it with the client.
        if ldap_user_to_dn_mapping := self.state.ldap.ldap_user_to_dn_mapping:
            relation_data[ClusterStateKeys.LDAP_USER_TO_DN_MAPPING.value] = ldap_user_to_dn_mapping

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
        if self.state.upgrade_in_progress:
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
            self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(
                relation, relation_departing=True
            )

    def update_config_server_db(self) -> None:
        """Updates the config server DB URI in the mongos relation."""
        self.assert_pass_hook_checks()

        config_server_db = self.state.generate_config_server_db()
        for relation in self.state.cluster_relations:
            if not self.data_interface.fetch_relation_field(relation.id, "database"):
                logger.info("Database Requested has not run yet, skipping.")
                continue
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
        super().__init__(parent=dependent, key=relation_name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.state = state
        self.workload = workload
        self.substrate = substrate
        self.relation_name = relation_name
        self.data_interface = self.state.cluster_requirer_data_interface

    def assert_pass_hook_checks(self) -> None:
        """Runs pre-hook checks, raises if one fails."""
        mongos_has_tls, config_server_has_tls = self.tls_status()
        match (mongos_has_tls, config_server_has_tls):
            case False, True:
                raise DeferrableFailedHookChecksError(
                    "Config-Server uses TLS but mongos does not. Please synchronise encryption method."
                )
            case True, False:
                raise DeferrableFailedHookChecksError(
                    "Mongos uses TLS but config-server does not. Please synchronise encryption method."
                )
            case _:
                pass
        if self.is_waiting_to_request_certs():
            raise DeferrableFailedHookChecksError(
                "Mongos was waiting for config-server to enable TLS. Wait for TLS to be enabled until starting mongos."
            )
        if self.state.upgrade_in_progress:
            raise DeferrableFailedHookChecksError(
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
        if self.state.upgrade_in_progress:
            logger.warning(
                "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            raise DeferrableFailedHookChecksError

        if not self.charm.unit.is_leader():
            return

        logger.info("Database and user created for mongos application.")
        self.state.secrets.set(AppPeerDataKeys.USERNAME.value, username, Scope.APP)
        self.state.secrets.set(AppPeerDataKeys.PASSWORD.value, password, Scope.APP)

    def update_mongos_and_restart(self) -> None:
        """Start/restarts mongos with config server information."""
        self.assert_pass_hook_checks()
        key_file_contents = self.state.cluster.keyfile
        config_server_db_uri = self.state.cluster.config_server_uri

        if self.charm.unit.is_leader() and (
            ldap_user_to_dn_mapping := self.state.cluster.ldap_user_to_dn_mapping
        ):
            logger.debug("Received a userToDNMapping, storing it in databag.")
            self.state.ldap.ldap_user_to_dn_mapping = ldap_user_to_dn_mapping

        if not key_file_contents or not config_server_db_uri:
            raise WaitingForSecretsError("Waiting for keyfile or config server db uri")

        updated_keyfile = self.dependent.update_keyfile(key_file_contents)
        updated_config = self.dependent.update_config_server_db(config_server_db_uri)

        if updated_keyfile or updated_config or not self.dependent.is_mongos_running():
            logger.info("Restarting mongos with new secrets.")
            self.charm.status_handler.set_running_status(
                MongosStatuses.STARTING_MONGOS.value, scope="unit"
            )

            self.dependent.restart_charm_services()

            # Restart on highly loaded databases can be very slow (up to 10-20 minutes).
            if not self.dependent.is_mongos_running():
                logger.info("Mongos has not started yet, deferring")
                self.state.statuses.set(
                    MongosStatuses.WAITING_FOR_MONGOS_START.value,
                    scope="unit",
                    component=self.dependent.name,
                )
                raise DeferrableError

        self.state.statuses.set(
            CharmStatuses.ACTIVE_IDLE.value, scope="unit", component=self.dependent.name
        )
        if self.charm.unit.is_leader():
            self.state.app_peer_data.db_initialised = True
            # In the K8S case, create the user
            self.update_users_for_k8s_routers()

        self.dependent.share_connection_info()

    def remove_users_and_cleanup_mongo(self, relation: Relation) -> None:
        """Proceeds on relation broken."""
        self.dependent.assert_proceed_on_broken_event(relation)
        try:
            self.remove_users_for_k8s_routers(relation)
        except PyMongoError:
            raise DeferrableError("Trouble removing router users")

        self.dependent.stop_charm_services()
        logger.info("Stopped mongos daemon")

        if not self.charm.unit.is_leader():
            return

        logger.info("Cleaning database and user removed for mongos application")
        self.state.secrets.remove(Scope.APP, AppPeerDataKeys.USERNAME.value)
        self.state.secrets.remove(Scope.APP, AppPeerDataKeys.PASSWORD.value)

        if self.substrate == Substrates.VM:
            self.dependent.remove_connection_info()
        else:
            self.state.db_initialised = False

    def update_users_for_k8s_routers(self) -> None:
        """Updates users after being initialised."""
        # VM Mongos Charm is not in charge of its users because it is a
        # subordinate charm so we delegate everything to the MongoDB config
        # server.
        if self.substrate != Substrates.K8S:
            return

        # We are a Kubernetes Mongos Charm so we are in charge of our client
        # applications and their users and we proceed to update the users and their DBs.
        try:
            for relation in self.state.client_relations:
                self.dependent.mongo_manager.reconcile_mongo_users_and_dbs(relation)
        except PyMongoError:
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

    def is_ca_compatible(self) -> bool:
        """Returns true if both the mongos and the config-server use the same CA.

        Using the same CA is a requirement for sharded clusters.
        """
        if not self.state.mongos_cluster_relation:
            return True
        config_server_tls_ca = self.state.cluster.internal_ca_secret
        mongos_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)
        if not config_server_tls_ca or not mongos_tls_ca:
            return True

        return config_server_tls_ca == mongos_tls_ca

    def is_waiting_to_request_certs(self) -> bool:
        """Returns True if mongos has been waiting for config server in order to request certs."""
        if not self.state.tls_relation:
            return False
        mongos_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)

        # our CA is none until certs have been requested. We cannot request certs until integrated
        # to config-server.
        return not mongos_tls_ca

    def tls_status(self) -> tuple[bool, bool]:
        """Returns the TLS integration status for mongos and config-server."""
        if self.state.mongos_cluster_relation:
            mongos_has_tls = self.state.tls_relation is not None
            config_server_has_tls = self.state.cluster.internal_ca_secret is not None
            return mongos_has_tls, config_server_has_tls

        return False, False

    def get_tls_statuses(self) -> StatusObject | None:
        """Return statuses relevant to TLS."""
        mongos_has_tls, config_server_has_tls = self.tls_status()
        match (mongos_has_tls, config_server_has_tls):
            case False, True:
                return MongosStatuses.MISSING_TLS_REL.value
            case True, False:
                return MongosStatuses.INVALID_TLS_REL.value
            case _:
                pass
        if not self.is_ca_compatible():
            logger.error(
                "mongos is integrated to a different CA than the config server. Please use the same CA for all cluster components."
            )
            return MongosStatuses.CA_MISMATCH.value
        return None
