# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the cluster relation between config-server and mongos."""

from __future__ import annotations

import json
from logging import getLogger
from typing import TYPE_CHECKING

from ops import BlockedStatus
from ops.framework import Object
from ops.model import Relation, StatusBase
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import Scope, Substrates
from single_kernel_mongo.config.relations import RelationNames
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
            self.charm.status_manager.to_blocked(
                "Relation to mongos not supported, config role must be config-server"
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

    def is_valid_mongos_integration(self):
        """Returns True if the integration to mongos is valid."""
        return self.state.is_role(MongoDBRoles.CONFIG_SERVER) or not self.state.cluster_relations

    def on_database_requested(self, relation: Relation):
        """Handles the database requested event.

        The first time secrets are written to relations should be on this event.
        """
        self.assert_pass_hook_checks()

        config_server_db = self.state.generate_config_server_db()
        self.dependent.mongo_manager.oversee_relation(relation)
        relation_data = {
            ClusterStateKeys.keyfile.value: self.state.get_keyfile(),
            ClusterStateKeys.config_server_db.value: config_server_db,
        }

        int_tls_ca = self.state.tls.get_secret(label_name=SECRET_CA_LABEL, internal=True)

        if int_tls_ca:
            relation_data[ClusterStateKeys.int_ca_secret.value] = int_tls_ca

        self.data_interface.update_relation_data(relation.id, relation_data)

    def on_relation_changed(self, relation: Relation) -> None:
        """Handles providing mongos with keyfile and hosts."""
        # First we need to ensure that the database requested event has run
        # otherwise we risk the chance of writing secrets in plain sight.
        if not self.data_interface.fetch_relation_field(relation.id, "database"):
            logger.info("Database Requested has not run yet, skipping.")
            return

        self.on_database_requested(relation)

    def on_relation_broken(self, relation: Relation) -> None:
        """Handles the relation broken event.

        Needs to decide what we do based on the situation.
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
            self.dependent.mongo_manager.oversee_relation(relation, relation_departing=True)

    def update_config_server_db(self):
        """Updates the config server DB URI in the mongos relation."""
        self.assert_pass_hook_checks()

        config_server_db = self.state.generate_config_server_db()
        for relation in self.state.cluster_relations:
            self.data_interface.update_relation_data(
                relation.id,
                {
                    ClusterStateKeys.config_server_db.value: config_server_db,
                },
            )

    def update_ca_secret(self, new_ca: str | None) -> None:
        """Updates the new CA for all related shards."""
        for relation in self.state.cluster_relations:
            if new_ca is None:
                self.data_interface.delete_relation_data(
                    relation.id, [ClusterStateKeys.int_ca_secret]
                )
            else:
                self.data_interface.update_relation_data(
                    relation.id, {ClusterStateKeys.int_ca_secret.value: new_ca}
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

    def assert_pass_hook_checks(self):
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
        if not self.is_ca_compatible():
            raise DeferrableFailedHookChecksError(
                "mongos is integrated to a different CA than the config server. Please use the same CA for all cluster components."
            )
        if self.state.upgrade_in_progress:
            raise DeferrableError(
                "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )

    def relation_created(self) -> None:
        """Just sets a status on relation created."""
        logger.info("Integrating to config-server")
        self.charm.status_manager.to_waiting("Connecting to config-server")

    def on_database_created(self, username: str | None, password: str | None):
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
        self.state.secrets.set(AppPeerDataKeys.username.value, username, Scope.APP)
        self.state.secrets.set(AppPeerDataKeys.password.value, password, Scope.APP)

    def relation_changed(self) -> None:
        """Start/restarts mongos with config server information."""
        self.assert_pass_hook_checks()
        key_file_contents = self.state.cluster.keyfile
        config_server_db_uri = self.state.cluster.config_server_uri

        if not key_file_contents or not config_server_db_uri:
            raise WaitingForSecretsError("Waiting for keyfile or config server db uri")

        updated_keyfile = self.dependent.update_keyfile(key_file_contents)
        updated_config = self.dependent.update_config_server_db(config_server_db_uri)

        if updated_keyfile or updated_config or not self.dependent.is_mongos_running():
            logger.info("Restarting mongos with new secrets.")
            self.charm.status_manager.to_maintenance("starting mongos")
            self.dependent.restart_charm_services()

            # Restart on highly loaded databases can be very slow (up to 10-20 minutes).
            if not self.dependent.is_mongos_running():
                logger.info("Mongos has not started yet, deferring")
                self.charm.status_manager.to_waiting("Waiting for mongos to start")
                raise DeferrableError

        if self.charm.unit.is_leader():
            self.state.app_peer_data.db_initialised = True

        self.dependent.share_connection_info()
        self.charm.status_manager.process_and_share_statuses()

    def relation_broken(self, relation: Relation):
        """Proceeds on relation broken."""
        self.dependent.assert_proceed_on_broken_event(relation)
        try:
            self.remove_users(relation)
        except PyMongoError:
            raise DeferrableError("Trouble removing router users")

        if not self.charm.unit.is_leader():
            return

        logger.info("Cleaning database and user removed for mongos application")
        self.state.secrets.remove(Scope.APP, AppPeerDataKeys.username.value)
        self.state.secrets.remove(Scope.APP, AppPeerDataKeys.password.value)
        self.charm.status_manager.process_and_share_statuses()

    def update_users(self):
        """Updates users after being initialised."""
        if self.substrate != Substrates.K8S:
            return

        try:
            for relation in self.state.client_relations:
                self.dependent.mongo_manager.oversee_relation(relation)
        except PyMongoError:
            raise DeferrableError("Failed to add users on mongos-k8s router.")

    def remove_users(self, relation: Relation):
        """Handles the removal of all client mongos-k8s users and the mongos-k8s admin user.

        Raises:
            PyMongoError
        """
        if self.substrate != Substrates.K8S:
            return

        if not self.charm.unit.is_leader():
            return

        for relation in self.state.client_relations:
            self.dependent.mongo_manager.remove_user(relation)
            data_interface = DatabaseProviderData(self.model, relation.name)
            fields = data_interface.fetch_my_relation_data([relation.id])[relation.id]
            data_interface.delete_relation_data(relation.id, list(fields.keys()))
            secret_id = json.loads(
                data_interface.fetch_relation_field(relation.id, "data") or "{}"
            )["secret-user"]

            user_secrets = self.charm.model.get_secret(id=secret_id)
            user_secrets.remove_all_revisions()
            user_secrets.get_content(refresh=True)
            relation.data[self.charm.app].clear()

    def is_ca_compatible(self) -> bool:
        """Returns true if both the mongos and the config-server use the same CA."""
        config_server_relation = self.state.mongos_cluster_relation
        if not config_server_relation:
            return True
        config_server_tls_ca = self.state.cluster.internal_ca_secret
        mongos_tls_ca = self.state.tls.get_secret(internal=True, label_name=SECRET_CA_LABEL)
        if not config_server_tls_ca or not mongos_tls_ca:
            return True

        return config_server_tls_ca == mongos_tls_ca

    def tls_status(self) -> tuple[bool, bool]:
        """Returns the TLS integration status for mongos and config-server."""
        config_server_relation = self.state.mongos_cluster_relation
        if config_server_relation:
            mongos_has_tls = self.state.tls_relation is not None
            config_server_has_tls = self.state.cluster.internal_ca_secret is not None
            return mongos_has_tls, config_server_has_tls

        return False, False

    def get_tls_statuses(self) -> StatusBase | None:
        """Return statuses relevant to TLS."""
        mongos_has_tls, config_server_has_tls = self.tls_status()
        match (mongos_has_tls, config_server_has_tls):
            case False, True:
                return BlockedStatus("mongos requires TLS to be enabled.")
            case True, False:
                return BlockedStatus("mongos has TLS enabled but config-server does not.")
            case _:
                pass
        if not self.is_ca_compatible():
            logger.error(
                "mongos is integrated to a different CA than the config server. Please use the same CA for all cluster components."
            )
            return BlockedStatus("mongos CA and Config-Server CA don't match.")
        return None
