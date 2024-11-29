#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Mongo manager.

In this class, we manage the mongo database internals.

This class is in charge of creating users, databases, initialising replicat sets, etc.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from dacite import from_dict
from ops import Object
from ops.model import Relation
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import DatabaseRequestedHasNotRunYetError, SetPasswordError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongo_config import (
    EMPTY_CONFIGURATION,
    MongoConfiguration,
)
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger(__name__)


class MongoManager(Object):
    """Manager for Mongo related operations."""

    def __init__(
        self,
        dependent: OperatorProtocol,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        super().__init__(parent=dependent, key="managers")
        self.charm = dependent.charm
        self.workload = workload
        self.state = state
        self.substrate = substrate
        pod_name = self.model.unit.name.replace("/", "-")
        self.k8s = K8sManager(pod_name, self.model.name)

    def mongod_ready(self, uri: str | None = None) -> bool:
        """Is MongoDB ready and running?"""
        config = EMPTY_CONFIGURATION
        actual_uri = uri or "localhost"
        with MongoConnection(config, actual_uri, direct=True) as direct_mongo:
            return direct_mongo.is_ready

    def set_user_password(self, user: MongoDBUser, password: str) -> str:
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

        return self.state.set_user_password(user, password)

    def initialise_replica_set(self) -> None:
        """Initialises the replica set."""
        with MongoConnection(self.state.mongo_config, "localhost", direct=True) as direct_mongo:
            direct_mongo.init_replset()
            self.state.app_peer_data.replica_set_hosts = [self.state.unit_peer_data.host]

    def initialise_users(self) -> None:
        """First initialisation of each user."""
        self.initialise_operator_user()
        self.initialise_monitor_user()
        self.initialise_backup_user()

    def initialise_operator_user(self):
        """Creates initial admin user for MongoDB.

        Initial admin user can be created only through localhost connection.
        see https://www.mongodb.com/docs/manual/core/localhost-exception/
        unfortunately, pymongo unable to create connection that considered
        as local connection by MongoDB, even if socket connection used.
        As a result, where are only hackish ways to create initial user.
        It is needed to install mongodb-clients inside charm container to make
        this function work correctly.
        """
        if self.state.app_peer_data.is_user_created(OperatorUser.username):
            return
        config = self.state.mongo_config
        with MongoConnection(config, "localhost", direct=True) as direct_mongo:
            direct_mongo.create_user(config=config, roles=OPERATOR_ROLE)
        self.state.app_peer_data.set_user_created(OperatorUser.username)

    def initialise_monitor_user(self):
        """Creates the monitor user on the MongoDB database."""
        if self.state.app_peer_data.is_user_created(MonitorUser.username):
            return
        with MongoConnection(self.state.mongo_config) as mongo:
            logger.debug("Creating the monitor user roles…")
            mongo.create_role(
                role_name=MonitorUser.mongodb_role,
                privileges=MonitorUser.privileges,
            )
            logger.debug("creating the monitor user...")
            mongo.create_user(self.state.monitor_config)
        self.state.app_peer_data.set_user_created(MonitorUser.username)

    def initialise_backup_user(self):
        """Creates the monitor user on the MongoDB database."""
        if self.state.app_peer_data.is_user_created(BackupUser.username):
            return
        with MongoConnection(self.state.mongo_config) as mongo:
            logger.debug("Creating the backup user roles…")
            mongo.create_role(
                role_name=BackupUser.mongodb_role,
                privileges=BackupUser.privileges,
            )
            logger.debug("creating the backup user...")
            mongo.create_user(self.state.backup_config)
        self.state.app_peer_data.set_user_created(BackupUser.username)

    def oversee_relation(
        self, relation: Relation, relation_departing: bool = False, relation_changed: bool = False
    ):
        """Oversees the users of the relation.

        Function manages user by removing, updated, and creating
        users; and dropping databases when necessary.

        Args:
            relation: The relation are working with.
            departing: If this is a relation broken event.
            event: relation event or None.

        Raises:
            PyMongoError
        """
        self.add_user(relation)
        self.update_user(relation)
        if relation_departing:
            self.remove_user(relation)
            self.auto_delete_db(relation)
        if relation_changed:
            self.update_diff(relation)

    def update_diff(self, relation: Relation):
        """Update the relation databag with the diff of data.

        Args:
            relation: The relation to update the databag from.
        """
        if not self.charm.unit.is_leader():
            return
        data_interface = DatabaseProviderData(
            self.model,
            relation.name,
        )
        actual_data = data_interface.fetch_relation_data([relation.id]).get(relation.id, {})
        new_data = {key: value for key, value in actual_data.items() if key != "data"}
        data_interface.update_relation_data(relation.id, {"data": json.dumps(new_data)})

    def add_user(self, relation: Relation):
        """Add a user for this relation."""
        managed_users = self.state.app_peer_data.managed_users
        data_interface = DatabaseProviderData(
            self.model,
            relation.name,
        )
        # We do nothing if the Database Requested event has not run yet.
        if not data_interface.fetch_relation_field(relation.id, "database"):
            logger.info(f"Database Requested for {relation} has not run yet, skipping.")
            raise DatabaseRequestedHasNotRunYetError

        username = f"relation-{relation.id}"
        with MongoConnection(self.state.mongo_config) as mongo:
            has_user = mongo.user_exists(username)

        # We do nothing if the user already exists in DB.
        if has_user:
            return

        with MongoConnection(self.state.mongo_config) as mongo:
            config = self.get_config(
                username,
                None,  # We are creating the user, which means we don't have password for it yet
                data_interface,
                relation.id,
            )
            logger.info("Create relation user: %s on %s", config.username, config.database)

            mongo.create_user(config)
            managed_users.add(username)
            data_interface.set_database(relation.id, config.database)
            data_interface.set_credentials(relation.id, config.username, config.password)

        self.state.app_peer_data.managed_users = managed_users

    def update_user(self, relation: Relation) -> None:
        """Add the user for this relation."""
        data_interface = DatabaseProviderData(
            self.model,
            relation.name,
        )

        username = f"relation-{relation.id}"
        password = data_interface.fetch_my_relation_field(relation.id, "password")
        with MongoConnection(self.state.mongo_config) as mongo:
            has_user = mongo.user_exists(username)
        if has_user:
            return
        with MongoConnection(self.state.mongo_config) as mongo:
            config = self.get_config(
                username,
                password,
                data_interface,
                relation.id,
            )

            logger.info("Update relation user: %s on %s", config.username, config.database)
            mongo.update_user(config)
            logger.info("Updating relation data according to diff")

    def remove_user(self, relation: Relation):
        """Removes a user from Charmed MongoDB.

        Note this only removes users that this application of Charmed MongoDB is responsible for
        managing. It won't remove:
        1. users created from other applications
        2. users created from other mongos routers.

        Raises:
            PyMongoError
        """
        username = f"relation-{relation.id}"
        managed_users = self.state.app_peer_data.managed_users
        mongo_config = self.state.mongo_config
        with MongoConnection(mongo_config) as mongo:
            logger.info("Remove relation user: %s", username)
            # Skip our user.
            if self.state.is_role(MongoDBRoles.MONGOS) and username == mongo_config.username:
                return
            # for user removal of mongos-k8s router, we let the router remove itself
            if self.substrate == Substrates.K8S and self.state.is_role(MongoDBRoles.CONFIG_SERVER):
                logger.info("K8s routers will remove themselves.")
                managed_users.remove(username)
                self.state.app_peer_data.managed_users = managed_users
                return
            mongo.drop_user(username)
            managed_users.remove(username)
        self.state.app_peer_data.managed_users = managed_users

    def update_app_relation_data(self, relation: Relation) -> None:
        """Helper function to update this application relation data."""
        if not self.charm.unit.is_leader():
            return
        if not self.state.db_initialised:
            return
        data_interface = DatabaseProviderData(self.model, relation.name)
        if not data_interface.fetch_relation_field(relation.id, "database"):
            return
        username = data_interface.fetch_my_relation_field(relation.id, "username")
        password = data_interface.fetch_my_relation_field(relation.id, "password")
        endpoints = data_interface.fetch_my_relation_field(relation.id, "endpoints") or ""
        uris = data_interface.fetch_my_relation_field(relation.id, "uris")
        if not username or not password:
            username = username or f"relation-{relation.id}"
            password = password or self.workload.generate_password()
            # Only set some of it was missing.
            data_interface.set_credentials(
                relation.id,
                username,
                password,
            )
        config = self.get_config(
            username,
            password,
            data_interface,
            relation.id,
        )
        with MongoConnection(self.state.mongo_config) as mongo:
            user_exists = mongo.user_exists(username)
        if user_exists:
            if config.hosts != set(endpoints.split(",")):
                data_interface.set_endpoints(
                    relation.id,
                    ",".join(config.hosts),
                )
            if config.uri != uris:
                data_interface.set_uris(
                    relation.id,
                    config.uri,
                )

    def auto_delete_db(self, relation: Relation) -> None:
        """Delete a DB if necessary."""
        with MongoConnection(self.state.mongo_config) as mongo:
            if not self.state.config.auto_delete:
                return
            data_interface = DatabaseProviderData(self.model, relation.name)
            database = data_interface.fetch_relation_field(relation.id, "database")
            if not database:  # Early return, no database to delete.
                return
            if database not in mongo.get_databases():  # Early return, database not in mongodb
                return
            logger.info(f"Drop database: {database}")
            mongo.drop_database(database)

    def get_config(
        self,
        username: str,
        password: str | None,
        data_inteface: DatabaseProviderData,
        relation_id: int,
    ) -> MongoConfiguration:
        """."""
        if not password:
            password = self.workload.generate_password()
        database_name = data_inteface.fetch_relation_field(relation_id, "database")
        roles = data_inteface.fetch_relation_field(relation_id, "extra-user-roles") or "default"
        if not database_name or not roles:
            raise Exception("Missing database name or roles.")
        mongo_args = {
            "database": database_name,
            "username": username,
            "password": password,
            "hosts": self.state.app_hosts,
            "roles": set(roles.split(",")),
            "tls_external": False,
            "tls_internal": False,
            "port": self.state.host_port,
        }
        if not self.state.is_role(MongoDBRoles.MONGOS):
            mongo_args["replset"] = self.state.app_peer_data.replica_set
        return from_dict(data_class=MongoConfiguration, data=mongo_args)

    def set_election_priority(self, priority: int):
        """Sets the election priority."""
        with MongoConnection(self.state.mongo_config) as mongo:
            mongo.set_replicaset_election_priority(priority=priority)

    def process_unremoved_units(self) -> None:
        """Remove units from replica set."""
        with MongoConnection(self.state.mongo_config) as mongo:
            try:
                replset_members = mongo.get_replset_members()
                for member in replset_members - mongo.config.hosts:
                    logger.debug("Removing %s from replica set", member)
                    mongo.remove_replset_member(member)
            except NotReadyError:
                logger.info("Deferring process_unremoved_units: another member is syncing")
                raise
            except PyMongoError as e:
                logger.error("Deferring process_unremoved_units: error=%r", e)
                raise

    def remove_replset_member(self) -> None:  # pragma: nocover
        """Remove a unit from the replicaset."""
        with MongoConnection(self.state.mongo_config) as mongo:
            mongo.remove_replset_member(self.state.unit_peer_data.host)

    def process_added_units(self) -> None:
        """Adds units to replica set."""
        with MongoConnection(self.state.mongo_config) as mongo:
            replset_members = mongo.get_replset_members()
            config_hosts = mongo.config.hosts
            # compare set of mongod replica set members and juju hosts to avoid the unnecessary
            # reconfiguration.
            if replset_members == config_hosts:
                return

            for member in config_hosts - replset_members:
                logger.debug("Adding %s to replica set", member)
                if not self.mongod_ready(uri=member):
                    logger.debug("not reconfiguring: %s is not ready yet.", member)
                    raise NotReadyError
                mongo.add_replset_member(member)

    # Keep for memory for now.
    # def get_relation_name(self):
    #    """Returns the name of the relation to use."""
    #    if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
    #        return RelationNames.CLUSTER
    #    if self.state.is_role(MongoDBRoles.MONGOS):
    #        return RelationNames.MONGOS_PROXY
    #    return RelationNames.DATABASE
