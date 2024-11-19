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
import re
from typing import TYPE_CHECKING

from dacite import from_dict
from ops import EventBase, Object
from ops.charm import RelationChangedEvent
from ops.model import Relation

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongo_config import (
    EMPTY_CONFIGURATION,
    MongoConfiguration,
)
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    BackupUser,
    MonitorUser,
    OperatorUser,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

logger = logging.getLogger(__name__)


class MongoManager(Object):
    """Manager for Mongo related operations."""

    def __init__(
        self,
        charm: AbstractMongoCharm,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        self.charm = charm
        self.workload = workload
        self.state = state
        self.substrate = substrate
        pod_name = self.model.unit.name.replace("/", "-")
        self.k8s = K8sManager(pod_name, self.model.name)

    @property
    def mongod_ready(self) -> bool:
        """Is MongoDB ready and running?"""
        empty_config = EMPTY_CONFIGURATION
        with MongoConnection(empty_config, "localhost", direct=True) as direct_mongo:
            return direct_mongo.is_ready

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

    def oversee_users(self, relation_id: int | None = None, event: EventBase | None = None):
        """Oversees the users of the application.

        Function manages user relations by removing, updated, and creating
        users; and dropping databases when necessary.

        Args:
            departed_relation_id: When specified execution of functions
                makes sure to exclude the users and databases and remove
                them if necessary.
            event: relation event.

        When the function is executed in relation departed event, the departed
        relation is still on the list of all relations. Therefore, for proper
        work of the function, we need to exclude departed relation from the list.

        Raises:
            PyMongoError
        """
        with MongoConnection(self.state.mongo_config) as mongo:
            database_users = mongo.get_users()

        users_being_managed = database_users.intersection(self.state.app_peer_data.managed_users)
        relations = self.model.relations[self.get_relation_name()]
        expected_current_users = {
            f"relation-{relation.id}" for relation in relations if relation.id != relation_id
        }
        self.remove_users(users_being_managed, expected_current_users)
        self.add_users(users_being_managed, expected_current_users)
        self.update_users(users_being_managed, expected_current_users)
        self.update_diff(event)
        self.auto_delete_dbs(relation_id)

    def update_diff(self, event: EventBase | None = None) -> None:
        """Update the relation databag with the diff of data.

        Args:
            event: An event. Does nothing if this event is not a RelationChangedEvent.
        """
        if not isinstance(event, RelationChangedEvent):
            logger.info("Cannot compute diff of event type: %s", type(event))
            return

        new_data = {
            key: value for key, value in event.relation.data[event.app].items() if key != "data"
        }
        event.relation.data[self.charm.model.app].update({"data": json.dumps(new_data)})

    def add_users(self, users_being_managed: set[str], expected_current_users: set[str]) -> None:
        """Adds users to Charmed MongoDB.

        Args:
            users_being_managed: The users managed by the Charm.
            expected_current_users: The expected users after this call.

        Raises:
            PyMongoError
        """
        managed_users = self.state.app_peer_data.managed_users
        with MongoConnection(self.state.mongo_config) as mongo:
            for username in expected_current_users - users_being_managed:
                relation = self._get_relation_from_username(username)
                data_interface = DatabaseProviderData(
                    self.model,
                    relation.name,
                )
                config = self.get_config(
                    username,
                    None,
                    data_interface,
                    relation.id,
                )
                if config.database is None:
                    # We need to wait for the moment when the provider library
                    # set the database name into the relation.
                    continue
                logger.info("Create relation user: %s on %s", config.username, config.database)

                mongo.create_user(config)
                managed_users.add(username)
                data_interface.set_database(relation.id, config.database)

        self.state.app_peer_data.managed_users = managed_users

    def update_users(self, users_being_managed: set[str], expected_current_users: set[str]) -> None:
        """Updates existing users in Charmed MongoDB.

        Raises:
            PyMongoError
        """
        with MongoConnection(self.state.mongo_config) as mongo:
            for username in expected_current_users.intersection(users_being_managed):
                relation = self._get_relation_from_username(username)
                data_interface = DatabaseProviderData(
                    self.model,
                    relation.name,
                )
                config = self.get_config(
                    username,
                    None,
                    data_interface,
                    relation.id,
                )
                logger.info("Update relation user: %s on %s", config.username, config.database)
                mongo.update_user(config)
                logger.info("Updating relation data according to diff")

    def update_app_relation_data(self) -> None:
        """Helper function to update application relation data."""
        # TODO: Add sanity checks.
        # if not self.pass_sanity_hook_checks():
        #    return

        # relations with the mongos server should not connect through the config-server directly
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return
        database_users = set()

        with MongoConnection(self.state.mongo_config) as mongo:
            database_users = mongo.get_users()

        relations = self.model.relations[self.get_relation_name()]

        for relation in relations:
            data_interface = DatabaseProviderData(self.model, relation.name)
            if not data_interface.fetch_relation_field(relation.id, "database"):
                continue
            username = data_interface.fetch_relation_field(relation.id, "username")
            password = data_interface.fetch_relation_field(relation.id, "password")

            if not username or not password:
                username = f"relation-{relation.id}"
                password = self.workload.generate_password()

            config = self.get_config(
                username,
                password,
                data_interface,
                relation.id,
            )

            data_interface.set_credentials(
                relation.id,
                username,
                password,
            )
            if username in database_users:
                data_interface.set_endpoints(
                    relation.id,
                    ",".join(config.hosts),
                )
                data_interface.set_uris(
                    relation.id,
                    config.uri,
                )

    def remove_users(self, users_being_managed: set[str], expected_current_users: set[str]) -> None:
        """Removes users from Charmed MongoDB.

        Note this only removes users that this application of Charmed MongoDB is responsible for
        managing. It won't remove:
        1. users created from other applications
        2. users created from other mongos routers.

        Raises:
            PyMongoError
        """
        mongo_config = self.state.mongo_config
        managed_users = self.state.app_peer_data.managed_users
        with MongoConnection(mongo_config) as mongo:
            for username in users_being_managed - expected_current_users:
                logger.info("Remove relation user: %s", username)
                # Skip our user.
                if self.state.is_role(MongoDBRoles.MONGOS) and username == mongo_config.username:
                    continue

                # for user removal of mongos-k8s router, we let the router remove itself
                if self.state.is_role(MongoDBRoles.CONFIG_SERVER) and self.substrate == "k8s":
                    logger.info("K8s routers will remove themselves.")
                    managed_users.remove(username)
                    continue

                mongo.drop_user(username)
                managed_users.remove(username)
        self.state.app_peer_data.managed_users = managed_users

    def auto_delete_dbs(self, relation_id: int | None) -> None:
        """Delete unused DBs if configured to do so."""
        with MongoConnection(self.state.mongo_config) as mongo:
            if not self.state.config.auto_delete:
                return

            relations = self.model.relations[self.get_relation_name()]
            database_dbs = mongo.get_databases()
            relation_dbs = set()
            for relation in relations:
                if relation.id == relation_id:
                    continue
                data_interface = DatabaseProviderData(self.model, relation.name)
                database = data_interface.fetch_relation_field(relation.id, "database")
                if database is not None:
                    relation_dbs.add(database)
            for database in database_dbs - relation_dbs:
                logger.info("Drop database: %s", database)
                mongo.drop_database(database)

    def get_config(
        self,
        username: str,
        password: str | None,
        data_inteface: DatabaseProviderData,
        relation_id: int,
    ) -> MongoConfiguration:
        """."""
        password = password or data_inteface.fetch_my_relation_field(relation_id, "password")
        if not password:
            password = self.workload.generate_password()
            data_inteface.set_credentials(relation_id, username, password)
        database_name = data_inteface.fetch_relation_field(relation_id, "database")
        roles = data_inteface.fetch_relation_field(relation_id, "extra-user-roles")
        if not database_name or not roles:
            raise Exception("Missing database name or roles.")
        mongo_args = {
            "database": database_name,
            "username": username,
            "password": password,
            "hosts": self.state.app_hosts,
            "roles": roles,
            "tls_external": False,
            "tls_internal": False,
            "port": self.state.host_port,
        }
        if not self.state.is_role(MongoDBRoles.MONGOS):
            mongo_args["replset"] = self.state.app_peer_data.replica_set
        return from_dict(data_class=MongoConfiguration, data=mongo_args)

    def _get_relation_from_username(self, username: str) -> Relation:
        """Parse relation ID from a username and return Relation object."""
        match = re.match(r"^relation-(\d+)$", username)
        # We generated username in `_get_users_from_relations`
        # func and passed it into this function later.
        # It means the username here MUST match regex.
        if not match:
            raise Exception("No relation match")
        relation_id = int(match.group(1))
        logger.debug("Relation ID: %s", relation_id)
        relation_name = self.get_relation_name()
        relation = self.model.get_relation(relation_name, relation_id)
        if not relation:
            raise Exception("No relation match")
        return relation

    def get_relation_name(self):
        """Returns the name of the relation to use."""
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return RelationNames.CLUSTER
        if self.state.is_role(MongoDBRoles.MONGOS):
            return RelationNames.MONGOS_PROXY
        return RelationNames.DATABASE
