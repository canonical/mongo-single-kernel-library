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
from typing import TYPE_CHECKING, final
from urllib.parse import urlencode

from dacite import from_dict
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import (
    AbstractManagerStatus,
)
from data_platform_helpers.advanced_statuses.types import Scope
from ops import Object
from ops.model import Relation
from pymongo.errors import (
    AutoReconnect,
    OperationFailure,
    PyMongoError,
    ServerSelectionTimeoutError,
    WriteConcernError,
)
from tenacity import Retrying, stop_after_attempt, wait_fixed

from single_kernel_mongo.config.literals import MongoPorts, Substrates
from single_kernel_mongo.config.statuses import CharmStatuses, MongodStatuses
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.exceptions import (
    DatabaseRequestedHasNotRunYetError,
    DeployedWithoutTrustError,
    FailedToElectNewPrimaryError,
    InvalidEntityRequestError,
    MissingCredentialsError,
    SetPasswordError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from single_kernel_mongo.utils.mongo_config import (
    EMPTY_CONFIGURATION,
    MongoConfiguration,
)
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    AuthRestrictions,
    CharmedBackupUser,
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
    MongoDBUser,
    roles_for_database,
    same_role_definition,
)
from single_kernel_mongo.utils.network_helpers import (
    cidrs,
    get_cidr_for_ip_list,
    network_for_relation,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import MainWorkloadType, OperatorProtocol

logger = logging.getLogger(__name__)


@final
class MongoManager(Object, AbstractManagerStatus[CharmState]):
    """Manager for Mongo related operations."""

    def __init__(
        self,
        dependent: OperatorProtocol,
        workload: MainWorkloadType,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        super().__init__(parent=dependent, key="managers")
        self.name: str = "mongo"
        self.charm: AbstractMongoCharm[MongoConfigModel, OperatorProtocol] = dependent.charm
        self.workload: MainWorkloadType = workload
        self.state: CharmState = state
        self.substrate: Substrates = substrate

        pod_name = self.model.unit.name.replace("/", "-")
        self.k8s = K8sManager(pod_name, self.model.name)
        if self.substrate == Substrates.K8S:
            try:
                self.k8s.get_pod()
            except DeployedWithoutTrustError:
                self.state.statuses.add(
                    CharmStatuses.DEPLOYED_WITHOUT_TRUST.value,
                    scope="unit",
                    component=self.charm.name,
                )

    def mongod_ready(self, uri: str | None = None, direct: bool = True) -> bool:
        """Is MongoDB ready and running?

        Pass direct=True, when checking if a *single replica* is ready.
        Pass direct=False, when checking if the entire replica set is ready
        """
        port = (
            MongoPorts.MONGOS_PORT.value
            if self.state.is_role(MongoDBRoles.MONGOS)
            else MongoPorts.MONGODB_PORT.value
        )
        params = self.state.operator_config.tls_config

        actual_uri = uri or f"mongodb://localhost:{port}"
        actual_uri = f"{actual_uri}/?{urlencode(params)}"

        try:
            with MongoConnection(EMPTY_CONFIGURATION, actual_uri, direct=direct) as direct_mongo:
                return direct_mongo.is_ready
        except FileNotFoundError as e:
            # Handle the missing external-cert.pem file because the unit is waiting a restart.
            logger.warning("Failed to connect to mongod: %s", e)
            return False

    def set_user_password(self, user: MongoDBUser, password: str) -> None:
        """Sets the password for a given username in the workload and secrets.

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

        self.state.set_user_password(user, password)

    def initialise_replica_set(self) -> None:
        """Initialises the replica set."""
        # We build a config with a single host, the others will be added afterwards.
        with MongoConnection(self.state.mongo_config, "localhost", direct=True) as direct_mongo:
            direct_mongo.init_replset(host=self.state.unit_peer_data.internal_address)

    def initialise_charm_admin_users(self) -> None:
        """First initialisation of each user."""
        self._initialise_charmed_operator_user()
        self._initialise_user(CharmedStatsUser)
        self._initialise_user(CharmedBackupUser)
        self._initialise_user(CharmedLogRotateUser)

    def _initialise_charmed_operator_user(self):
        """Creates initial admin user for MongoDB.

        Initial admin user can be created only through localhost connection.
        see https://www.mongodb.com/docs/manual/core/localhost-exception/
        unfortunately, pymongo unable to create connection that considered
        as local connection by MongoDB, even if socket connection used.
        As a result, where are only hackish ways to create initial user.
        It is needed to install mongodb-clients inside charm container to make
        this function work correctly.
        """
        if self.state.app_peer_data.is_user_created(CharmedOperatorUser.username):
            return
        config = self.state.mongo_config
        cmd = [
            "--quiet",
            "--eval",
            '"db.createUser({'
            f"  user: '{config.username}',"
            "  pwd: passwordPrompt(),"
            f"  roles: {OPERATOR_ROLE},"
            "  mechanisms: ['SCRAM-SHA-256'],"
            "  passwordDigestor: 'server',"
            '})"',
        ]
        self.workload.run_bin_command("mongodb://localhost/admin", cmd, input=config.password)
        self.state.app_peer_data.set_user_created(CharmedOperatorUser.username)

    def _initialise_user(self, user: MongoDBUser):
        """Creates a user and sets its role on the MongoDB database."""
        if self.state.app_peer_data.is_user_created(user.username):
            return
        with MongoConnection(self.state.mongo_config) as mongo:
            logger.info(f"Creating the {user.username} user roles…")
            mongo.create_role(
                role_name=user.mongodb_role,
                privileges=user.privileges,
            )
            logger.info(f"Creating the {user.username} user...")
            config = self.state.mongodb_config_for_user(
                user, auth_restrictions=self.state.local_auth_restrictions
            )
            mongo.create_user(
                config.username,
                config.password,
                config.supported_roles,
                auth_restrictions=config.auth_restrictions,
            )

        self.state.app_peer_data.set_user_created(user.username)

    def update_users_local_auth_restrictions(
        self, auth_restrictions: list[AuthRestrictions]
    ) -> None:
        """Update auth restrictions for internal users that connect locally.

        Args:
            auth_restrictions: The auth restrictions to apply.
        """
        for user in (CharmedStatsUser, CharmedBackupUser, CharmedLogRotateUser):
            if not self.state.app_peer_data.is_user_created(user.username):
                continue
            with MongoConnection(self.state.mongo_config) as mongo:
                config = self.state.mongodb_config_for_user(
                    user, auth_restrictions=auth_restrictions
                )
                mongo.update_user_auth_restrictions(config)

    def update_cluster_ip_source_allowlist(self, allowlist: list[str]) -> None:
        """Update the cluster IP source allowlist at runtime."""
        config = self.state.mongodb_config_for_user(
            CharmedOperatorUser, hosts={"localhost"}, standalone=True
        )
        with MongoConnection(config, direct=True) as mongo:
            mongo.set_cluster_ip_source_allowlist(allowlist)

    def reconcile_mongo_users_and_dbs(
        self,
        relation: Relation,
        relation_departing: bool = False,
        relation_changed: bool = False,
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
        match (relation_departing, relation_changed):
            case (False, False):
                self.add_user(relation)
                self.update_user(relation)
            case (True, False):
                self.remove_user(relation)
            case (False, True):
                self.update_diff(relation)
            case (True, True):
                raise ValueError("This case should never happen")

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
        # We do nothing if the Database Requested event has not run yet.
        if not data_interface.fetch_relation_field(relation.id, "database"):
            logger.info(f"Database Requested for {relation} has not run yet, skipping.")
            raise DatabaseRequestedHasNotRunYetError

        if not relation.units:
            logger.info(f"Database Requested for {relation} has not run yet, skipping.")
            raise DatabaseRequestedHasNotRunYetError

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
        username = f"relation-{relation.id}"

        # We do nothing if the Database Requested event has not run yet.
        if not data_interface.fetch_relation_field(relation.id, "database"):
            logger.info(f"Database Requested for {relation} has not run yet, skipping.")
            raise DatabaseRequestedHasNotRunYetError

        if not relation.units:
            logger.info(f"Database Requested for {relation} has not run yet, skipping.")
            raise DatabaseRequestedHasNotRunYetError

        with MongoConnection(self.state.mongo_config) as mongo:
            has_user = mongo.user_exists(username)

        # We do nothing if the user already exists in DB.
        if has_user:
            return

        auth_restrictions = self._compute_auth_restrictions(relation, data_interface)

        with MongoConnection(self.state.mongo_config) as mongo:
            config = self.get_config(
                username,
                None,  # We are creating the user, which means we don't have password for it yet
                data_interface,
                relation,
            )
            logger.info("Create relation user: %s on %s", config.username, config.database)

            mongo.create_user(
                config.username,
                config.password,
                config.supported_roles,
                auth_restrictions=auth_restrictions,
            )
            managed_users.add(username)
            data_interface.set_database(relation.id, config.database)
            data_interface.set_credentials(relation.id, config.username, config.password)

            self.state.app_peer_data.managed_users = managed_users

            if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
                return

            data_interface.set_endpoints(relation.id, ",".join(sorted(config.hosts)))
            data_interface.set_uris(relation.id, config.uri_without_tls)

            if ext_tls_ca := self.state.tls.get_secret(internal=False, label_name=SECRET_CA_LABEL):
                data_interface.set_tls(relation.id, "True")
                data_interface.set_tls_ca(relation.id, ext_tls_ca)

            if not self.state.is_role(MongoDBRoles.MONGOS):
                data_interface.set_replset(
                    relation.id, config.replset or self.state.app_peer_data.replica_set
                )

    def update_user(self, relation: Relation) -> None:
        """Update the user for this relation."""
        data_interface = DatabaseProviderData(
            self.model,
            relation.name,
        )

        username = f"relation-{relation.id}"
        password = data_interface.fetch_my_relation_field(relation.id, "password")

        with MongoConnection(self.state.mongo_config) as mongo:
            has_user = mongo.user_exists(username)

        # Don't update a user that doesn't exist
        if not has_user:
            return

        with MongoConnection(self.state.mongo_config) as mongo:
            config = self.get_config(
                username,
                password,
                data_interface,
                relation,
            )

            logger.info("Update relation user: %s on %s", config.username, config.database)
            mongo.update_user(config)
            logger.info("Updating relation data according to diff")

    def remove_user(self, relation: Relation):
        """Removes a user from Charmed MongoDB.

        Note this only removes users that this application of Charmed MongoDB is responsible for
        managing. It won't remove:
        1. users created from other applications
        2. users created from other mongos routers. The removal of these is
        triggered by the config-server in the case that the mongos and
        config-server integration is prematurely removed.

        Raises:
            PyMongoError
        """
        username = f"relation-{relation.id}"
        managed_users = self.state.app_peer_data.managed_users
        mongo_config = self.state.mongo_config

        # Skip our user.
        if self.state.is_role(MongoDBRoles.MONGOS) and username == mongo_config.username:
            return

        # Nothing to do if it's not a user we're managing.
        if username not in managed_users:
            return

        with MongoConnection(self.state.mongo_config) as mongo:
            has_user = mongo.user_exists(username)

        # Don't remove a user that doesn't exist
        if not has_user:
            return

        # Dropping the admin-user for mongos-k8s-router is done by mongos-k8s charm.
        if self.substrate == Substrates.K8S and self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            logger.info("K8s routers will remove themselves.")
            managed_users.remove(username)
            self.state.app_peer_data.managed_users = managed_users
            return

        with MongoConnection(mongo_config) as mongo:
            logger.info("Remove relation user: %s", username)
            mongo.drop_user(username)
            managed_users.remove(username)
        self.state.app_peer_data.managed_users = managed_users

    def add_entity(self, relation: Relation) -> None:
        """Creates the MongoDB role requested over the relation, once.

        The role is created in `admin` under the requested name, with the requested
        privileges, inheriting the requested charm roles on the requested database. Only
        the entity name is published to the requester. A relation now requesting another
        name gets its previous role dropped first. An existing role is adopted only when it
        has the requested definition and no other relation recorded it: a hook
        failing after `createRole` leaves it without a record. An invalid request or a role
        MongoDB refuses is reported with a Blocked status. A write concern error means
        the role was created on the primary, so it is recorded like a created one.

        Args:
            relation: The relation carrying the entity request.

        Raises:
            PyMongoError: on a connection or authentication failure, to retry later.
        """
        entity = self.state.entity_state(relation)
        if not entity.requested:
            logger.info("Relation %s does not request an entity, skipping.", relation.id)
            return

        try:
            entity.validate()
        except InvalidEntityRequestError as e:
            logger.error("Invalid entity request on relation %s: %s", relation.id, e)
            self.state.statuses.add(
                MongodStatuses.INVALID_ENTITY_REQUEST.value, scope="app", component=self.name
            )
            return

        name = entity.name
        privileges = entity.permissions
        roles = roles_for_database(entity.database, entity.extra_group_roles)
        managed_entities = self.state.app_peer_data.managed_entities
        recorded = managed_entities.get(relation.id)
        if recorded == name:
            logger.info("Role %s of relation %s already created, skipping.", name, relation.id)
            return
        if recorded:
            logger.info(
                "Relation %s now requests role %s instead of %s.", relation.id, name, recorded
            )
            self.remove_entity(relation.id)
            managed_entities = self.state.app_peer_data.managed_entities

        with MongoConnection(self.state.mongo_config) as mongo:
            existing = mongo.get_role(name)
            if existing and (
                name in managed_entities.values()
                or not same_role_definition(existing, privileges, roles)
            ):
                logger.error(
                    "Role %s already exists with another definition or for another relation, "
                    "not adopting it.",
                    name,
                )
                self.state.statuses.add(
                    MongodStatuses.ENTITY_ROLE_NOT_CREATED.value, scope="app", component=self.name
                )
                return

            if existing:
                logger.info("Adopt the existing role %s for relation %s", name, relation.id)
            else:
                logger.info("Create role %s for relation %s", name, relation.id)
                try:
                    mongo.create_role(name, privileges, roles)
                except WriteConcernError as e:
                    # A subclass of OperationFailure: the role exists, only its replication
                    # was not acknowledged in time. Not recording it would leak it.
                    logger.warning(
                        "Entity role %s was created with a write concern error: %r", name, e
                    )
                except OperationFailure as e:
                    if e.code in (
                        MongoErrorCodes.UNAUTHORIZED,
                        MongoErrorCodes.AUTHENTICATION_FAILED,
                    ):
                        raise
                    logger.error(
                        "MongoDB refused to create role %s for relation %s: %s",
                        name,
                        relation.id,
                        e,
                    )
                    self.state.statuses.add(
                        MongodStatuses.ENTITY_ROLE_NOT_CREATED.value,
                        scope="app",
                        component=self.name,
                    )
                    return

        managed_entities[relation.id] = name
        self.state.app_peer_data.managed_entities = managed_entities
        entity.entity_name = name

    def remove_entity(self, relation_id: int) -> None:
        """Drops the MongoDB role this application created for the relation.

        Decided from the peer data only: the relation data is not readable once the
        relation is broken.

        Args:
            relation_id: The id of the relation the role was created for.

        Raises:
            PyMongoError: if the role cannot be dropped, the record is kept to retry later.
        """
        managed_entities = self.state.app_peer_data.managed_entities
        name = managed_entities.pop(relation_id, None)
        if name is None:
            logger.info("No role was created for relation %s, nothing to drop.", relation_id)
            return

        with MongoConnection(self.state.mongo_config) as mongo:
            logger.info("Drop role %s of relation %s", name, relation_id)
            mongo.drop_role(name)
        self.state.app_peer_data.managed_entities = managed_entities

    def update_app_relation_data(self, relation: Relation) -> None:
        """Helper function to update this application relation data."""
        if not self.charm.unit.is_leader():
            return
        if not self.state.db_initialised:
            logger.info("Not updating client databag, db is not initialised")
            return
        if self.state.is_role(MongoDBRoles.SHARD):
            logger.debug("Not updating client databag, role is shard")
            return
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            logger.debug("Not updating client databag, role is config-server")
            return
        data_interface = DatabaseProviderData(self.model, relation.name)
        if not data_interface.fetch_relation_field(relation.id, "database"):
            return
        username = data_interface.fetch_my_relation_field(relation.id, "username")
        password = data_interface.fetch_my_relation_field(relation.id, "password")
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
            relation,
        )
        self.update_app_relation_data_for_config(relation, config)

    def update_app_relation_data_for_config(self, relation: Relation, config: MongoConfiguration):
        """Updates the data for a given config."""
        data_interface = DatabaseProviderData(self.model, relation.name)
        endpoints = data_interface.fetch_my_relation_field(relation.id, "endpoints") or ""
        uris = data_interface.fetch_my_relation_field(relation.id, "uris")
        database = data_interface.fetch_my_relation_field(relation.id, "database")
        username = data_interface.fetch_my_relation_field(relation.id, "username")
        password = data_interface.fetch_my_relation_field(relation.id, "password")

        if not username or not password:
            data_interface.set_credentials(
                relation.id,
                config.username,
                config.password,
            )
        if config.hosts != set(endpoints.split(",")):
            data_interface.set_endpoints(
                relation.id,
                ",".join(sorted(config.hosts)),
            )
        if config.uri_without_tls != uris:
            data_interface.set_uris(
                relation.id,
                config.uri_without_tls,
            )
        if config.database != database:
            data_interface.set_database(
                relation.id,
                config.database,
            )

        if ext_tls_ca := self.state.tls.get_secret(internal=False, label_name=SECRET_CA_LABEL):
            data_interface.set_tls(relation.id, "True")
            data_interface.set_tls_ca(relation.id, ext_tls_ca)

    def get_config(
        self,
        username: str,
        password: str | None,
        data_inteface: DatabaseProviderData,
        relation: Relation,
    ) -> MongoConfiguration:
        """."""
        if not password:
            password = self.workload.generate_password()
        database_name = data_inteface.fetch_relation_field(relation.id, "database")
        roles = data_inteface.fetch_relation_field(relation.id, "extra-user-roles") or "default"
        if not database_name or not roles:
            raise Exception("Missing database name or roles.")

        mongo_args = {
            "database": database_name,
            "username": username,
            "password": password,
            "hosts": self.state.hosts_for(relation),
            "roles": set(roles.split(",")),
            "tls_enabled": False,
            "port": self.state.host_port,
        }
        if not self.state.is_role(MongoDBRoles.MONGOS):
            mongo_args["replset"] = self.state.app_peer_data.replica_set
        return from_dict(data_class=MongoConfiguration, data=mongo_args)

    def set_election_priority(self, priority: int):
        """Sets the election priority."""
        with MongoConnection(self.state.mongo_config) as mongo:
            mongo.set_replicaset_election_priority(priority=priority)

    def remove_replset_member(self) -> None:  # pragma: nocover
        """Remove a unit from the replicaset."""
        with MongoConnection(self.state.mongo_config) as mongo:
            mongo.remove_replset_member(self.state.unit_peer_data.internal_address)

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
                logger.info("Adding %s to replica set", member)
                mongo.add_replset_member(member)

    def get_draining_shards(
        self, shard_name: str, config: MongoConfiguration | None = None
    ) -> list[str]:
        """Returns the shard that is currently draining."""
        with MongoConnection(config or self.state.mongos_config) as mongo:
            draining_shards = mongo.get_draining_shards(shard_name=shard_name)

            # in theory, this should always be a list of one. But if something has gone wrong we
            # should take note and log it
            if len(draining_shards) > 1:
                logger.error("Multiple shards draining at the same time.")

            return draining_shards

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:  # noqa: C901 (this function is complex but we can't reduce its complexity easily enough)
        """Generates the status of a unit based on its status reported by mongod."""
        charm_statuses: list[StatusObject] = []

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if not self.state.db_initialised:
            return [MongodStatuses.WAITING_REPL_SET_INIT.value]

        if scope == "app":
            return self._entity_statuses()

        if not self.mongod_ready():
            return [MongodStatuses.NOT_READY.value]

        try:
            with MongoConnection(self.state.mongo_config) as mongo:
                replset_status = mongo.get_replset_status()

            replica_status = replset_status.get(self.state.unit_peer_data.internal_address, "")

            match replica_status:
                case "":
                    return [MongodStatuses.ADDING_MEMBER.value]
                case "PRIMARY":
                    charm_statuses.append(MongodStatuses.PRIMARY.value)
                case "SECONDARY":
                    charm_statuses.append(MongodStatuses.SECONDARY.value)
                case "STARTUP" | "STARTUP2" | "ROLLBACK" | "RECOVERING":
                    return [MongodStatuses.SYNCING_MEMBER.value]
                case "REMOVED":
                    return [MongodStatuses.REMOVING_MEMBER.value]
                case _:
                    return [MongodStatuses.replset_status(replica_status)]

            charm_statuses.extend(self.get_leader_statuses())
            return charm_statuses

        except ServerSelectionTimeoutError as e:
            # Usually it is due to ReplicaSetNoPrimary
            logger.debug(f"Got error {e} while checking replica set status")
            return [MongodStatuses.WAITING_ELECTION.value]
        except AutoReconnect as e:
            # AutoReconnect is raised when a connection to the database is lost and an attempt to
            # auto-reconnect will be made by pymongo.
            logger.debug("Got error: %s, while checking replica set status", str(e))
            return [MongodStatuses.WAITING_RECONNECTION.value]
        except OperationFailure as e:
            logger.warning("Authentication Failed: %s", e, exc_info=True)
            return [MongodStatuses.WAITING_RECONFIG.value]
        except MissingCredentialsError as e:
            logger.warning("Missing credentials: %s", e, exc_info=True)
            return [MongodStatuses.WAITING_CREDENTIALS.value]

    def _entity_statuses(self) -> list[StatusObject]:
        """Returns the statuses of the entity requests, at most one of each kind."""
        statuses: list[StatusObject] = []
        managed_entities = self.state.app_peer_data.managed_entities
        for relation in sorted(self.state.entity_relations, key=lambda relation: relation.id):
            try:
                self.state.entity_state(relation).validate()
            except InvalidEntityRequestError as e:
                logger.warning("Invalid entity request on relation %s: %s", relation.id, e)
                status = MongodStatuses.INVALID_ENTITY_REQUEST.value
            else:
                if relation.id in managed_entities:
                    continue
                logger.warning("The role requested on relation %s is not created.", relation.id)
                status = MongodStatuses.ENTITY_ROLE_NOT_CREATED.value
            if status not in statuses:
                statuses.append(status)
        return statuses

    def get_leader_statuses(self) -> list[StatusObject]:
        """Returns statuses that juju leader can retrieve for mongo."""
        charm_statuses: list[StatusObject] = []

        if not self.charm.unit.is_leader():
            return charm_statuses

        try:
            with MongoConnection(self.state.mongo_config) as mongo:
                replset_members = mongo.get_replset_members()
                config_hosts = mongo.config.hosts
                if replset_members != config_hosts:
                    return [MongodStatuses.WAITING_RECONFIG.value]
        except PyMongoError as e:
            logger.error("Error checking members, %s", e)
            return [MongodStatuses.WAITING_RECONFIG.value]

        return charm_statuses

    def set_feature_compatibility_version(self, feature_version: str) -> None:
        """Sets the mongos feature compatibility version."""
        if self.state.is_role(MongoDBRoles.REPLICATION):
            config = self.state.mongo_config
        elif self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            config = self.state.mongos_config
        else:
            return
        with MongoConnection(config) as mongos:
            mongos.client.admin.command(
                "setFeatureCompatibilityVersion", value=feature_version, confirm=True
            )

    def step_down_primary_and_wait_reelection(self):
        """Steps down the current primary and waits for a new one to be elected."""
        if len(self.state.internal_hosts) < 2:
            logger.warning(
                "No secondaries to become primary - upgrading primary without electing a new one, expect downtime."
            )
            return

        old_primary = self.dependent.primary_unit_name  # type: ignore
        with MongoConnection(self.state.mongo_config) as mongod:
            mongod.step_down_primary()

        for attempt in Retrying(stop=stop_after_attempt(30), wait=wait_fixed(1), reraise=True):
            with attempt:
                new_primary = self.dependent.primary_unit_name  # type: ignore
                if new_primary == old_primary:
                    raise FailedToElectNewPrimaryError()

    def _compute_auth_restrictions(
        self, relation: Relation, data_interface: DatabaseProviderData
    ) -> list[AuthRestrictions]:
        """Compute the correct auth restriction rules."""
        # No juju spaces support on K8S.
        if self.substrate == Substrates.K8S:
            return []

        external_connectivity: bool = json.loads(
            data_interface.fetch_relation_field(relation.id, "external-node-connectivity")
            or "false"
        )
        # No restriction on external connectivity for now.
        if external_connectivity:
            return []
        # We can't enforce rules on sharded deployments due to
        # - No support for socket connection
        # - Otherwise it's external connectivity, hence already handled.
        if self.state.is_cluster_component:
            return []

        ip_list = [
            self.state.unit_peer_data_for(unit, relation).internal_address
            for unit in relation.units
        ]

        return [
            AuthRestrictions(
                clientSource=cidrs(network_for_relation(relation).bind_addresses),
                serverAddress=cidrs(self.state.peer_network().bind_addresses),
            ),
            AuthRestrictions(
                clientSource=[get_cidr_for_ip_list(ip_list)],
                serverAddress=cidrs(self.state.peer_network().bind_addresses),
            ),
            AuthRestrictions(
                clientSource=cidrs(self.state.peer_network().bind_addresses),
                serverAddress=cidrs(self.state.peer_network().bind_addresses),
            ),
        ]

    def get_unwanted_replicaset_members(self) -> set[str]:
        """Return replica set members that are no longer part of the desired config."""
        with MongoConnection(self.state.mongo_config) as mongo:
            return mongo.get_replset_members() - mongo.config.hosts

    def remove_replset_members(self, members: set[str]) -> None:
        """Remove the given members from the replica set configuration.

        Raises:
        NotReadyError: If MongoDB is not ready to process the removal
            (e.g. another removal is in progress).
        PyMongoError: If an error occurs while communicating with MongoDB.
        """
        with MongoConnection(self.state.mongo_config) as mongo:
            for member in members:
                logger.info("Removing %s from replica set", member)
                mongo.remove_replset_member(member)
