#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The general charm state."""

from __future__ import annotations

import json
import logging
from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, TypeVar

from ops import Object, Relation, Unit

from single_kernel_mongo.config.literals import (
    SECRETS_UNIT,
    MongoPorts,
    RoleEnum,
    Scope,
    Substrates,
)
from single_kernel_mongo.config.models import Role
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    PeerRelationNames,
    RelationNames,
)
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseRequirerData,
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
)
from single_kernel_mongo.state.app_peer_state import (
    AppPeerDataKeys,
    AppPeerReplicaSet,
)
from single_kernel_mongo.state.cluster_state import ClusterState
from single_kernel_mongo.state.config_server_state import (
    SECRETS_FIELDS,
    ConfigServerState,
)
from single_kernel_mongo.state.models import ClusterData
from single_kernel_mongo.state.tls_state import TLSState
from single_kernel_mongo.state.unit_peer_state import (
    UnitPeerReplicaSet,
)
from single_kernel_mongo.utils.helpers import generate_relation_departed_key
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
    RoleNames,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol

    T = TypeVar("T", bound=MongoConfigModel)
    U = TypeVar("U", bound=OperatorProtocol)

logger = logging.getLogger()


class CharmState(Object):
    """The Charm State object.

    This object represents the charm state, including the different relations
    the charm is bound to, and the model information.
    It is parametrized by the substrate and the RoleEnum.

    The substrate will allow to compute the right hosts.
    The Role allows selection of the right peer relation name and also the
    generation of the correct mongo uri.
    The charm is passed as an argument to build the secret storage, and provide
    an access to the charm configuration.
    """

    def __init__(self, charm: AbstractMongoCharm[T, U], substrate: Substrates, charm_role: Role):
        super().__init__(parent=charm, key="charm_state")
        self.charm_role = charm_role
        self.config = charm.parsed_config
        self.substrate: Substrates = substrate
        self.secrets = SecretCache(charm)

        self.peer_app_interface = DataPeerData(
            self.model,
            relation_name=PeerRelationNames.PEERS.value,
        )
        self.peer_unit_interface = DataPeerUnitData(
            self.model,
            relation_name=PeerRelationNames.PEERS.value,
            additional_secret_fields=SECRETS_UNIT,
        )

    # BEGIN: Relations

    @property
    def peer_relation(self) -> Relation | None:
        """The replica set peer relation."""
        return self.model.get_relation(PeerRelationNames.PEERS.value)

    @property
    def peers_units(self) -> set[Unit]:
        """Get peers units in a safe way."""
        if not self.peer_relation:
            return set()
        return self.peer_relation.units

    @property
    def client_relations(self) -> set[Relation]:
        """The set of client relations."""
        return set(self.model.relations[RelationNames.DATABASE.value])

    @property
    def mongos_cluster_relation(self) -> Relation | None:
        """The Mongos side of the cluster relation."""
        return self.model.get_relation(RelationNames.CLUSTER.value)

    @property
    def cluster_relations(self) -> set[Relation]:
        """The Config Server side of the cluster relation."""
        return set(self.model.relations[RelationNames.CLUSTER.value])

    @property
    def shard_relation(self) -> Relation | None:
        """The set of shard relations."""
        return self.model.get_relation(RelationNames.SHARDING.value)

    @property
    def config_server_relation(self) -> set[Relation]:
        """The config-server relation if it exists."""
        return set(self.model.relations[RelationNames.CONFIG_SERVER.value])

    @property
    def tls_relation(self) -> Relation | None:
        """The TLS relation."""
        return self.model.get_relation(ExternalRequirerRelations.TLS.value)

    @property
    def s3_relation(self) -> Relation | None:
        """The S3 relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.S3_CREDENTIALS.value)

    # END: Relations

    # BEGIN: State Accessors

    @property
    def app_peer_data(self) -> AppPeerReplicaSet:
        """The app peer relation data."""
        return AppPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
            role=self.config.role,
        )

    @property
    def unit_peer_data(self) -> UnitPeerReplicaSet:
        """This unit peer relation data."""
        return UnitPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
            substrate=self.substrate,
            bind_address=str(self.bind_address),
        )

    @property
    def units(self) -> set[UnitPeerReplicaSet]:
        """Grabs all units in the current peer relation, including this unit.

        Returns:
            Set of UnitPeerReplicaSet in the current peer relation, including this unit.
        """
        _units = set()
        for unit, data_interface in self.peer_units_data_interfaces.items():
            _units.add(
                UnitPeerReplicaSet(
                    relation=self.peer_relation,
                    data_interface=data_interface,
                    component=unit,
                    substrate=self.substrate,
                )
            )
        _units.add(self.unit_peer_data)

        return _units

    @property
    def cluster(self) -> ClusterState:
        """The cluster state of the current running App."""
        return ClusterState(
            relation=self.mongos_cluster_relation,
            data_interface=ClusterData(self.model, RelationNames.CLUSTER),
            component=self.model.app,
        )

    @property
    def tls(self) -> TLSState:
        """A view of the TLS status from the local unit databag."""
        return TLSState(relation=self.peer_relation, secrets=self.secrets)

    # END: State Accessors

    # BEGIN: Helpers
    def is_role(self, role: MongoDBRoles) -> bool:
        """Is the charm in the correct role?"""
        return self.app_peer_data.role == role

    @property
    def is_sharding_component(self) -> bool:
        """Is the shard a sharding component?"""
        return self.is_role(MongoDBRoles.SHARD) or self.is_role(MongoDBRoles.CONFIG_SERVER)

    @property
    def db_initialised(self) -> bool:
        """Is the DB initialised?"""
        return self.app_peer_data.db_initialised

    @db_initialised.setter
    def db_initialised(self, other: bool):
        self.app_peer_data.db_initialised = other

    @property
    def upgrade_in_progress(self) -> bool:
        """Is the charm in upgrade?"""
        return False

    @property
    def bind_address(self) -> IPv4Address | IPv6Address | str:
        """The network binding address from the peer relation."""
        bind_address = None
        if self.peer_relation:
            if binding := self.model.get_binding(self.peer_relation):
                bind_address = binding.network.bind_address

        return bind_address or ""

    def get_user_password(self, user: MongoDBUser) -> str:
        """Returns the user password for a system user."""
        return self.secrets.get_for_key(Scope.APP, user.password_key_name) or ""

    def set_user_password(self, user: MongoDBUser, content: str) -> str:
        """Sets the user password for a system user."""
        return self.secrets.set(user.password_key_name, content, Scope.APP).label

    def set_keyfile(self, keyfile_content: str) -> str:
        """Sets the keyfile content in the secret."""
        return self.secrets.set(AppPeerDataKeys.keyfile.value, keyfile_content, Scope.APP).label

    def get_keyfile(self) -> str | None:
        """Gets the keyfile content from the secret."""
        return self.secrets.get_for_key(Scope.APP, AppPeerDataKeys.keyfile.value)

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @cached_property
    def peer_units_data_interfaces(self) -> dict[Unit, DataPeerOtherUnitData]:
        """The cluster peer relation."""
        return {
            unit: DataPeerOtherUnitData(
                model=self.model, unit=unit, relation_name=PeerRelationNames.PEERS.value
            )
            for unit in self.peers_units
        }

    @property
    def app_hosts(self) -> set[str]:
        """Retrieve the hosts associated with MongoDB application."""
        return {unit.host for unit in self.units}

    @property
    def internal_hosts(self) -> set[str]:
        """Internal hosts for internal access."""
        return {unit.internal_address for unit in self.units}

    @property
    def host_port(self) -> int:
        """Retrieve the port associated with MongoDB application."""
        if self.is_role(MongoDBRoles.MONGOS):
            if self.config["expose_external"]:
                return self.unit_peer_data.node_port
            return MongoPorts.MONGOS_PORT
        return MongoPorts.MONGODB_PORT

    @property
    def shard_state(self):
        """The shard state."""
        return ConfigServerState(
            relation=self.shard_relation,
            data_interface=DatabaseRequirerData(
                self.model, RelationNames.SHARDING, "", additional_secret_fields=SECRETS_FIELDS
            ),
            component=self.model.app,
        )

    @property
    def config_server_name(self) -> str | None:
        """Gets the config server name."""
        if self.charm_role.name == RoleEnum.MONGOS:
            if self.mongos_cluster_relation:
                return self.mongos_cluster_relation.app.name
            return None
        if self.is_role(MongoDBRoles.SHARD):
            if self.shard_relation:
                return self.shard_relation.app.name
            return None
        logger.info(
            "Component %s is not a shard, cannot be integrated to a config-server.",
            self.app_peer_data.role,
        )
        return None

    # END: Helpers
    def is_scaling_down(self, rel_id: int) -> bool:
        """Returns True if the application is scaling down."""
        rel_departed_key = generate_relation_departed_key(rel_id)
        return json.loads(self.unit_peer_data.get(rel_departed_key, "false"))

    def has_departed_run(self, rel_id: int) -> bool:
        """Returns True if the relation departed event has run."""
        rel_departed_key = generate_relation_departed_key(rel_id)
        return self.unit_peer_data.get(rel_departed_key) != ""

    def set_scaling_down(self, rel_id: int, departing_unit_name: str) -> bool:
        """Sets whether or not the current unit is scaling down."""
        # check if relation departed is due to current unit being removed. (i.e. scaling down the
        # application.)
        rel_departed_key = generate_relation_departed_key(rel_id)
        scaling_down = departing_unit_name == self.unit_peer_data.name
        self.unit_peer_data.update({rel_departed_key: json.dumps(scaling_down)})
        return scaling_down

    # BEGIN: Configuration accessors

    def mongodb_config_for_user(
        self,
        user: MongoDBUser,
        hosts: set[str] = set(),
        replset: str | None = None,
        standalone: bool = False,
    ) -> MongoConfiguration:
        """Returns a mongodb-specific MongoConfiguration object for the provided user.

        Either user.hosts or hosts should be a non empty set.

        Returns:
            A MongoDB configuration object.

        Raises:
            Exception if neither user.hosts nor hosts is non empty.
        """
        if not user.hosts and not hosts:
            raise Exception("Invalid call: no host in user nor as a parameter.")
        return MongoConfiguration(
            replset=replset or self.app_peer_data.replica_set,
            database=user.database_name,
            username=user.username,
            password=self.get_user_password(user),
            hosts=hosts or user.hosts,
            port=MongoPorts.MONGODB_PORT,
            roles=user.roles,
            tls_external=self.tls.external_enabled,
            tls_internal=self.tls.internal_enabled,
            standalone=standalone,
        )

    def mongos_config_for_user(
        self,
        user: MongoDBUser,
        hosts: set[str] = set(),
    ) -> MongoConfiguration:
        """Returns a mongos-specific MongoConfiguration object for the provided user.

        Either user.hosts or hosts should be a non empty set.

        Returns:
            A MongoDB configuration object.

        Raises:
            Exception if neither user.hosts nor hosts is non empty.
        """
        if not user.hosts and not hosts:
            raise Exception("Invalid call: no host in user nor as a parameter.")
        return MongoConfiguration(
            database=user.database_name,
            username=user.username,
            password=self.get_user_password(user),
            hosts=hosts or user.hosts,
            port=MongoPorts.MONGOS_PORT,
            roles=user.roles,
            tls_external=self.tls.external_enabled,
            tls_internal=self.tls.internal_enabled,
        )

    @property
    def backup_config(self) -> MongoConfiguration:
        """Mongo Configuration for the backup user."""
        return self.mongodb_config_for_user(BackupUser, standalone=True)

    @property
    def monitor_config(self) -> MongoConfiguration:
        """Mongo Configuration for the monitoring user."""
        return self.mongodb_config_for_user(MonitorUser)

    @property
    def operator_config(self) -> MongoConfiguration:
        """Mongo Configuration for the operator user."""
        return self.mongodb_config_for_user(OperatorUser, hosts=self.app_hosts)

    @property
    def mongos_config(self) -> MongoConfiguration:
        """Mongos Configuration for the mongos user."""
        username = self.secrets.get_for_key(Scope.APP, key="username")
        password = self.secrets.get_for_key(Scope.APP, key="password")
        if not username or not password:
            raise Exception("Missing credentials.")

        return MongoConfiguration(
            database=f"{self.model.app.name}_{self.model.name}",
            username=username,
            password=password,
            hosts=self.internal_hosts,
            # unlike the vm mongos charm, the K8s charm does not communicate with the unix socket
            port=MongoPorts.MONGOS_PORT,
            roles={RoleNames.ADMIN},
            tls_external=self.tls.external_enabled,
            tls_internal=self.tls.internal_enabled,
        )

    @property
    def mongo_config(self) -> MongoConfiguration:
        """The mongo configuration to use by default for charm interactions."""
        if self.charm_role.name == RoleEnum.MONGOD:
            return self.operator_config
        return self.mongos_config

    # END: Configuration accessors
