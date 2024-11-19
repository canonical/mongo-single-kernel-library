#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The general charm state."""

import logging
from functools import cached_property
from ipaddress import IPv4Address, IPv6Address
from typing import TypeVar

from ops import Object, Relation, Unit

from single_kernel_mongo.abstract_charm import AbstractMongoCharm
from single_kernel_mongo.config.literals import SECRETS_UNIT, MongoPorts, Scope, Substrates
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    RelationNames,
)
from single_kernel_mongo.config.roles import MongoDBRole, MongosRole, Role
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
)
from single_kernel_mongo.state.app_peer_state import (
    AppPeerReplicaSet,
)
from single_kernel_mongo.state.cluster_state import ClusterState
from single_kernel_mongo.state.models import ClusterData
from single_kernel_mongo.state.tls_state import TLSState
from single_kernel_mongo.state.unit_peer_state import (
    UnitPeerReplicaSet,
)
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
    RoleNames,
)

logger = logging.getLogger()

T = TypeVar("T", bound=MongoConfigModel)


class CharmState(Object):
    """All the charm states."""

    def __init__(self, charm: AbstractMongoCharm[T], role: Role):
        super().__init__(parent=charm, key="charm_state")
        self.role = role
        self.config = charm.config
        self.substrate: Substrates = self.role.substrate
        self.secrets = SecretCache(charm)

        self.peer_app_interface = DataPeerData(
            self.model,
            relation_name=RelationNames.PEERS,
        )
        self.peer_unit_interface = DataPeerUnitData(
            self.model,
            relation_name=RelationNames.PEERS,
            additional_secret_fields=SECRETS_UNIT,
        )

    # BEGIN: Relations

    @property
    def peer_relation(self) -> Relation | None:
        """The replica set peer relation."""
        return self.model.get_relation(RelationNames.PEERS)

    @property
    def peers_units(self) -> set[Unit]:
        """Get peers units in a safe way."""
        if not self.peer_relation:
            return set()
        return self.peer_relation.units

    @property
    def client_relations(self) -> set[Relation]:
        """The set of client relations."""
        return set(self.model.relations[RelationNames.DATABASE])

    @property
    def cluster_relation(self) -> Relation | None:
        """The Cluster relation."""
        return self.model.get_relation(RelationNames.CLUSTER)

    @property
    def shard_relations(self) -> list[Relation]:
        """The set of shard relations."""
        return self.model.relations[RelationNames.SHARDING]

    @property
    def config_server_relation(self) -> Relation | None:
        """The config-server relation if it exists."""
        return self.model.get_relation(RelationNames.CONFIG_SERVER)

    @property
    def s3_relation(self) -> Relation | None:
        """The S3 relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.S3_CREDENTIALS)

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
            relation=self.cluster_relation,
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

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @cached_property
    def peer_units_data_interfaces(self) -> dict[Unit, DataPeerOtherUnitData]:
        """The cluster peer relation."""
        return {
            unit: DataPeerOtherUnitData(
                model=self.model, unit=unit, relation_name=RelationNames.PEERS
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
    def config_server_name(self) -> str | None:
        """Gets the config server name."""
        if isinstance(self.role, MongosRole):
            if self.cluster_relation:
                return self.cluster_relation.app.name
            return None
        if self.is_role(MongoDBRoles.SHARD):
            if self.shard_relations:
                return self.shard_relations[0].app.name
            return None
        logger.info(
            "Component %s is not a shard, cannot be integrated to a config-server.", self.role
        )
        return None

    # END: Helpers

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
            password=self.app_peer_data.get_user_password(user.username),
            hosts=hosts or user.hosts,
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
            password=self.app_peer_data.get_user_password(user.username),
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
        if isinstance(self.role, MongoDBRole):
            return self.operator_config
        return self.mongos_config

    # END: Configuration accessors
