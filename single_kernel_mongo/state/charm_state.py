#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The general charm state."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, TypeVar, final
from urllib.parse import quote

from data_platform_helpers.advanced_statuses.protocol import (
    AbstractStatusesState,
    StatusesState,
)
from ops import ModelError, Object, Relation, SecretNotFoundError, Unit
from ops.hookcmds import Network, network_get
from pymongo.errors import (
    AutoReconnect,
    ConfigurationError,
    NotPrimaryError,
    OperationFailure,
    ServerSelectionTimeoutError,
)

from single_kernel_mongo.config.literals import (
    LOCALHOST,
    SECRETS_UNIT,
    CharmKind,
    MongoPorts,
    Scope,
    Substrates,
)
from single_kernel_mongo.config.models import CharmSpec
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    PeerRelationNames,
    RelationNames,
)
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.core.structured_config import (
    ExposeExternal,
    MongoConfigModel,
    MongoDBRoles,
)
from single_kernel_mongo.core.workload import MongoPaths
from single_kernel_mongo.exceptions import MissingCredentialsError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
    DatabaseRequirerData,
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.app_peer_state import (
    AppPeerDataKeys,
    AppPeerReplicaSet,
)
from single_kernel_mongo.state.cluster_state import ClusterState, ClusterStateKeys
from single_kernel_mongo.state.config_server_state import (
    SECRETS_FIELDS,
    AppShardingComponentState,
    UnitShardingComponentState,
)
from single_kernel_mongo.state.ldap_state import LdapState
from single_kernel_mongo.state.tls_state import TLSState
from single_kernel_mongo.state.unit_peer_state import (
    UnitPeerReplicaSet,
)
from single_kernel_mongo.state.vault_state import VaultState
from single_kernel_mongo.utils.helpers import (
    generate_relation_departed_key,
)
from single_kernel_mongo.utils.mongo_config import MongoConfiguration
from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes
from single_kernel_mongo.utils.mongodb_users import (
    AuthRestrictions,
    CharmedBackupUser,
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
    InternalUsers,
    MongoDBUser,
    RoleNames,
)
from single_kernel_mongo.utils.network_helpers import (
    cidrs,
    ip_addresses,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol

    T = TypeVar("T", bound=MongoConfigModel)
    U = TypeVar("U", bound=OperatorProtocol)

logger = logging.getLogger()


@final
class CharmState(Object, AbstractStatusesState):
    """The Charm State object.

    This object represents the charm state, including the different relations
    the charm is bound to, and the model information.
    It is parametrized by the substrate and the CharmKind.

    The substrate will allow to compute the right hosts.
    The CharmSpec allows selection of the right peer relation name and also the
    generation of the correct mongo uri.
    The charm is passed as an argument to build the secret storage, and provide
    an access to the charm configuration.
    """

    def __init__(
        self,
        charm: AbstractMongoCharm[T, U],
        substrate: Substrates,
        charm_role: CharmSpec,
    ):
        super().__init__(parent=charm, key="charm_state")
        self.charm_role = charm_role
        self.charm = charm
        self.substrate: Substrates = substrate
        self.secrets = SecretCache(charm)
        self.peer_relation_name = charm.peer_rel_name.value
        self.ldap_peer_relation_name = PeerRelationNames.LDAP_PEERS.value
        self.statuses_relation_name = PeerRelationNames.STATUS_PEERS.value

        self.statuses = StatusesState(self, self.statuses_relation_name)

        self.peer_app_interface = DataPeerData(
            self.model,
            relation_name=self.peer_relation_name,
        )
        self.peer_unit_interface = DataPeerUnitData(
            self.model,
            relation_name=self.peer_relation_name,
            additional_secret_fields=SECRETS_UNIT,
        )
        self.ldap_peer_interface = DataPeerData(
            self.model,
            self.ldap_peer_relation_name,
        )

        self.paths = MongoPaths(self.charm_role)

        self.k8s_manager = K8sManager(
            pod_name=self.pod_name,
            namespace=self.model.unit._backend.model_name,
        )

    @property
    def config(self) -> MongoConfigModel:
        """Returns the charm config."""
        return self.charm.parsed_config

    @property
    def pod_name(self) -> str:
        """K8S only: The pod name."""
        return self.model.unit.name.replace("/", "-")

    # BEGIN: Relations
    @property
    def client_relation_name(self) -> str:
        """The correct client relation name."""
        if self.charm_role.name == CharmKind.MONGOS:
            return RelationNames.MONGOS_PROXY.value
        return RelationNames.DATABASE.value

    @property
    def peer_relation(self) -> Relation | None:
        """The replica set peer relation."""
        return self.model.get_relation(self.peer_relation_name)

    @property
    def ldap_peer_relation(self) -> Relation | None:
        """The LDAP peer relation."""
        return self.model.get_relation(self.ldap_peer_relation_name)

    @property
    def peers_units(self) -> set[Unit]:
        """Get peers units in a safe way."""
        if not self.peer_relation:
            return set()
        return self.peer_relation.units

    @property
    def reverse_order_peer_units(self) -> list[Unit]:
        """Units sorted in reverse order."""
        return sorted(
            self.peers_units, key=lambda unit: int(unit.name.split("/")[-1]), reverse=True
        )

    @property
    def client_relations(self) -> set[Relation]:
        """The set of client relations.

        Client relations exist on two separate interfaces, one for sharding,
        which is exposed for mongos charms, and one for replication which is
        exposed for mongodb charms.
        """
        return set(self.model.relations[self.client_relation_name])

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
    def client_tls_relation(self) -> Relation | None:
        """The client TLS relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.CLIENT_TLS.value)

    @property
    def peer_tls_relation(self) -> Relation | None:
        """The peer TLS relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.PEER_TLS.value)

    @property
    def s3_relation(self) -> Relation | None:
        """The S3 relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.S3_CREDENTIALS.value)

    @property
    def gcs_relation(self) -> Relation | None:
        """The S3 relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.GCS_CREDENTIALS.value)

    @property
    def ldap_relation(self) -> Relation | None:
        """The LDAP relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.LDAP.value)

    @property
    def ldap_cert_relation(self) -> Relation | None:
        """The certificate transfer relation for LDAP if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.LDAP_CERT.value)

    @property
    def vault_relation(self) -> Relation | None:
        """The Vault relation if it exists."""
        return self.model.get_relation(ExternalRequirerRelations.VAULT.value)

    # END: Relations

    # BEGIN: State Accessors

    @property
    def app_peer_data(self) -> AppPeerReplicaSet:
        """The app peer relation data."""
        return AppPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
            substrate=self.substrate,
            model=self.model,
        )

    @property
    def unit_peer_data(self) -> UnitPeerReplicaSet:
        """This unit peer relation data."""
        return UnitPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
            substrate=self.substrate,
            k8s_manager=self.k8s_manager,
            bind_address=str(self.bind_address),
        )

    def unit_peer_data_for(self, unit: Unit, relation: Relation) -> UnitPeerReplicaSet:
        """The provided unit peer relation data."""
        data_interface = DataPeerOtherUnitData(
            model=self.model,
            unit=unit,
            relation_name=relation.name,
        )
        return UnitPeerReplicaSet(
            relation=relation,
            data_interface=data_interface,
            component=unit,
            substrate=self.substrate,
            k8s_manager=self.k8s_manager,
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
                    k8s_manager=self.k8s_manager,
                )
            )
        _units.add(self.unit_peer_data)

        return _units

    def peer_unit_data(self, unit: Unit) -> UnitPeerReplicaSet:
        """Returns the peer data for a peer unit."""
        if unit.name == self.model.unit.name:
            return self.unit_peer_data
        return UnitPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_units_data_interfaces[unit],
            component=unit,
            substrate=self.substrate,
            k8s_manager=self.k8s_manager,
        )

    @property
    def client_data_interface(self) -> DatabaseProviderData:
        """The client data interface."""
        return DatabaseProviderData(
            self.model,
            RelationNames.DATABASE.value,
        )

    @property
    def cluster_provider_data_interface(self) -> DatabaseProviderData:
        """The Requirer Data interface for the cluster relation (config-server side)."""
        return DatabaseProviderData(
            self.model,
            RelationNames.CLUSTER.value,
        )

    @property
    def cluster_requirer_data_interface(self) -> DatabaseRequirerData:
        """The Requirer Data interface for the cluster relation (mongos side)."""
        return DatabaseRequirerData(
            self.model,
            RelationNames.CLUSTER.value,
            database_name=self.app_peer_data.database,
            extra_user_roles=",".join(sorted(self.app_peer_data.extra_user_roles)),
            additional_secret_fields=[
                ClusterStateKeys.KEYFILE.value,
                ClusterStateKeys.CONFIG_SERVER_DB.value,
                ClusterStateKeys.INT_CA_SECRET.value,
                ClusterStateKeys.EXT_CA_SECRET.value,
                ClusterStateKeys.CLUSTER_ID.value,
            ],
        )

    @property
    def cluster(self) -> ClusterState:
        """The cluster state of the current running App."""
        return ClusterState(
            relation=self.mongos_cluster_relation,
            data_interface=self.cluster_requirer_data_interface,
            component=self.model.app,
        )

    @property
    def tls(self) -> TLSState:
        """A view of the TLS status from the local unit databag."""
        return TLSState(
            peer_relation=self.peer_tls_relation,
            client_relation=self.client_tls_relation,
            secrets=self.secrets,
        )

    @property
    def ldap(self) -> LdapState:
        """A view of the TLS status from the local unit databag."""
        return LdapState(
            self.charm,
            relation=self.ldap_peer_relation,
            data_interface=self.ldap_peer_interface,
            component=self.model.app,
        )

    @property
    def vault_state(self) -> VaultState:
        """A view of the vault state from the local app databag."""
        return VaultState(
            charm=self.charm,
            vault_relation=self.vault_relation,
        )

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
    def is_cluster_component(self) -> bool:
        """Is the application a cluster component?"""
        return self.is_role(MongoDBRoles.MONGOS) or self.is_role(MongoDBRoles.CONFIG_SERVER)

    @property
    def has_sharding_integration(self) -> bool:
        """Has the sharding component a sharded deployment integration?"""
        return (self.shard_relation is not None) or bool(self.config_server_relation)

    @property
    def db_initialised(self) -> bool:
        """Is the DB initialised?"""
        return self.app_peer_data.db_initialised

    @db_initialised.setter
    def db_initialised(self, other: bool):
        self.app_peer_data.db_initialised = other

    @property
    def enable_encryption_at_rest(self) -> bool:
        """Should encryption at rest be enabled."""
        return self.app_peer_data.enable_encryption_at_rest or False

    @enable_encryption_at_rest.setter
    def enable_encryption_at_rest(self, other: bool):
        self.app_peer_data.enable_encryption_at_rest = other

    @property
    def bind_address(self) -> str:
        """The network binding address from the peer relation."""
        if not self.peer_relation:
            return ""
        try:
            return str(self.peer_network().bind_addresses[0].addresses[0].value)
        except IndexError:
            return ""

    def get_user_password(self, user: MongoDBUser) -> str:
        """Returns the user password for a system user."""
        return self.secrets.get_for_key(Scope.APP, user.password_key_name) or ""

    def set_user_password(self, user: MongoDBUser, content: str) -> str:
        """Sets the user password for a system user."""
        return self.secrets.set(user.password_key_name, content, Scope.APP).label

    def internal_user_passwords_are_initialized(self) -> bool:
        """Returns true if all the charmed users have a password."""
        return all(self.get_user_password(user) for user in InternalUsers)

    def get_user_credentials(self) -> tuple[str | None, str | None]:
        """Retrieve the user credentials."""
        return (
            self.secrets.get_for_key(Scope.APP, key=AppPeerDataKeys.USERNAME.value),
            self.secrets.get_for_key(Scope.APP, key=AppPeerDataKeys.PASSWORD.value),
        )

    def set_keyfile(self, keyfile_content: str) -> str:
        """Sets the keyfile content in the secret."""
        return self.secrets.set(AppPeerDataKeys.KEYFILE.value, keyfile_content, Scope.APP).label

    def get_keyfile(self) -> str | None:
        """Gets the keyfile content from the secret."""
        return self.secrets.get_for_key(Scope.APP, AppPeerDataKeys.KEYFILE.value)

    def set_cluster_id(self, cluster_id_content: str) -> str:
        """Sets the cluster id content in the secret."""
        return self.secrets.set(
            AppPeerDataKeys.CLUSTER_ID.value, cluster_id_content, Scope.APP
        ).label

    def get_cluster_id(self) -> str | None:
        """Gets the cluster id content from the secret."""
        if self.substrate == Substrates.K8S:
            return None
        return self.secrets.get_for_key(Scope.APP, AppPeerDataKeys.CLUSTER_ID.value)

    def remove_cluster_id(self) -> None:
        """Remove the content of cluster id from the secret."""
        self.secrets.remove(key=AppPeerDataKeys.CLUSTER_ID.value, scope=Scope.APP)

    @property
    def planned_units(self) -> int:
        """Return the planned units for the charm."""
        return self.model.app.planned_units()

    @property
    def peer_units_data_interfaces(self) -> dict[Unit, DataPeerOtherUnitData]:
        """The cluster peer relation."""
        return {
            unit: DataPeerOtherUnitData(
                model=self.model, unit=unit, relation_name=self.peer_relation_name
            )
            for unit in self.peers_units
        }

    @property
    def formatted_socket_path(self) -> str:
        """URL encoded socket path.

        Explanation: On Mongos VM which is a subordinate charm, we'd rather
        share the connection with a socket in order to improve latency.
        """
        return quote(f"{self.paths.socket_path}", safe="")

    def hosts_for(self, relation: Relation) -> set[str]:
        """Retrieve the hosts associated with MongoDB application."""
        if self.substrate == Substrates.K8S and self.charm_role.name == CharmKind.MONGOS:
            if self.config.expose_external == ExposeExternal.NODEPORT:
                return {f"{unit.node_ip}" for unit in self.units}
        return {unit.address_for(relation.name) for unit in self.units}

    @property
    def unit_host(self) -> str | None:
        """The Unit host for mongos external clients."""
        assert self.charm_role.name == CharmKind.MONGOS
        if self.substrate == Substrates.K8S:
            return f"{self.unit_peer_data.node_ip}"
        return None

    @property
    def is_external_client(self) -> bool:
        """The universal external connectivity for mongos charms."""
        if self.charm_role.name == CharmKind.MONGOD:
            return False
        if self.substrate == Substrates.VM:
            return self.app_peer_data.external_connectivity
        return self.config.expose_external == ExposeExternal.NODEPORT

    @property
    def internal_hosts(self) -> set[str]:
        """Internal hosts for internal access."""
        if (
            self.substrate == Substrates.VM
            and self.charm_role.name == CharmKind.MONGOS
            and not self.app_peer_data.external_connectivity
        ):
            return {self.formatted_socket_path}
        return {unit.internal_address for unit in self.units}

    @property
    def host_port(self) -> int:
        """Retrieve the port associated with MongoDB application."""
        if self.is_role(MongoDBRoles.MONGOS):
            if self.is_external_client and self.substrate == Substrates.K8S:
                return self.unit_peer_data.node_port
            return MongoPorts.MONGOS_PORT.value
        return MongoPorts.MONGODB_PORT.value

    @property
    def config_server_data_interface(self) -> DatabaseProviderData:
        """The config server database interface."""
        return DatabaseProviderData(self.model, RelationNames.CONFIG_SERVER.value)

    @property
    def shard_state_interface(self) -> DatabaseRequirerData:
        """The shard database interface."""
        return DatabaseRequirerData(
            self.model,
            relation_name=RelationNames.SHARDING.value,
            additional_secret_fields=SECRETS_FIELDS,
            database_name="unused",  # Needed for relation events
        )

    @property
    def shard_state(self) -> AppShardingComponentState:
        """The app shard state."""
        return AppShardingComponentState(
            relation=self.shard_relation,
            data_interface=self.shard_state_interface,
            component=self.model.app,
        )

    def config_server_state(self, relation: Relation) -> AppShardingComponentState:
        """The app shard state."""
        return AppShardingComponentState(
            relation=relation,
            data_interface=self.config_server_data_interface,
            component=relation.app,
        )

    @property
    def unit_shard_state(self) -> UnitShardingComponentState:
        """The unit shard state."""
        return UnitShardingComponentState(
            relation=self.shard_relation,
            data_interface=self.shard_state_interface,
            component=self.model.unit,
        )

    @property
    def config_server_name(self) -> str | None:
        """Gets the config server name."""
        if self.charm_role.name == CharmKind.MONGOS:
            if self.mongos_cluster_relation:
                return self.cluster.replica_set
            return None
        if self.is_role(MongoDBRoles.SHARD):
            if self.shard_relation:
                return self.shard_state.config_server_replset
            return None
        logger.debug(
            "Component %s is not a shard, cannot be integrated to a config-server.",
            self.app_peer_data.role,
        )
        return None

    @property
    def config_server_uri(self) -> str | None:
        """Gets the config-server URI for Mongos."""
        if self.charm_role.name == CharmKind.MONGOS:
            return self.cluster.config_server_uri
        if not self.is_role(MongoDBRoles.CONFIG_SERVER):
            return None
        return f"{self.app_peer_data.replica_set}/{self.unit_peer_data.internal_address}:{MongoPorts.MONGODB_PORT.value}"

    def get_subject_name(self) -> str:
        """Generate the subject name for CSR."""
        # In sharded MongoDB deployments it is a requirement that all subject names match across
        # all cluster components. The config-server name is the source of truth across mongos and
        # shard deployments.
        if self.is_role(MongoDBRoles.REPLICATION) or self.is_role(MongoDBRoles.CONFIG_SERVER):
            return self.model.app.name
        # until integrated with config-server use current app name as
        # subject name
        return self.config_server_name or self.model.app.name

    def generate_config_server_db(self, relation: Relation) -> str:
        """Generates the config server DB URI."""
        replica_set_name = self.model.app.name
        hosts = sorted(
            f"{host}:{MongoPorts.MONGODB_PORT.value}" for host in self.hosts_for(relation)
        )
        return f"{replica_set_name}/{','.join(hosts)}"

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

    def is_shard_added_to_cluster(self) -> bool:
        """Returns true if the shard has been added to the clusted."""
        # this information is required in order to check if we have been added
        if not self.config_server_name or not self.app_peer_data.mongos_hosts:
            return False

        # We can't check if we don't have a valid certificate
        if self.shard_state.external_ca_secret is not None and not self.tls.client_enabled:
            return False

        if not self.shard_state.shard_integrated:
            return False

        try:
            # check our ability to use connect to mongos
            with MongoConnection(self.remote_mongos_config) as mongos:
                members = mongos.get_shard_members()
        except FileNotFoundError:
            return False
        except OperationFailure as e:
            if e.code in (
                MongoErrorCodes.UNAUTHORIZED,
                MongoErrorCodes.AUTHENTICATION_FAILED,
                MongoErrorCodes.FAILED_TO_SATISFY_READ_PREFERENCE,
            ):
                return False
            raise
        except (ServerSelectionTimeoutError, AutoReconnect, NotPrimaryError, ConfigurationError):
            # Connection refused, - this occurs when internal membership is not in sync across the
            # cluster (i.e. TLS + KeyFile).
            return False

        return self.app_peer_data.replica_set in members

    @property
    def peer_database_addresses(self) -> list[str]:
        """Return the database addresses published by remote peer units."""
        return [unit.database_address for unit in self.units if unit.database_address]

    @property
    def related_cluster_hosts(self) -> list[str]:
        """Return hosts published by related sharding components.

        The config servers get the RS hosts from all the shards it is integrated with.
        The shards get the mongos hosts from config server it is integrated with.
        """
        if self.substrate != Substrates.VM:
            return []
        if self.is_role(MongoDBRoles.CONFIG_SERVER):
            hosts = []
            for relation in self.config_server_relation:
                hosts.extend(
                    AppShardingComponentState(
                        relation=relation,
                        data_interface=self.config_server_data_interface,
                        component=relation.app,
                    ).rs_hosts
                )
            return sorted(set(hosts))

        if self.is_role(MongoDBRoles.SHARD):
            return sorted(set(self.shard_state.mongos_hosts))

        return []

    # BEGIN: Configuration accessors
    @property
    def local_auth_restrictions(self) -> list[AuthRestrictions]:
        """Return auth restrictions for local users."""
        peer_client_sources = cidrs(self.peer_network().bind_addresses)
        peer_client_sources.extend(self.peer_database_addresses)
        peer_client_sources.extend(self.related_cluster_hosts)
        peer_client_sources = sorted(set(peer_client_sources))

        return [
            AuthRestrictions(clientSource=[LOCALHOST], serverAddress=[LOCALHOST]),
            AuthRestrictions(
                clientSource=peer_client_sources,
                serverAddress=peer_client_sources,
            ),
        ]

    def has_credentials(self) -> bool:
        """Checks if we have received credentials or not."""
        try:
            self.mongo_config
            return True
        except MissingCredentialsError:
            return False

    def mongodb_config_for_user(
        self,
        user: MongoDBUser,
        hosts: set[str] | None = None,
        replset: str | None = None,
        standalone: bool = False,
        auth_restrictions: list[AuthRestrictions] | None = None,
        tls_external_ca: Path | None = None,
    ) -> MongoConfiguration:
        """Returns a mongodb-specific MongoConfiguration object for the provided user.

        Either user.hosts or hosts should be a non empty set.

        Returns:
            A MongoDB configuration object.

        Raises:
            Exception if neither user.hosts nor hosts is non empty.
        """
        if not hosts:
            hosts = set()
        if not user.hosts and not hosts:
            raise Exception("Invalid call: no host in user nor as a parameter.")
        if not auth_restrictions:
            auth_restrictions = []
        # TLS is considered enabled if we have client certificates AND they are on the file system.
        tls_external_ca = tls_external_ca or self.paths.ext_ca_file
        tls_enabled = self.tls.client_enabled and tls_external_ca.exists()
        return MongoConfiguration(
            replset=replset or self.app_peer_data.replica_set,
            database=user.database_name,
            username=user.username,
            password=self.get_user_password(user),
            hosts=hosts or user.hosts,
            port=MongoPorts.MONGODB_PORT.value,
            roles=user.roles,
            tls_enabled=tls_enabled,
            tls_external_ca=tls_external_ca,
            standalone=standalone,
            auth_restrictions=auth_restrictions,
        )

    def mongos_config_for_user(
        self,
        user: MongoDBUser,
        hosts: set[str] | None = None,
        tls_external_ca: Path | None = None,
    ) -> MongoConfiguration:
        """Returns a mongos-specific MongoConfiguration object for the provided user.

        Either user.hosts or hosts should be a non empty set.

        Returns:
            A MongoDB configuration object.

        Raises:
            Exception if neither user.hosts nor hosts is non empty.
        """
        if not hosts:
            hosts = set()
        if not user.hosts and not hosts:
            raise Exception("Invalid call: no host in user nor as a parameter.")
        # TLS is considered enabled if we have client certificates AND they are on the file system.
        tls_external_ca = tls_external_ca or self.paths.ext_ca_file
        tls_enabled = self.tls.client_enabled and tls_external_ca.exists()
        return MongoConfiguration(
            database=user.database_name,
            username=user.username,
            password=self.get_user_password(user),
            hosts=hosts or user.hosts,
            port=MongoPorts.MONGOS_PORT.value,
            roles=user.roles,
            tls_enabled=tls_enabled,
            tls_external_ca=tls_external_ca,
        )

    @property
    def backup_config(self) -> MongoConfiguration:
        """Mongo Configuration for the charmed-backup user."""
        return self.mongodb_config_for_user(
            CharmedBackupUser, standalone=True, auth_restrictions=self.local_auth_restrictions
        )

    @property
    def stats_config(self) -> MongoConfiguration:
        """Mongo Configuration for the charmed-stats user."""
        return self.mongodb_config_for_user(
            CharmedStatsUser, auth_restrictions=self.local_auth_restrictions
        )

    @property
    def logrotate_config(self) -> MongoConfiguration:
        """Mongo Configuration for the charmed-logrotate user."""
        return self.mongodb_config_for_user(
            CharmedLogRotateUser, standalone=True, auth_restrictions=self.local_auth_restrictions
        )

    @property
    def operator_config(self) -> MongoConfiguration:
        """Mongo Configuration for the charmed-operator user."""
        return self.mongodb_config_for_user(CharmedOperatorUser, hosts=self.internal_hosts)

    @property
    def remote_mongos_config(self) -> MongoConfiguration:
        """Mongos Configuration for the remote mongos server."""
        mongos_hosts = self.app_peer_data.mongos_hosts
        return self.mongos_config_for_user(
            CharmedOperatorUser, set(mongos_hosts), self.paths.config_server_ext_ca_file
        )

    @property
    def mongos_config(self) -> MongoConfiguration:
        """Mongos Configuration for the admin mongos user."""
        if self.charm_role.name == CharmKind.MONGOD:
            return self.mongos_config_for_user(CharmedOperatorUser, self.internal_hosts)
        username, password = self.get_user_credentials()
        database = self.app_peer_data.database
        port: int | None = MongoPorts.MONGOS_PORT.value

        # VM Mongos without external connectivity is using the UNIX socket.
        if (
            self.charm_role.name == CharmKind.MONGOS
            and self.substrate == Substrates.VM
            and not self.app_peer_data.external_connectivity
        ):
            port = None

        if not username or not password:
            raise MissingCredentialsError("Missing credentials.")

        # TLS is considered enabled if we have client certificates AND they are on the file system.
        tls_enabled = self.tls.client_enabled and self.paths.ext_ca_file.exists()

        return MongoConfiguration(
            database=database,
            username=username,
            password=password,
            hosts=self.internal_hosts,
            # unlike the vm mongos charm, the K8s charm does not communicate with the unix socket
            port=port,
            roles={RoleNames.ADMIN},
            tls_enabled=tls_enabled,
            tls_external_ca=self.paths.ext_ca_file,
        )

    @property
    def mongo_config(self) -> MongoConfiguration:
        """The mongo configuration to use by default for charm interactions."""
        if self.charm_role.name == CharmKind.MONGOD:
            return self.operator_config
        return self.mongos_config

    # END: Configuration accessors

    def get_secret_from_id(self, secret_id: str) -> dict[str, str]:
        """Resolve the given id of a Juju secret and return the content as a dict.

        Args:
            secret_id (str): The id of the secret.

        Returns:
            dict: The content of the secret.
        """
        if not secret_id.startswith("secret:"):
            raise ValueError(f"Invalid secret URI '{secret_id}'. It must start with 'secret:'")
        try:
            secret_content = self.charm.model.get_secret(id=secret_id).get_content(refresh=True)
        except SecretNotFoundError:
            raise SecretNotFoundError(f"The secret '{secret_id}' does not exist.")
        except ModelError:
            raise

        return secret_content

    # BEGIN: Addresses accessors
    def client_network(self) -> Network:
        """Listening IP for that unit on the client relation."""
        return network_get(self.client_relation_name)

    def peer_network(self) -> Network:
        """Listening IP for that unit on the peer relation."""
        return network_get(self.peer_relation_name)

    def sharding_network(self) -> Network:
        """Listening IP for that unit on the sharding relation."""
        return network_get(RelationNames.SHARDING.value)

    def config_server_network(self) -> Network:
        """Listening IP for that unit on the config-server relation."""
        return network_get(RelationNames.CONFIG_SERVER.value)

    def cluster_network(self) -> Network:
        """Listening IP for that unit on the sharding relation."""
        return network_get(RelationNames.CLUSTER.value)

    def listen_hosts(self) -> set[str]:
        """All the hosts to listen to."""
        if self.substrate == Substrates.VM:
            return set()
        return {self.unit_peer_data.internal_address}

    def listen_ips(self) -> set[str]:
        """All the IPs to listen to."""
        if self.substrate == Substrates.K8S:
            return {"127.0.0.1"}
        ip_list: list[str] = [
            *ip_addresses(self.client_network().bind_addresses),
            *ip_addresses(self.peer_network().bind_addresses),
        ]
        if self.is_sharding_component:
            ip_list.extend(ip_addresses(self.sharding_network().bind_addresses))
            ip_list.extend(
                ip_addresses(self.config_server_network().bind_addresses),
            )
        if self.is_cluster_component:
            ip_list.extend(ip_addresses(self.cluster_network().bind_addresses))

        # Localhost
        ip_list.append("127.0.0.1")

        return {str(ip) for ip in ip_list if ip}

    def listens_on(self) -> set[str]:
        """Everything we should listen on."""
        return {*self.listen_ips(), *self.listen_hosts()}
