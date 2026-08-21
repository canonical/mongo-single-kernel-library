#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Cluster state."""

import json
from enum import Enum

from ops import Application
from ops.model import Relation

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import Data
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class ClusterStateKeys(str, Enum):
    """Cluster State Model."""

    DATABASE = "database"
    EXTRA_USER_ROLES = "extra-user-roles"
    ALIAS = "alias"
    EXTERNAL_NODE_CONNECTIVITY = "external-node-connectivity"
    CONFIG_SERVER_DB = "config-server-db"
    REPLICA_SET = "replset"
    KEYFILE = "key-file"
    INT_CA_SECRET = "int-ca-secret"
    EXT_CA_SECRET = "ext-ca-secret"
    LDAP_USER_TO_DN_MAPPING = "ldap-user-to-dn-mapping"
    LDAP_HASH = "ldap-hash"
    USERNAME = "username"
    PASSWORD = "password"
    CLUSTER_ID = "cluster-id"


class ClusterState(AbstractRelationState[Data]):
    """The stored state for the Cluster relation."""

    component: Application

    def __init__(self, relation: Relation | None, data_interface: Data, component: Application):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface

    @property
    def config_server_uri(self) -> str:
        """Return config-server URI in the databag."""
        return self.relation_data.get(ClusterStateKeys.CONFIG_SERVER_DB.value, "")

    @property
    def username(self) -> str:
        """Return config-server URI in the databag."""
        return self.relation_data.get(ClusterStateKeys.USERNAME.value, "")

    @property
    def password(self) -> str:
        """Return config-server URI in the databag."""
        return self.relation_data.get(ClusterStateKeys.PASSWORD.value, "")

    @property
    def database(self) -> str:
        """Return database value in the databag."""
        return self.relation_data.get(ClusterStateKeys.DATABASE.value, None)

    @database.setter
    def database(self, value: str):
        self.update({ClusterStateKeys.DATABASE.value: value})

    @property
    def keyfile(self) -> str:
        """The keyfile in the relation databag."""
        return self.relation_data.get(ClusterStateKeys.KEYFILE.value, "")

    @property
    def extra_user_roles(self) -> set[str]:
        """Return extra user roles value in the databag."""
        return set(  # type: ignore[return-value]
            self.relation_data.get(ClusterStateKeys.EXTRA_USER_ROLES.value, "default").split(",")
        )

    @extra_user_roles.setter
    def extra_user_roles(self, value: set[str]):
        roles_str = ",".join(value)
        self.update({ClusterStateKeys.EXTRA_USER_ROLES.value: roles_str})

    @property
    def internal_ca_secret(self) -> str | None:
        """Returns the internal CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(ClusterStateKeys.INT_CA_SECRET.value, None)

    @property
    def external_ca_secret(self) -> str | None:
        """Returns the external CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(ClusterStateKeys.EXT_CA_SECRET.value, None)

    @property
    def ldap_user_to_dn_mapping(self) -> str | None:
        """Returns the userToDNMapping config option shared by the config-server."""
        return self.relation_data.get(ClusterStateKeys.LDAP_USER_TO_DN_MAPPING.value, None)

    @property
    def ldap_hash(self) -> str | None:
        """Returns the ldap hash shared by the config-server."""
        return self.relation_data.get(ClusterStateKeys.LDAP_HASH.value, None)

    @property
    def external_node_connectivity(self) -> bool:
        """Returns the external-connectivity flag."""
        return json.loads(
            self.relation_data.get(ClusterStateKeys.EXTERNAL_NODE_CONNECTIVITY.value, "false")
        )

    @external_node_connectivity.setter
    def external_node_connectivity(self, value: bool) -> None:
        """Sets the external-connectivity flag."""
        self.update({ClusterStateKeys.EXTERNAL_NODE_CONNECTIVITY.value: json.dumps(value)})

    @property
    def cluster_id(self) -> str | None:
        """Returns the cluster ID."""
        return self.relation_data.get(ClusterStateKeys.CLUSTER_ID.value, None)

    @property
    def replica_set(self) -> str | None:
        """The name of the replica set."""
        if not self.relation:
            return None
        return self.relation_data.get(ClusterStateKeys.REPLICA_SET.value, None)

    @replica_set.setter
    def replica_set(self, value: str):
        """Sets the replset field."""
        self.update({ClusterStateKeys.REPLICA_SET.value: value})
