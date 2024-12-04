#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Cluster state."""

from enum import Enum

from ops import Application
from ops.model import Relation

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import Data
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class ClusterStateKeys(str, Enum):
    """Cluster State Model."""

    database = "database"
    extra_user_roles = "extra-user-roles"
    alias = "alias"
    external_node_connectivity = "external-node-connectivity"
    config_server_db = "config-server-db"


class ClusterState(AbstractRelationState[Data]):
    """The stored state for the Cluster relation."""

    component: Application

    def __init__(self, relation: Relation | None, data_interface: Data, component: Application):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface

    @property
    def config_server_uri(self) -> str:
        """Is TLS enabled."""
        return self.relation_data.get(ClusterStateKeys.config_server_db, "")
