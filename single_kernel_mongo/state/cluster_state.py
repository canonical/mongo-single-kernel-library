#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Cluster state."""

from ops import Application
from ops.model import Relation
from pydantic import BaseModel, Field

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import Data
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class ClusterStateModel(BaseModel):
    """Cluster State Model."""

    database: str | None = Field(default=None)
    extra_user_roles: str | None = Field(default=None, alias="extra-user-roles")
    alias: str | None = Field(default=None)
    external_node_connectivity: bool = Field(default=False, alias="external-node-connectivity")
    config_server_db: str | None = Field(default=None, alias="config-server-db")


class ClusterState(AbstractRelationState[ClusterStateModel, Data]):
    """The stored state for the TLS relation."""

    component: Application

    def __init__(self, relation: Relation | None, data_interface: Data, component: Application):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface

    @property
    def config_server_uri(self) -> str:
        """Is TLS enabled."""
        return self.relation_data.config_server_db or ""
