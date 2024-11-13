# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer unit relation databag."""

from ops.model import Relation, Unit
from pydantic import BaseModel, Field

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerUnitData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class UnitPeerRelationModel(BaseModel):
    """The peer relation model."""

    private_address: str = Field(default="", alias="private-address")
    ingress_address: str = Field(default="", alias="ingress-address")
    egress_subnets: str = Field(default="", alias="egress-subnets")


class UnitPeerReplicaSet(AbstractRelationState[UnitPeerRelationModel, DataPeerUnitData]):
    """State collection for unit data."""

    component: Unit

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
        substrate: Substrates,
    ):
        super().__init__(relation, data_interface, component, None)
        self.data_interface = data_interface
        self.substrate = substrate
        self.unit = component

    @property
    def unit_id(self) -> int:
        """The id of the unit from the unit name.

        e.g mongodb/2 --> 2
        """
        return int(self.unit.name.split("/")[1])

    @property
    def internal_address(self) -> str:
        """The address for internal communication between brokers."""
        if self.substrate == "vm":
            return self.relation_data.private_address

        if self.substrate == "k8s":
            return f"{self.unit.name.split('/')[0]}-{self.unit_id}.{self.unit.name.split('/')[0]}-endpoints"

        return ""
