# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer unit relation databag."""

from enum import Enum
from functools import cached_property

from ops.model import Relation, Unit

from single_kernel_mongo.config.literals import MongoPorts, Substrates
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerUnitData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class UnitPeerRelationKeys(str, Enum):
    """The peer relation model."""

    private_address = "private-address"
    ingress_address = "ingress-address"
    egress_subnets = "egress-subnets"


class UnitPeerReplicaSet(AbstractRelationState[DataPeerUnitData]):
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
        self.k8s = K8sManager(
            pod_name=self.pod_name,
            namespace=self.unit._backend.model_name,
        )

    @property
    def pod_name(self) -> str:
        """K8S only: The pod name."""
        return self.unit.name.replace("/", "-")

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
            return str(self.relation_data.get(UnitPeerRelationKeys.private_address))

        if self.substrate == "k8s":
            return f"{self.unit.name.split('/')[0]}-{self.unit_id}.{self.unit.name.split('/')[0]}-endpoints"

        return ""

    @property
    def host(self) -> str:
        """Return the hostname of a unit."""
        if self.substrate == "vm":
            return self.internal_address
        return self.node_ip or self.internal_address

    @cached_property
    def node_ip(self) -> str:
        """The IPV4/IPV6 IP address the Node the unit is on.

        K8s-only.
        """
        return self.k8s.get_node_ip(self.pod_name)

    @cached_property
    def node_port(self) -> int:
        """The port for this unit.

        K8s-only.
        """
        return self.k8s.get_node_port(MongoPorts.MONGOS_PORT)
