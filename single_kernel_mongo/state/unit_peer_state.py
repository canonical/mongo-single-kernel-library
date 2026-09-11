# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer unit relation databag."""

import json
from enum import Enum
from functools import cached_property

from ops.model import Relation, Unit

from single_kernel_mongo.config.literals import MongoPorts, Substrates
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerUnitData,
)
from single_kernel_mongo.managers.k8s import K8sManager
from single_kernel_mongo.state.abstract_state import AbstractRelationState
from single_kernel_mongo.utils.network_helpers import k8s_fqdn


class UnitPeerRelationKeys(str, Enum):
    """The peer relation model."""

    PRIVATE_ADDRESS = "private-address"
    INGRESS_ADDRESS = "ingress-address"
    EGRESS_SUBNETS = "egress-subnets"
    DRAINED = "drained"
    CURRENT_REVISION = "current_revision"

    # IPs of the relations
    DATABASE_ADDRESS = "database-address"
    CONFIG_SERVER_ADDRESS = "config-server-address"
    CLUSTER_ADDRESS = "cluster-address"
    MONGOS_PROXY_ADDRESS = "mongos_proxy-address"


class UnitPeerReplicaSet(AbstractRelationState[DataPeerUnitData]):
    """State collection for unit data."""

    component: Unit

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
        substrate: Substrates,
        k8s_manager: K8sManager,
        bind_address: str | None = None,
    ):
        super().__init__(relation, data_interface, component, None)
        self.data_interface = data_interface
        self.substrate = substrate
        self.unit = component
        self.bind_address = bind_address
        self.k8s = k8s_manager

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
    def unit_service_name(self) -> str:
        """Unit service name (local)."""
        return f"{self.unit.name.split('/')[0]}-{self.unit_id}.{self.unit.name.split('/')[0]}-endpoints"

    @property
    def internal_address(self) -> str:
        """The address for internal communication between brokers."""
        if self.substrate == Substrates.VM:
            # We directly access the value in the relation here because of external applications.
            if self.bind_address:
                return self.bind_address
            # It's a remote unit so we need the relation.
            assert self.relation
            return str(
                self.relation.data[self.component].get(UnitPeerRelationKeys.PRIVATE_ADDRESS.value)
            )
        # K8s Case.
        return k8s_fqdn(self.unit_service_name)

    @property
    def name(self) -> str:
        """The unit name."""
        return self.unit.name

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

    @property
    def drained(self) -> bool:
        """Returns True if the shard is drained.

        We check the unit databag rather than the app databag since a draining
        operation blocks all events from occurring. The unit databag allows us
        to update and check our draining status in the same event as the
        draining. Unlike the app databag which triggers requires a
        RelationChangedEvent to propagate.
        """
        return json.loads(self.relation_data.get(UnitPeerRelationKeys.DRAINED.value, "false"))

    @drained.setter
    def drained(self, value: bool):
        if not isinstance(value, bool):
            raise ValueError(f"drained value is not boolean but {value}")
        self.update({UnitPeerRelationKeys.DRAINED.value: json.dumps(value)})

    @property
    def current_revision(self) -> str:
        """The revision of the charm that's running before the upgrade."""
        return self.relation_data.get(UnitPeerRelationKeys.CURRENT_REVISION, "-1")

    @current_revision.setter
    def current_revision(self, value: str):
        self.update({UnitPeerRelationKeys.CURRENT_REVISION.value: value})

    @property
    def database_address(self) -> str:
        """The address of that unit on the database interface."""
        return self.relation_data.get(UnitPeerRelationKeys.DATABASE_ADDRESS, "")

    @database_address.setter
    def database_address(self, value: str):
        self.update({UnitPeerRelationKeys.DATABASE_ADDRESS.value: value})

    @property
    def config_server_address(self) -> str:
        """The address of that unit on the config_server interface."""
        return self.relation_data.get(UnitPeerRelationKeys.CONFIG_SERVER_ADDRESS, "")

    @config_server_address.setter
    def config_server_address(self, value: str):
        self.update({UnitPeerRelationKeys.CONFIG_SERVER_ADDRESS.value: value})

    @property
    def cluster_address(self) -> str:
        """The address of that unit on the cluster interface."""
        return self.relation_data.get(UnitPeerRelationKeys.CLUSTER_ADDRESS, "")

    @cluster_address.setter
    def cluster_address(self, value: str):
        self.update({UnitPeerRelationKeys.CLUSTER_ADDRESS.value: value})

    @property
    def mongos_proxy_address(self) -> str:
        """The address of that unit on the mongos_proxy interface."""
        return self.relation_data.get(UnitPeerRelationKeys.MONGOS_PROXY_ADDRESS, "")

    @mongos_proxy_address.setter
    def mongos_proxy_address(self, value: str):
        self.update({UnitPeerRelationKeys.MONGOS_PROXY_ADDRESS.value: value})

    def address_for(self, relation_name: str) -> str:
        """Address for the correct relation."""
        if self.substrate == Substrates.VM:
            return self.relation_data.get(f"{relation_name}-address", "")
        # K8s Case.
        return k8s_fqdn(self.unit_service_name)
