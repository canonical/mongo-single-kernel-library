#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The general charm state."""

from functools import cached_property
from ipaddress import IPv4Address, IPv6Address

from ops import CharmBase, Object, Relation, Unit

from single_kernel_mongo.config.literals import SECRETS_UNIT, Substrates
from single_kernel_mongo.config.relations import RelationNames, RequirerRelations
from single_kernel_mongo.config.roles import ROLES
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerData,
    DataPeerOtherUnitData,
    DataPeerUnitData,
)
from single_kernel_mongo.state.backup_state import BackupState
from single_kernel_mongo.state.cluster_state import ClusterState
from single_kernel_mongo.state.peer_state import AppPeerReplicaSet, UnitPeerReplicaSet
from single_kernel_mongo.state.tls_state import TLSState


class CharmState(Object):
    """All the charm states."""

    backup: BackupState

    def __init__(self, charm: CharmBase, substrate: Substrates):
        super().__init__(parent=charm, key="charm_state")
        self.roles = ROLES[substrate]
        self.config = charm.config
        self.substrate: Substrates = substrate

        self.peer_app_interface = DataPeerData(
            self.model,
            relation_name=RelationNames.PEERS,
        )
        self.peer_unit_interface = DataPeerUnitData(
            self.model,
            relation_name=RelationNames.PEERS,
            additional_secret_fields=SECRETS_UNIT,
        )

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
    def tls_relation(self) -> Relation | None:
        """The TLS relation."""
        return self.model.get_relation(RequirerRelations.TLS)

    @property
    def tls(self) -> TLSState:
        """The tls state of the current running app."""
        return TLSState(
            relation=self.tls_relation,
        )

    @property
    def cluster(self) -> ClusterState:
        """The cluster state of the current running App."""
        return ClusterState()

    @property
    def app(self) -> AppPeerReplicaSet:
        """The app peer relation data."""
        return AppPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_app_interface,
            component=self.model.app,
            role=str(self.config["role"]),
        )

    @property
    def unit(self) -> UnitPeerReplicaSet:
        """This unit peer relation data."""
        return UnitPeerReplicaSet(
            relation=self.peer_relation,
            data_interface=self.peer_unit_interface,
            component=self.model.unit,
            substrate=self.substrate,
        )

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
        _units.add(self.unit)

        return _units

    @property
    def app_hosts(self) -> set[str]:
        """Retrieve the hosts associated with MongoDB application."""
        return {unit.internal_address for unit in self.units}
