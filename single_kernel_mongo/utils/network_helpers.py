#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for network interfaces."""

from collections.abc import Sequence

from ops import Relation
from ops.hookcmds import BindAddress, Network, network_get


def ip_addresses(bind_addresses: Sequence[BindAddress]) -> Sequence[str]:
    """Returns all ip addresses for a sequence of bindaddress."""
    return [address.value for bind_address in bind_addresses for address in bind_address.addresses]


def cidrs(bind_addresses: Sequence[BindAddress]) -> list[str]:
    """Returns all ip addresses for a sequence of bindaddress."""
    return [address.cidr for bind_address in bind_addresses for address in bind_address.addresses]


def network_for_relation(relation: Relation) -> Network:
    """Return network for a specific relation."""
    return network_get(binding_name=relation.name, relation_id=relation.id)
