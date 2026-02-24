#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for network interfaces."""

import os
import subprocess  # nosec: B404
from collections.abc import Sequence

from ops import Relation
from ops.hookcmds import BindAddress, Network, network_get


def ip_addresses(bind_addresses: Sequence[BindAddress]) -> Sequence[str]:
    """Returns all ip addresses for a sequence of bindaddress."""
    return [address.value for bind_address in bind_addresses for address in bind_address.addresses]


def cidrs(bind_addresses: Sequence[BindAddress]) -> list[str]:
    """Returns all ip addresses for a sequence of bindaddress."""
    result: set[str] = set()
    for bind_address in bind_addresses:
        for address in bind_address.addresses:
            if address.cidr:
                result.add(address.cidr)
            else:
                result.add(f"{address.value}/24")
    return sorted(result)


def network_for_relation(relation: Relation) -> Network:
    """Return network for a specific relation."""
    return network_get(binding_name=relation.name, relation_id=relation.id)


def get_host_public_ip() -> set[str]:
    """Fetches the Public IP address of the current unit."""
    cmd = "unit-get public-address".split()
    output = subprocess.run(  # nosec: B603
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=25,
        env=os.environ,
    )
    if output.returncode != 0:
        return set()

    return {output.stdout.strip()}
