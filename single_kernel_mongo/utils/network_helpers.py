#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for network interfaces."""

import os
import socket
import subprocess  # nosec: B404
from collections.abc import Sequence
from ipaddress import ip_address, ip_network
from logging import getLogger

from ops import Relation
from ops.hookcmds import BindAddress, Network, network_get

logger = getLogger(__name__)


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


def get_cidr_for_ip_list(ip_list: list[str]) -> str:
    """Returns a CIDR (/8, /16, ...) for a set of ip addresses.

    Works for both IPv4 and IPv6.
    """
    ip_v4 = ip_address(ip_list[0]).version == 4
    if ip_v4:
        version = 4
        ip_length = 4
        block_length = 8
        split_sign = "."
    else:
        version = 6
        ip_length = 8
        block_length = 16
        split_sign = ":"

    # Return smallest slash bound to a limiter (/24 for IPv4, /112 for IPv6
    if len(ip_list) == 1:
        return ip_list[0] + f"/{(ip_length - 1) * block_length}"

    if not all(ip_address(ip).version == version for ip in ip_list):
        raise ValueError("Invalid IP list received, not all versions matching.")

    ip_list_split = [ip_address(ip).exploded.split(split_sign) for ip in ip_list]
    first = ip_list_split[0]
    acc = []

    for i in range(len(first)):
        if any(ip[i] != ip_list_split[0][i] for ip in ip_list_split):
            break
        acc.append(ip_list_split[0][i])

    slash = block_length * len(acc)

    while len(acc) < ip_length:
        acc.append("0")

    return ip_network(split_sign.join(acc) + f"/{slash}").compressed


def k8s_fqdn(service_name: str) -> str:
    """Resolve the canonical FQDN for a Kubernetes service or pod name."""
    if not service_name:
        return ""

    try:
        info = socket.getaddrinfo(
            host=service_name,
            port=None,
            family=socket.AF_UNSPEC,
            flags=socket.AI_CANONNAME,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as e:
        logger.warning(
            "Failed to resolve canonical name for %s: %s. \nFalling back on default fqdn.",
            service_name,
            e,
        )
        return socket.getfqdn(service_name)

    for entry in info:
        if canonname := entry[3]:
            return canonname

    logger.warning(
        "Failed to resolve canonical name for %s. \nFalling back on default fqdn.", service_name
    )
    return socket.getfqdn(service_name)
