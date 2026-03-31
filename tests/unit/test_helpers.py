# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from ops.hookcmds import Network

from single_kernel_mongo.utils.helpers import hostname_from_hostport, mask_sensitive_information
from single_kernel_mongo.utils.network_helpers import cidrs, get_cidr_for_ip_list, ip_addresses


def test_hostname_from_hostport():
    hostname = "127.0.0.1:27017"
    assert hostname_from_hostport(hostname) == "127.0.0.1"


def test_mask_cmd():
    assert mask_sensitive_information("hmacSecret=deadbeef") == "hmacSecret=xxx"


def test_get_cidr_for_ip_list():
    assert get_cidr_for_ip_list(["10.0.3.254", "10.0.3.136"]) == "10.0.3.0/24"
    assert get_cidr_for_ip_list(["10.0.3.254"]) == "10.0.3.254/24"
    assert get_cidr_for_ip_list(["10.1.2.254", "10.1.3.136"]) == "10.1.0.0/16"
    assert (
        get_cidr_for_ip_list(["2001:1234:0:1000::", "2001:1234:0:1000:1234::"])
        == "2001:1234:0:1000::/64"
    )


def test_ip_addresses():
    network = Network._from_dict(
        {
            "bind-addresses": [
                {
                    "mac-address": "aa:bb",
                    "interface-name": "eth0",
                    "addresses": [{"hostname": "host", "value": "10.0.0.1", "cidr": "10.0.0.1/24"}],
                },
                {
                    "mac-address": "cc:dd",
                    "interface-name": "enp0s9",
                    "addresses": [{"hostname": "host", "value": "10.0.1.2", "cidr": "10.0.1.1/24"}],
                },
            ],
            "egress-subnets": ["127.0.0.0/24"],
            "ingress-addresses": ["10.0.0.1"],
        }
    )
    assert ip_addresses(network.bind_addresses) == ["10.0.0.1", "10.0.1.2"]


def test_cidrs():
    network = Network._from_dict(
        {
            "bind-addresses": [
                {
                    "mac-address": "aa:bb",
                    "interface-name": "eth0",
                    "addresses": [{"hostname": "host", "value": "10.0.0.1", "cidr": "10.0.0.1/24"}],
                },
                {
                    "mac-address": "cc:dd",
                    "interface-name": "enp0s9",
                    "addresses": [{"hostname": "host", "value": "10.0.1.2", "cidr": "10.0.1.1/24"}],
                },
            ],
            "egress-subnets": ["127.0.0.0/24"],
            "ingress-addresses": ["10.0.0.1"],
        }
    )
    assert cidrs(network.bind_addresses) == ["10.0.0.1/24", "10.0.1.1/24"]
