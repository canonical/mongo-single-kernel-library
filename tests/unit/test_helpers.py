# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from single_kernel_mongo.utils.helpers import hostname_from_hostport, mask_sensitive_information
from single_kernel_mongo.utils.network_helpers import get_cidr_for_ip_list


def test_hostname_from_hostport():
    hostname = "127.0.0.1:27017"
    assert hostname_from_hostport(hostname) == "127.0.0.1"


def test_mask_cmd():
    assert mask_sensitive_information("hmacSecret=deadbeef") == "hmacSecret=xxx"


def test_get_cidr_for_ip_list():
    assert get_cidr_for_ip_list(["10.0.3.254", "10.0.3.136"]) == "10.0.3.0/24"
