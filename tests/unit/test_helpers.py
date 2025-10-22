# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from single_kernel_mongo.utils.helpers import hostname_from_hostport


def test_hostname_from_hostport():
    hostname = "127.0.0.1:27017"
    assert hostname_from_hostport(hostname) == "127.0.0.1"
