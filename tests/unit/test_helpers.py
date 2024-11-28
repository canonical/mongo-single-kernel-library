# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import base64

from single_kernel_mongo.utils.helpers import hostname_from_hostport, parse_tls_file


def test_hostname_from_hostport():
    hostname = "127.0.0.1:27017"
    assert hostname_from_hostport(hostname) == "127.0.0.1"


def test_parse_tls_file_raw():
    with open("tests/unit/data/key.pem") as fd:
        certificate = "".join(fd.readlines()).rstrip()
    certificate_b64 = base64.b64encode(certificate.encode("utf-8")).decode("utf-8")
    decoded = parse_tls_file(certificate)
    assert decoded == certificate.encode("utf-8")
    assert decoded == parse_tls_file(certificate_b64)
