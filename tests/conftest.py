# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
from _pytest.config.argparsing import Parser

from tests.integration.helpers.types import Substrate


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either lxd or microk8s",
        choices=("lxd", "microk8s"),
        default="lxd",
    )
    parser.addoption(
        "--mongodb-revision",
        action="store",
        help="MongoDB revision",
        default=1,
        type=int,
    )
    parser.addoption(
        "--mongos-revision",
        action="store",
        help="MongoDB revision",
        default=1,
        type=int,
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "skip_if_substrate(substrate): skip test for the given substrate"
    )


@pytest.fixture(scope="session")
def substrate(request) -> Substrate:
    """The substrate that we are testing."""
    return request.config.option.substrate


# To skip tests


@pytest.fixture(autouse=True)
def skip_for_substrate(request, substrate: Substrate):
    if mark := request.node.get_closest_marker("skip_if_substrate"):
        if mark.args[0] == substrate:
            pytest.skip(f"This test does not run on {substrate}")


@pytest.fixture
def mongod_base_path(substrate) -> Path:
    """The base path for the files of the mongodb charms, according to the substrate."""
    if substrate == "microk8s":
        return Path("tests/charms/mongodb_k8s_test_charm")
    return Path("tests/charms/mongodb_test_charm")


@pytest.fixture
def mongos_base_path(substrate) -> Path:
    """The base path for the files of the mongos charms, according to the substrate."""
    if substrate == "microk8s":
        return Path("tests/charms/mongos_k8s_test_charm")
    return Path("tests/charms/mongos_test_charm")
