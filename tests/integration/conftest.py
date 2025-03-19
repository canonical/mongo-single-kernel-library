# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

from logging import getLogger
from pathlib import Path
from typing import Any

import pytest
from _pytest.config.argparsing import Parser
from yaml import safe_load

logger = getLogger(__name__)


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either lxd or microk8s",
        choices=("lxd", "microk8s"),
    )


@pytest.fixture(autouse=True)
def substrate(request):
    """The substrate that we are testing."""
    return request.config.option.substrate


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


@pytest.fixture
def mongodb_charm(substrate, mongod_base_path) -> str:
    """The MongoDB charm path, to deploy charms, according to the substrate."""
    if substrate == "microk8s":
        return f"./{mongod_base_path}/test-mongodb-k8s_ubuntu@22.04-amd64.charm"
    return f"./{mongod_base_path}/test-mongodb_ubuntu@22.04-amd64.charm"


@pytest.fixture
def mongos_charm(substrate, mongos_base_path) -> str:
    """The Mongos charm path, to deploy charms, according to the substrate."""
    if substrate == "microk8s":
        return f"./{mongos_base_path}/test-mongos-k8s_ubuntu@22.04-amd64.charm"
    return f"./{mongos_base_path}/test-mongos_ubuntu@22.04-amd64.charm"


@pytest.fixture
def mongod_metadata(mongod_base_path) -> dict[str, Any]:
    """The MongoDB charm metadata."""
    with open(mongod_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongod_resource(mongod_metadata, substrate) -> dict[str, Any]:
    """The MongoDB charm resources for k8s charms."""
    if substrate == "microk8s":
        return {"mongodb-image": mongod_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}


@pytest.fixture
def mongos_metadata(mongos_base_path) -> dict[str, Any]:
    """The Mongos charm metadata."""
    with open(mongos_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongos_resource(mongos_metadata) -> dict[str, Any]:
    """The Mongos charm resources for k8s charms."""
    if substrate == "microk8s":
        return {"mongodb-image": mongos_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}
