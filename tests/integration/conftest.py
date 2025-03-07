from logging import getLogger
from pathlib import Path

import pytest
from _pytest.config.argparsing import Parser
from yaml import safe_load

logger = getLogger(__name__)


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--substrate",
        action="store",
        help="Substrate to test, either vm or k8s",
        choices=("vm", "k8s"),
    )


@pytest.fixture(autouse=True)
def substrate(request):
    return request.config.options.substrate


@pytest.fixture
def mongodb_charm(substrate) -> Path:
    if substrate == "k8s":
        return Path("test-mongodb-k8s_ubuntu-22.04-amd64.charm")
    return Path("test-mongodb_ubuntu-22.04-amd64.charm")


@pytest.fixture
def mongos_charm(substrate) -> Path:
    if substrate == "k8s":
        return Path("test-mongos-k8s_ubuntu-22.04-amd64.charm")
    return Path("test-mongos_ubuntu-22.04-amd64.charm")


@pytest.fixture
def mongod_base_path(substrate) -> Path:
    if substrate == "k8s":
        return Path("tests/charms/mongodb_k8s_test_charm")
    return Path("tests/charms/mongodb_test_charm")


@pytest.fixture
def mongos_base_path(substrate) -> Path:
    if substrate == "k8s":
        return Path("tests/charms/mongos_k8s_test_charm")
    return Path("tests/charms/mongos_test_charm")


@pytest.fixture
def mongod_metadata(mongod_base_path):
    with open(mongod_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongod_resource(mongod_metadata):
    return {"mongodb-image": mongod_metadata["resources"]["mongodb-image"]["upstream-source"]}


@pytest.fixture
def mongos_metadata(mongos_base_path):
    with open(mongos_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongos_resource(mongos_metadata):
    return {"mongodb-image": mongos_metadata["resources"]["mongodb-image"]["upstream-source"]}
