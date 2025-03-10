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
        help="Substrate to test, either lxd or microk8s",
        choices=("lxd", "microk8s"),
    )


@pytest.fixture(autouse=True)
def substrate(request):
    return request.config.option.substrate


@pytest.fixture
def mongodb_charm(substrate) -> str:
    if substrate == "microk8s":
        return "./test-mongodb-k8s_ubuntu@22.04-amd64.charm"
    return "./test-mongodb_ubuntu@22.04-amd64.charm"


@pytest.fixture
def mongos_charm(substrate) -> str:
    if substrate == "microk8s":
        return "./test-mongos-k8s_ubuntu@22.04-amd64.charm"
    return "./test-mongos_ubuntu@22.04-amd64.charm"


@pytest.fixture
def mongod_base_path(substrate) -> Path:
    if substrate == "microk8s":
        return Path("tests/charms/mongodb_k8s_test_charm")
    return Path("tests/charms/mongodb_test_charm")


@pytest.fixture
def mongos_base_path(substrate) -> Path:
    if substrate == "microk8s":
        return Path("tests/charms/mongos_k8s_test_charm")
    return Path("tests/charms/mongos_test_charm")


@pytest.fixture
def mongod_metadata(mongod_base_path):
    with open(mongod_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongod_resource(mongod_metadata, substrate):
    if substrate == "microk8s":
        return {"mongodb-image": mongod_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}


@pytest.fixture
def mongos_metadata(mongos_base_path):
    with open(mongos_base_path / "metadata.yaml") as fd:
        return safe_load(fd)


@pytest.fixture
def mongos_resource(mongos_metadata):
    if substrate == "microk8s":
        return {"mongodb-image": mongos_metadata["resources"]["mongodb-image"]["upstream-source"]}
    return {}
