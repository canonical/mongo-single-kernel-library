import pytest
from parameterized import parameterized

from single_kernel_mongo.config.literals import LOCALHOST, MongoPorts
from single_kernel_mongo.core.exceptions import AmbiguousConfigError
from single_kernel_mongo.utils.mongodb_users import (
    REGULAR_ROLES,
    RoleNames,
)

from .helpers import MongoConfigurationFactory


def test_configuration_ok():
    config = MongoConfigurationFactory.build()
    assert config.formatted_hosts == {"127.0.0.1:27017"}
    assert config.formatted_replset == {"replicaSet": "cafebabe"}
    assert config.formatted_auth_source == {"authSource": "admin"}

    assert config.uri == (
        "mongodb://operator:deadbeef@127.0.0.1:27017/abadcafe?replicaSet=cafebabe&authSource=admin"
    )

    assert config.supported_roles == []


@parameterized.expand([[RoleNames.ADMIN], [RoleNames.BACKUP], [RoleNames.MONITOR]])
def test_configuration_with_roles(role: RoleNames):
    config = MongoConfigurationFactory.build(roles={"default", role.value})

    roles = config.supported_roles
    expected_roles = [
        {"role": "readWrite", "db": config.database},
        {"role": "enableSharding", "db": config.database},
    ]
    expected_system_roles = REGULAR_ROLES[role]
    assert all(role in roles for role in expected_roles)
    assert all(role in roles for role in expected_system_roles)


def test_invalid_configuration_port_replset():
    config = MongoConfigurationFactory.build(port=MongoPorts.MONGOS_PORT, replset="cafebabe")

    with pytest.raises(AmbiguousConfigError):
        config.uri


def test_invalid_configuration_port_standalone():
    config = MongoConfigurationFactory.build(port=None, standalone=True)
    with pytest.raises(AmbiguousConfigError):
        config.uri


def test_valid_formatted():
    config = MongoConfigurationFactory.build(database="admin", replset=None, port=None)

    assert config.formatted_replset == {}
    assert config.formatted_auth_source == {}
    assert config.formatted_hosts == {LOCALHOST}


def test_standalone():
    config = MongoConfigurationFactory.build(standalone=True)
    assert config.uri == "mongodb://operator:deadbeef@localhost:27017/?authSource=admin"
