import logging

import mongomock
import pymongo
import pytest
from pymongo.errors import OperationFailure, WriteConcernError

from single_kernel_mongo.utils.mongo_connection import MongoConnection
from tests.unit.helpers import MongoConfigurationFactory


@pytest.fixture
@mongomock.patch(servers=(("servers.example.org", 27017),))
def mongo_connection():
    config = MongoConfigurationFactory.build()
    with MongoConnection(config) as mongo:
        mongo.client = pymongo.MongoClient("servers.example.org")
        return mongo


def test_is_ready(mongo_connection):
    assert mongo_connection.is_ready


def test_add_replset_member(mongo_connection, mocker):
    def mock_command(command, *args):
        if command == "replSetGetConfig":
            return {
                "config": {
                    "version": 1,
                    "members": [
                        {"_id": "1", "host": "host1:27017"},
                        {"_id": "2", "host": "host2:27017"},
                    ],
                }
            }
        if command == "replSetGetStatus":
            return {"members": [{"stateStr": "PRIMARY"}, {"stateStr": "SECONDARY"}]}
        if command == "replSetReconfig":
            new_config = args[0]
            assert new_config["version"] == 2
            assert len(new_config["members"]) == 2
            assert new_config["members"][0]["host"] == "host1.new-cluster:27017"
            assert new_config["members"][1]["host"] == "host2:27017"
            return {"1"}
        raise ValueError("Invalid call")

    mocker.patch.object(mongo_connection.client.admin, "command", new=mock_command)
    mongo_connection.add_replset_member("host1.new-cluster:27017")


def test_create_role_passes_privileges_list(mongo_connection, mocker):
    command = mocker.patch.object(mongo_connection.client.admin, "command")
    privilege = {"resource": {"cluster": True}, "actions": ["logRotate"]}
    mongo_connection.create_role("logRotate", [privilege])
    command.assert_called_once_with("createRole", "logRotate", privileges=[privilege], roles=[])


@pytest.mark.parametrize("roles, expected", [([{"role": "x"}], {"role": "x"}), ([], None)])
def test_get_role_found_and_absent(mongo_connection, mocker, roles, expected):
    command = mocker.patch.object(
        mongo_connection.client.admin, "command", return_value={"roles": roles}
    )
    assert mongo_connection.get_role("x") == expected
    command.assert_called_once_with("rolesInfo", {"role": "x", "db": "admin"}, showPrivileges=True)


def test_get_role_failure_is_logged_and_raised(mongo_connection, mocker, caplog):
    mocker.patch.object(
        mongo_connection.client.admin,
        "command",
        side_effect=OperationFailure("not authorized", code=13),
    )
    with pytest.raises(OperationFailure):
        mongo_connection.get_role("x")
    assert any(
        record.levelno == logging.ERROR and "Cannot check role x" in record.getMessage()
        for record in caplog.records
    )


def test_drop_role_calls_drop_role(mongo_connection, mocker):
    command = mocker.patch.object(mongo_connection.client.admin, "command")
    mongo_connection.drop_role("name")
    command.assert_called_once_with("dropRole", "name")


def test_drop_role_not_found_is_logged_not_raised(mongo_connection, mocker):
    mocker.patch.object(
        mongo_connection.client.admin, "command", side_effect=OperationFailure("nf", code=31)
    )
    mongo_connection.drop_role("name")


def test_drop_role_other_failure_raises(mongo_connection, mocker):
    mocker.patch.object(
        mongo_connection.client.admin, "command", side_effect=OperationFailure("bad", code=96)
    )
    with pytest.raises(OperationFailure):
        mongo_connection.drop_role("name")


def test_drop_role_write_concern_error_is_logged_not_raised(mongo_connection, mocker, caplog):
    # Applied on the primary, only the majority acknowledgement timed out: the role is gone.
    mocker.patch.object(
        mongo_connection.client.admin,
        "command",
        side_effect=WriteConcernError("wtimeout", code=64),
    )
    mongo_connection.drop_role("name")
    assert any(
        record.levelno == logging.WARNING
        and "Role name was dropped with a write concern error" in record.getMessage()
        for record in caplog.records
    )
