import mongomock
import pymongo
import pytest
from pymongo.errors import OperationFailure

from single_kernel_mongo.utils.mongo_connection import MongoConnection
from single_kernel_mongo.utils.mongo_error_codes import MongoErrorCodes
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


def test_create_role_passes_privileges_and_roles(mongo_connection, mocker):
    command = mocker.patch.object(mongo_connection.client.admin, "command")
    privileges = [{"resource": {"db": "superdb", "collection": ""}, "actions": ["find"]}]
    roles = [{"role": "readWrite", "db": "superdb"}]

    mongo_connection.create_role("ou=dba,dc=glauth,dc=com", privileges, roles)

    command.assert_called_once_with(
        "createRole", "ou=dba,dc=glauth,dc=com", privileges=privileges, roles=roles
    )


def test_create_role_exist_ok_swallows_already_exists(mongo_connection, mocker):
    command = mocker.patch.object(
        mongo_connection.client.admin,
        "command",
        side_effect=OperationFailure("exists", code=MongoErrorCodes.ROLE_ALREADY_EXISTS),
    )

    mongo_connection.create_role("explainRole", [{"resource": {"cluster": True}, "actions": []}])

    command.assert_called_once()


def test_create_role_not_exist_ok_raises_already_exists(mongo_connection, mocker):
    mocker.patch.object(
        mongo_connection.client.admin,
        "command",
        side_effect=OperationFailure("exists", code=MongoErrorCodes.ROLE_ALREADY_EXISTS),
    )

    with pytest.raises(OperationFailure):
        mongo_connection.create_role("relation-7", [], [], exist_ok=False)


def test_drop_role(mongo_connection, mocker):
    command = mocker.patch.object(mongo_connection.client.admin, "command")

    mongo_connection.drop_role("relation-7")

    command.assert_called_once_with("dropRole", "relation-7")
