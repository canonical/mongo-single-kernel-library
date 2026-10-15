import mongomock
import pymongo
import pytest

from single_kernel_mongo.utils.mongo_connection import MongoConnection

from .helpers import MongoConfigurationFactory


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
