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
