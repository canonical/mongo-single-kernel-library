from single_kernel_mongo.core.structured_config import (
    ExposeExternal,
    MongoDBCharmConfig,
    MongoDBRoles,
    MongosCharmConfig,
)


def test_invalid_mongodb_config():
    model = MongoDBCharmConfig.model_validate({"role": "wrong"})  # type: ignore
    assert model.role == MongoDBRoles.UNKNOWN


def test_invalid_mongos_config():
    model = MongosCharmConfig.model_validate({"expose-external": "invalid"})  # type: ignore
    assert model.expose_external == ExposeExternal.UNKNOWN


def test_valid_mongodb_config():
    MongoDBCharmConfig.model_validate({"role": "replication"})
    MongoDBCharmConfig.model_validate({"role": "shard"})
    MongoDBCharmConfig.model_validate({"role": "mongos"})
    MongoDBCharmConfig.model_validate({"role": "config-server"})

    MongosCharmConfig.model_validate({"expose-external": "none"})
    MongosCharmConfig.model_validate({"expose-external": "nodeport"})
