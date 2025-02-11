from single_kernel_mongo.core.structured_config import (
    ExposeExternal,
    MongoDBCharmConfig,
    MongoDBRoles,
    MongosCharmConfig,
)


def test_invalid_mongodb_config():
    model = MongoDBCharmConfig.model_validate({"role": "wrong", "auto_delete": True})  # type: ignore
    assert model.role == MongoDBRoles.UNKNOWN


def test_invalid_mongos_config():
    model = MongosCharmConfig.model_validate({"expose-external": "invalid"})  # type: ignore
    assert model.expose_external == ExposeExternal.UNKNOWN


def test_valid_mongodb_config():
    MongoDBCharmConfig.model_validate({"role": "replication", "auto-delete": True})
    MongoDBCharmConfig.model_validate({"role": "replication", "auto-delete": False})
    MongoDBCharmConfig.model_validate({"role": "shard", "auto-delete": False})
    MongoDBCharmConfig.model_validate({"role": "mongos", "auto-delete": False})
    MongoDBCharmConfig.model_validate({"role": "config-server", "auto-delete": False})

    MongosCharmConfig.model_validate({"expose-external": "none", "auto-delete": False})
    MongosCharmConfig.model_validate({"expose-external": "nodeport", "auto-delete": False})
    MongosCharmConfig.model_validate({"expose-external": "none", "auto-delete": True})
    MongosCharmConfig.model_validate({"expose-external": "nodeport", "auto-delete": False})
