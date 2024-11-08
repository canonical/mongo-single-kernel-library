import pytest
from pydantic import ValidationError

from single_kernel_mongo.core.structured_config import (
    MongoDBCharmConfig,
    MongoDBRoles,
    MongosCharmConfig,
)


def test_invalid_mongodb_config():
    with pytest.raises(ValidationError):
        MongoDBCharmConfig(role="wrong", auto_delete=True)  # type: ignore

    with pytest.raises(ValidationError):
        # Non existing config should not be set
        MongoDBCharmConfig(role=MongoDBRoles.REPLICATION, invalid=True)  # type: ignore


def test_invalid_mongos_config():
    with pytest.raises(ValidationError):
        MongosCharmConfig(expose_external="invalid")  # type: ignore

    with pytest.raises(ValidationError):
        # Non existing config should not be set
        MongosCharmConfig(expose_external="none", invalid=True)  # type: ignore


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
