#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Structure configuration for the Mongo charms."""

from enum import Enum
from typing import Annotated, TypeVar

from pydantic import ConfigDict, Field, PlainSerializer

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_models import (
    BaseConfigModel,
)

# Generic TypeVar for serializers
T = TypeVar("T")

# Serialize enums as their str
SerializeLiteralAsStr = Annotated[
    T,
    PlainSerializer(func=lambda v: str(v), return_type=str, when_used="always"),
]


# Useful enums
class MongoDBRoles(str, Enum):
    """The different accepted roles for a charm."""

    REPLICATION = "replication"
    CONFIG_SERVER = "config-server"
    SHARD = "shard"
    MONGOS = "mongos"


class ExposeExternalEnum(str, Enum):
    """The possible values for the expose-external config value."""

    NODEPORT = "nodeport"
    NONE = "none"


# NewType for typing (ghost type)
class MongoConfigModel(BaseConfigModel):
    """Default class for typing."""

    ...


# The config for MongoDB Charms
class MongoDBCharmConfig(MongoConfigModel):
    """The structured configuration of a MongoDB charm."""

    model_config = ConfigDict(use_enum_values=True)

    role: SerializeLiteralAsStr[MongoDBRoles] = Field(default=MongoDBRoles.REPLICATION)
    auto_delete: bool = Field(default=False)


# The config for Mongos Charms (unused in case of mongos VM)
class MongosCharmConfig(MongoConfigModel):
    """The structured configuration of a Mongos charm."""

    model_config = ConfigDict(use_enum_values=True)

    expose_external: SerializeLiteralAsStr[ExposeExternalEnum] = Field(
        default=ExposeExternalEnum.NONE
    )
    auto_delete: bool = Field(default=False)
