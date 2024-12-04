#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Structure configuration for the Mongo charms."""

from enum import Enum
from typing import Annotated, TypeVar

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

# Generic TypeVar for serializers
T = TypeVar("T")

# Serialize enums as their str
SerializeLiteralAsStr = Annotated[
    T,
    PlainSerializer(func=lambda v: str(v), return_type=str, when_used="always"),
]


class BaseConfigModel(BaseModel):
    """Class to be used for defining the structured configuration options."""

    def __getitem__(self, x):
        """Return the item using the notation instance[key]."""
        return getattr(self, x.replace("-", "_"))


# Useful enums
class MongoDBRoles(str, Enum):
    """The different accepted roles for a charm."""

    UNKNOWN = ""
    REPLICATION = "replication"
    CONFIG_SERVER = "config-server"
    SHARD = "shard"
    MONGOS = "mongos"


class ExposeExternal(str, Enum):
    """The possible values for the expose-external config value."""

    NODEPORT = "nodeport"
    NONE = "none"


# NewType for typing (ghost type)
class MongoConfigModel(BaseConfigModel):
    """Default class for typing."""

    expose_external: SerializeLiteralAsStr[ExposeExternal] = Field(
        default=ExposeExternal.NONE, alias="expose-external"
    )
    role: SerializeLiteralAsStr[MongoDBRoles]
    auto_delete: bool = Field(default=False, alias="auto-delete")


# The config for MongoDB Charms
class MongoDBCharmConfig(MongoConfigModel):
    """The structured configuration of a MongoDB charm."""

    model_config = ConfigDict(use_enum_values=True, extra="allow")

    role: SerializeLiteralAsStr[MongoDBRoles] = Field(default=MongoDBRoles.REPLICATION)


# The config for Mongos Charms (unused in case of mongos VM)
class MongosCharmConfig(MongoConfigModel):
    """The structured configuration of a Mongos charm."""

    model_config = ConfigDict(use_enum_values=True, extra="allow")

    role: SerializeLiteralAsStr[MongoDBRoles] = MongoDBRoles.MONGOS
