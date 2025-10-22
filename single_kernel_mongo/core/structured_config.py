#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Structured classes for the available configurations for Mongo charms.

Modifiable configurations should be defined in `config.yaml` in each charm.
"""

from enum import Enum
from typing import Annotated, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    TypeAdapter,
    field_validator,
    model_validator,
)
from typing_extensions import Self

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
    INVALID = "invalid"
    REPLICATION = "replication"
    CONFIG_SERVER = "config-server"
    SHARD = "shard"
    MONGOS = "mongos"

    @classmethod
    def valid_roles(cls) -> set[str]:
        """The valid roles for mongodb."""
        return {cls.REPLICATION, cls.CONFIG_SERVER, cls.SHARD}


class ExposeExternal(str, Enum):
    """The possible values for the expose-external config value."""

    UNKNOWN = ""
    NODEPORT = "nodeport"
    NONE = "none"

    @classmethod
    def valid_roles(cls) -> set[str]:
        """The valid roles for expose external.

        This is exposed as config on k8s routers only.
        """
        return {cls.NODEPORT, cls.NONE}


class SingleLdapUserToDnMapping(BaseModel):
    """Validating the Mapping structure."""

    match: str
    substitution: str | None = None
    ldap_query: str | None = Field(default=None, alias="ldapQuery")  # noqa: N815

    @model_validator(mode="after")
    def verify_subst_or_ldapquery(self) -> Self:
        """Ensures that only one of substitution or ldapQuery is present."""
        if self.substitution and self.ldap_query or (not self.substitution and not self.ldap_query):
            raise ValueError("substitution and ldapQuery are mutually exclusive")
        return self


LdapUserToDnMapping = TypeAdapter(list[SingleLdapUserToDnMapping])


# NewType for typing (ghost type)
class MongoConfigModel(BaseConfigModel):
    """Default class for typing."""

    expose_external: SerializeLiteralAsStr[ExposeExternal] = Field(
        default=ExposeExternal.NONE, alias="expose-external"
    )
    role: SerializeLiteralAsStr[MongoDBRoles]
    auto_delete: bool = Field(default=False, alias="auto-delete")
    ldap_user_to_dn_mapping: str | None = Field(default=None, alias="ldap-user-to-dn-mapping")
    ldap_query_template: str | None = Field(default=None, alias="ldap-query-template")

    @field_validator("expose_external", mode="before")
    @classmethod
    def invalid_expose_to_unknown(cls, v: str) -> ExposeExternal:
        """If the value is neither none or nodeport, returns unknown."""
        if v not in ExposeExternal.valid_roles():
            return ExposeExternal.UNKNOWN
        return ExposeExternal(v)


# The config for MongoDB Charms
class MongoDBCharmConfig(MongoConfigModel):
    """The structured configuration of a MongoDB charm."""

    model_config = ConfigDict(use_enum_values=True, extra="allow")

    role: SerializeLiteralAsStr[MongoDBRoles] = Field(default=MongoDBRoles.REPLICATION)

    @field_validator("role", mode="before")
    @classmethod
    def invalid_role_to_invalid(cls, v: str) -> MongoDBRoles:
        """If the value is neither replication, config-server, or shard, returns invalid."""
        if v not in MongoDBRoles.valid_roles():
            return MongoDBRoles.INVALID
        return MongoDBRoles(v)


# The config for Mongos Charms (unused in case of mongos VM)
class MongosCharmConfig(MongoConfigModel):
    """The structured configuration of a Mongos charm."""

    model_config = ConfigDict(use_enum_values=True, extra="allow")

    role: SerializeLiteralAsStr[MongoDBRoles] = Field(default=MongoDBRoles.MONGOS)
