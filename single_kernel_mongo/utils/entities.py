# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Parsing of mongodb_client entity requests (GROUP roles).

A requester may send `entity-type`, `extra-group-roles`, `entity-permissions` and a
`requested-entity-secret` over the `database` / `mongos_proxy` relation. A VM mongos
forwards the same request to its config-server over the `cluster` relation under
charm-owned `client-*` keys, see the design spec, section 5.3.
"""

from __future__ import annotations

import json
from typing import Any

from ops.model import Model, ModelError, Relation, SecretNotFoundError
from pydantic import (
    BaseModel,
    ConfigDict,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.exceptions import EntityRequestError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.utils.mongo_config import roles_for
from single_kernel_mongo.utils.mongodb_users import REGULAR_ROLES, DBPrivilege, RoleNames

ENTITY_TYPE_GROUP = "GROUP"
RESOURCE_TYPES = ("db", "collection", "cluster", "anyResource")
VALID_GROUP_ROLES = {role.value for role in REGULAR_ROLES} | {RoleNames.DEFAULT.value}

# Keys as the data_interfaces library writes them on a client relation.
CLIENT_FIELD_NAMES = {
    "entity-type": "entity-type",
    "extra-group-roles": "extra-group-roles",
    "entity-permissions": "entity-permissions",
    "entity-name": "requested-entity-secret",
}
# Keys a VM mongos writes on the cluster relation; the library ignores them.
CLUSTER_FIELD_NAMES = {
    "entity-type": "client-entity-type",
    "extra-group-roles": "client-extra-group-roles",
    "entity-permissions": "client-entity-permissions",
    "entity-name": "client-entity-name",
}


def entity_field_names(relation: Relation) -> dict[str, str]:
    """The databag keys carrying the entity request on this relation."""
    if relation.name == RelationNames.CLUSTER.value:
        return CLUSTER_FIELD_NAMES
    return CLIENT_FIELD_NAMES


class EntityPermission(BaseModel):
    """One item of `entity-permissions`, in MongoDB vocabulary."""

    model_config = ConfigDict(extra="forbid")

    resource_name: str
    resource_type: str
    privileges: list[str]

    @field_validator("resource_type")
    @classmethod
    def _known_resource_type(cls, value: str) -> str:
        if value not in RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {', '.join(RESOURCE_TYPES)}")
        return value

    @field_validator("privileges")
    @classmethod
    def _non_empty_privileges(cls, value: list[str]) -> list[str]:
        if not value or any(not action for action in value):
            raise ValueError("privileges must be a non-empty list of MongoDB actions")
        return value

    @model_validator(mode="after")
    def _collection_is_namespaced(self) -> Self:
        if self.resource_type == "collection" and "." not in self.resource_name:
            raise ValueError("a collection resource_name must be <db>.<collection>")
        return self

    def to_mongodb(self) -> dict[str, Any]:
        """The MongoDB privilege document for this permission."""
        match self.resource_type:
            case "db":
                resource: dict[str, Any] = {"db": self.resource_name, "collection": ""}
            case "collection":
                db, _, collection = self.resource_name.partition(".")
                resource = {"db": db, "collection": collection}
            case "cluster":
                resource = {"cluster": True}
            case "anyResource":
                resource = {"anyResource": True}
            case _:
                raise ValueError(f"unknown resource_type {self.resource_type!r}")
        return {"resource": resource, "actions": list(self.privileges)}


_PERMISSIONS_ADAPTER = TypeAdapter(list[EntityPermission])


class EntityRequest(BaseModel):
    """A validated GROUP request."""

    database: str
    name: str
    extra_group_roles: set[str]
    permissions: list[EntityPermission]

    def roles(self) -> list[DBPrivilege]:
        """MongoDB roles the new role inherits from."""
        return roles_for(self.database, self.extra_group_roles)

    def privileges(self) -> list[dict[str, Any]]:
        """MongoDB privilege documents for the new role."""
        return [permission.to_mongodb() for permission in self.permissions]


def requested_entity_name_from_secret(model: Model, secret_id: str) -> str:
    """Reads the requested entity name from the requester's `requested-entity-secret`.

    Raises:
        EntityRequestError: if the secret cannot be read or carries no usable entity-name.
    """
    if not secret_id:
        raise EntityRequestError("requested-entity-secret is empty")
    try:
        content = model.get_secret(id=secret_id).get_content(refresh=True)
    except (SecretNotFoundError, ModelError) as e:
        raise EntityRequestError("cannot read requested-entity-secret") from e
    if "entity-name" not in content:
        raise EntityRequestError("requested-entity-secret has no entity-name key")
    if not (name := content["entity-name"]):
        raise EntityRequestError("entity-name is empty")
    return name


def _parse_group_roles(raw: str | None) -> set[str]:
    roles = {role.strip() for role in (raw or RoleNames.DEFAULT.value).split(",")}
    if "" in roles:
        raise EntityRequestError("extra-group-roles contains an empty value")
    if unknown := roles - VALID_GROUP_ROLES:
        names = ", ".join(repr(role) for role in sorted(unknown))
        raise EntityRequestError(f"unknown extra-group-roles value(s) {names}")
    return roles


def _parse_permissions(raw: str | None) -> list[EntityPermission]:
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as e:
        raise EntityRequestError(f"entity-permissions is not valid JSON: {e.msg}") from e
    if not isinstance(items, list):
        raise EntityRequestError("entity-permissions must be a JSON list")
    try:
        return _PERMISSIONS_ADAPTER.validate_python(items)
    except ValidationError as e:
        first = e.errors()[0]
        # loc starts with the item index: (0,), (0, "privileges"), (0, "privileges", 1).
        where = "".join(
            f"[{part}]" if isinstance(part, int) else f".{part}" for part in first["loc"]
        )
        msg = first["msg"].removeprefix("Value error, ")
        raise EntityRequestError(f"invalid entity-permissions{where}: {msg}") from e


def _requested_name(model: Model, data_interface: DatabaseProviderData, relation: Relation) -> str:
    key = entity_field_names(relation)["entity-name"]
    value = data_interface.fetch_relation_field(relation.id, key)
    if value is None:
        return f"relation-{relation.id}"
    if relation.name != RelationNames.CLUSTER.value:
        return requested_entity_name_from_secret(model, value)
    if not value:
        raise EntityRequestError("entity-name is empty")
    return value


def parse_entity_request(
    model: Model,
    data_interface: DatabaseProviderData,
    relation: Relation,
    name: str | None = None,
) -> EntityRequest:
    """Reads and validates the GROUP request carried by the relation.

    Args:
        model: the charm model, to read the requester's `requested-entity-secret`.
        data_interface: the provider data interface of the relation.
        relation: the relation carrying the request.
        name: the role name already read for this relation, if any. It is used as is,
            without reading the secret, which the requester removes once the role exists.

    Raises:
        EntityRequestError: with a reason suitable for a relation status message.
    """
    names = entity_field_names(relation)
    entity_type = data_interface.fetch_relation_field(relation.id, names["entity-type"])
    if entity_type != ENTITY_TYPE_GROUP:
        raise EntityRequestError(f"entity-type {entity_type!r} is not supported, only GROUP")
    database = data_interface.fetch_relation_field(relation.id, "database")
    if not database:
        raise EntityRequestError("database is missing")
    return EntityRequest(
        database=database,
        name=name if name is not None else _requested_name(model, data_interface, relation),
        extra_group_roles=_parse_group_roles(
            data_interface.fetch_relation_field(relation.id, names["extra-group-roles"])
        ),
        permissions=_parse_permissions(
            data_interface.fetch_relation_field(relation.id, names["entity-permissions"])
        ),
    )
