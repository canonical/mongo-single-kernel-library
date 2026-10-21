# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The entity request state: a GROUP role requested over a mongodb_client relation.

A requester sends `entity-type`, `extra-group-roles`, `entity-permissions` and, optionally,
a `requested-entity-secret` carrying the entity name. A VM mongos forwards the same request
to its config-server over the `cluster` relation, under the same keys.
"""

import json
from enum import Enum
from typing import Any

from ops.model import Application, Model, ModelError, Relation, SecretNotFoundError

from single_kernel_mongo.config.literals import InternalUsernames
from single_kernel_mongo.exceptions import InvalidEntityRequestError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState
from single_kernel_mongo.utils.mongodb_users import (
    INTERNAL_ROLE_NAMES,
    REGULAR_ROLES,
    RoleNames,
    RolePrivilege,
)


class EntityStateKeys(str, Enum):
    """Entity request keys of a mongodb_client relation."""

    DATABASE = "database"
    ENTITY_TYPE = "entity-type"
    EXTRA_GROUP_ROLES = "extra-group-roles"
    ENTITY_PERMISSIONS = "entity-permissions"
    REQUESTED_ENTITY_SECRET = "requested-entity-secret"
    ENTITY_NAME = "entity-name"


ENTITY_TYPE_GROUP = "GROUP"
RESOURCE_TYPES = ("db", "collection", "cluster", "anyResource")
VALID_GROUP_ROLES = {role.value for role in REGULAR_ROLES} | {RoleNames.DEFAULT.value}
RESERVED_ENTITY_PREFIX = "charmed-"
RESERVED_ENTITY_NAMES = frozenset(user.value for user in InternalUsernames) | INTERNAL_ROLE_NAMES


def _to_privilege(index: int, item: Any) -> RolePrivilege:
    """Checks one `entity-permissions` item and translates it into a MongoDB privilege.

    Raises:
        InvalidEntityRequestError: if the item is not a valid permission.
    """
    prefix = f"invalid entity-permissions[{index}]: "
    if not isinstance(item, dict) or set(item) != {"resource_name", "resource_type", "privileges"}:
        raise InvalidEntityRequestError(
            prefix + "expected the keys resource_name, resource_type, privileges"
        )
    resource_name, resource_type = item["resource_name"], item["resource_type"]
    privileges = item["privileges"]
    if resource_type not in RESOURCE_TYPES:
        raise InvalidEntityRequestError(
            prefix + f"resource_type must be one of {', '.join(RESOURCE_TYPES)}"
        )
    if not isinstance(resource_name, str):
        raise InvalidEntityRequestError(prefix + "resource_name must be a string")
    if (
        not isinstance(privileges, list)
        or not privileges
        or not all(isinstance(action, str) and action for action in privileges)
    ):
        raise InvalidEntityRequestError(
            prefix + "privileges must be a non-empty list of MongoDB actions"
        )

    resource: dict[str, Any]
    match resource_type:
        case "db":
            resource = {"db": resource_name, "collection": ""}
        case "collection":
            db, _, collection = resource_name.partition(".")
            if not db or not collection:
                raise InvalidEntityRequestError(
                    prefix + "a collection resource_name must be <db>.<collection>"
                )
            resource = {"db": db, "collection": collection}
        case "cluster":
            resource = {"cluster": True}
        case _:  # "anyResource", the last of RESOURCE_TYPES
            resource = {"anyResource": True}
    return RolePrivilege(resource=resource, actions=list(privileges))


class EntityState(AbstractRelationState[DatabaseProviderData]):
    """The provider's view of the entity request of one relation."""

    component: Application

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DatabaseProviderData,
        component: Application,
        model: Model,
        forwarded: bool = False,
    ):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.model = model
        self.forwarded = forwarded

    def field(self, key: EntityStateKeys) -> str:
        """The raw value of an entity request key, "" when unset."""
        return self.relation_data.get(key.value, "")

    @property
    def requested(self) -> bool:
        """Whether the relation requests an entity."""
        return bool(self.field(EntityStateKeys.ENTITY_TYPE))

    @property
    def entity_type(self) -> str:
        """The requested entity type, "" when no entity is requested."""
        return self.field(EntityStateKeys.ENTITY_TYPE)

    @property
    def database(self) -> str:
        """The database requested on the relation."""
        return self.field(EntityStateKeys.DATABASE)

    @property
    def extra_group_roles(self) -> set[str]:
        """The charm roles the entity role inherits from, `default` when none are requested.

        Raises:
            InvalidEntityRequestError: if a value is empty or is not a charm role.
        """
        raw = self.field(EntityStateKeys.EXTRA_GROUP_ROLES)
        if not raw:
            return {RoleNames.DEFAULT.value}
        roles = [role.strip() for role in raw.split(",")]
        if "" in roles:
            raise InvalidEntityRequestError("extra-group-roles contains an empty value")
        for role in roles:
            if role not in VALID_GROUP_ROLES:
                raise InvalidEntityRequestError(f"unknown extra-group-roles value '{role}'")
        return set(roles)

    @property
    def permissions(self) -> list[RolePrivilege]:
        """The MongoDB privileges translated from `entity-permissions`, [] when none.

        Raises:
            InvalidEntityRequestError: if `entity-permissions` is not a valid list of permissions.
        """
        raw = self.field(EntityStateKeys.ENTITY_PERMISSIONS)
        if not raw:
            return []
        try:
            items = json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidEntityRequestError("entity-permissions is not valid JSON") from e
        if not isinstance(items, list):
            raise InvalidEntityRequestError("entity-permissions must be a JSON list")
        return [_to_privilege(index, item) for index, item in enumerate(items)]

    @property
    def requested_name(self) -> str:
        """The entity name the requester asked for.

        The relation carries it in the `entity-name` key of its `requested-entity-secret` and
        defaults to `relation-<id>` without one. A VM mongos shares the name of its client in
        a secret of its own.

        Raises:
            InvalidEntityRequestError: if the name cannot be read or is empty.
        """
        if self.relation is None:
            return ""
        secret_id = self.field(EntityStateKeys.REQUESTED_ENTITY_SECRET)
        if not secret_id:
            return f"relation-{self.relation.id}"
        try:
            content = self.model.get_secret(id=secret_id).get_content(refresh=True)
        except (SecretNotFoundError, ModelError) as e:
            raise InvalidEntityRequestError("cannot read requested-entity-secret") from e
        if EntityStateKeys.ENTITY_NAME.value not in content:
            raise InvalidEntityRequestError("requested-entity-secret has no entity-name key")
        if not (name := content[EntityStateKeys.ENTITY_NAME.value]):
            raise InvalidEntityRequestError("entity-name is empty")
        return name

    @property
    def entity_name(self) -> str:
        """The entity name this provider published, "" until the entity is created.

        Read from the own side only: a requester cannot set it.
        """
        return self.get(EntityStateKeys.ENTITY_NAME.value)

    @entity_name.setter
    def entity_name(self, value: str) -> None:
        """Publishes the name of the created entity."""
        self.update({EntityStateKeys.ENTITY_NAME.value: value})

    @property
    def name(self) -> str:
        """The entity name: the published one once created, else the requested one.

        A forwarded request always carries its name, which the mongos replaces when its
        client asks for another one: the requested name wins there.

        Raises:
            InvalidEntityRequestError: if there is no published name and the requested name
                cannot be read.
        """
        if self.forwarded:
            return self.requested_name
        return self.entity_name or self.requested_name

    def validate(self) -> None:
        """Checks the entity request.

        Raises:
            InvalidEntityRequestError: with the reason of the first rule the request breaks.
        """
        entity_type = self.entity_type
        if entity_type != ENTITY_TYPE_GROUP:
            raise InvalidEntityRequestError(
                f"entity-type '{entity_type}' is not supported, only {ENTITY_TYPE_GROUP}"
            )
        if not self.database:
            raise InvalidEntityRequestError("database is missing")
        # Both properties raise on an invalid value: reading them is the check.
        _ = self.extra_group_roles
        _ = self.permissions
        # `requested_name` raises on an empty name; no relation already failed the type check.
        name = self.name
        if name in RESERVED_ENTITY_NAMES or name.startswith(RESERVED_ENTITY_PREFIX):
            raise InvalidEntityRequestError(f"entity-name '{name}' is reserved")
