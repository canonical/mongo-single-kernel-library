# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer relation databag."""

import json
from enum import Enum

from ops.model import Application, Model, Relation
from typing_extensions import override

from single_kernel_mongo.config.literals import SECRETS_APP, Substrates
from single_kernel_mongo.core.structured_config import ExposeExternal, MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class AppPeerDataKeys(str, Enum):
    """Enum to access the app peer data keys."""

    # MongoDB
    MANAGED_USERS_KEY = "managed-users-key"
    DB_INITIALISED = "db_initialised"
    KEYFILE = "keyfile"
    EXTERNAL_CONNECTIVITY = "external-connectivity"
    MONGOS_HOSTS = "mongos_hosts"

    # Shared
    ROLE = "role"

    # Mongos
    DATABASE = "database"
    EXTRA_USER_ROLES = "extra-user-roles"
    EXPOSE_EXTERNAL = "expose-external"
    USERNAME = "username"
    PASSWORD = "password"


class AppPeerReplicaSet(AbstractRelationState[DataPeerData]):
    """State collection for replicaset relation."""

    component: Application

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        substrate: Substrates,
        model: Model,
    ):
        super().__init__(relation, data_interface, component, substrate=substrate)
        self.data_interface = data_interface
        self._model = model

    @override
    def update(self, items: dict[str, str | None]) -> None:
        """Overridden update to allow for same interface, but writing to local app bag."""
        if not self.relation:
            return

        for key, value in items.items():
            # note: relation- check accounts for dynamically created secrets
            if key in SECRETS_APP or key.startswith("relation-"):
                if value:
                    self.data_interface.set_secret(self.relation.id, key, value)
                else:
                    self.data_interface.delete_secret(self.relation.id, key)
            else:
                self.data_interface.update_relation_data(self.relation.id, {key: value})

    @property
    def role(self) -> MongoDBRoles:
        """The role.

        Either from the app databag or unknown.
        """
        if (
            not (databag_role := self.relation_data.get(AppPeerDataKeys.ROLE.value))
            or not self.relation
        ):
            return MongoDBRoles.UNKNOWN
        return MongoDBRoles(databag_role)

    @role.setter
    def role(self, value: MongoDBRoles) -> None:
        self.update({"role": f"{value}"})

    def is_role(self, role_name: str) -> bool:
        """Checks if the application is running in the provided role."""
        return self.role == role_name

    @property
    def db_initialised(self) -> bool:
        """Whether the db is initialised or not yet."""
        if not self.relation:
            return False
        return json.loads(self.relation_data.get(AppPeerDataKeys.DB_INITIALISED.value, "false"))

    @db_initialised.setter
    def db_initialised(self, value: bool):
        if isinstance(value, bool):
            self.update({AppPeerDataKeys.DB_INITIALISED.value: json.dumps(value)})
        else:
            raise ValueError(
                f"'db_initialised' must be a boolean value. Provided: {value} is of type {type(value)}"
            )

    @property
    def managed_users(self) -> set[str]:
        """Returns the stored set of managed-users."""
        if not self.relation:
            return set()

        return set(
            json.loads(self.relation_data.get(AppPeerDataKeys.MANAGED_USERS_KEY.value, "[]"))
        )

    @managed_users.setter
    def managed_users(self, value: set[str]) -> None:
        """Stores the managed users set."""
        self.update({AppPeerDataKeys.MANAGED_USERS_KEY.value: json.dumps(sorted(value))})

    @property
    def mongos_hosts(self) -> list[str]:
        """Gets the mongos hosts from the databag."""
        if not self.relation:
            return []

        return json.loads(self.relation_data.get(AppPeerDataKeys.MONGOS_HOSTS.value, "[]"))

    @mongos_hosts.setter
    def mongos_hosts(self, value: list[str]):
        """Stores the mongos hosts in the databag."""
        self.update({AppPeerDataKeys.MONGOS_HOSTS.value: json.dumps(sorted(value))})

    def set_user_created(self, user: str):
        """Stores the flag stating if user was created."""
        self.update({f"{user}-user-created": json.dumps(True)})

    def is_user_created(self, user: str) -> bool:
        """Has the user already been created?"""
        return json.loads(self.relation_data.get(f"{user}-user-created", "false"))

    @property
    def replica_set(self) -> str:
        """The replica set name."""
        return self.component.name

    @property
    def external_connectivity(self) -> bool:
        """Is the external connectivity tag in the databag?"""
        return json.loads(
            self.relation_data.get(AppPeerDataKeys.EXTERNAL_CONNECTIVITY.value, "false")
        )

    @external_connectivity.setter
    def external_connectivity(self, value: bool) -> None:
        if isinstance(value, bool):
            self.update({AppPeerDataKeys.EXTERNAL_CONNECTIVITY.value: json.dumps(value)})
        else:
            raise ValueError(
                f"'external-connectivity' must be a boolean value. Provided: {value} is of type {type(value)}"
            )

    @property
    def database(self) -> str:
        """Database tag for mongos."""
        if self.substrate == Substrates.K8S:
            return f"{self.component.name}_{self._model.name}"
        return self.relation_data.get(AppPeerDataKeys.DATABASE.value, "")

    @database.setter
    def database(self, value: str):
        """Sets database tag in databag."""
        self.update({AppPeerDataKeys.DATABASE.value: value})

    @property
    def extra_user_roles(self) -> set[str]:
        """extra_user_roles tag for mongos."""
        if self.substrate == Substrates.K8S:
            return {"admin"}
        return set(
            self.relation_data.get(
                AppPeerDataKeys.EXTRA_USER_ROLES.value,
                "default",
            ).split(",")
        )

    @extra_user_roles.setter
    def extra_user_roles(self, value: set[str]):
        """Sets extra_user_roles tag in databag."""
        roles_str = ",".join(value)
        self.update({AppPeerDataKeys.EXTRA_USER_ROLES.value: roles_str})

    @property
    def expose_external(self) -> ExposeExternal:
        """The value of the expose-external flag."""
        if not self.relation:
            return ExposeExternal.UNKNOWN
        return ExposeExternal(self.relation_data.get(AppPeerDataKeys.EXPOSE_EXTERNAL.value, ""))

    @expose_external.setter
    def expose_external(self, value: ExposeExternal):
        self.update({AppPeerDataKeys.EXPOSE_EXTERNAL.value: f"{value}"})
