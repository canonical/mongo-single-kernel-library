# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer relation databag."""

import json
from enum import Enum

from ops.model import Application, Relation
from typing_extensions import override

from single_kernel_mongo.config.literals import SECRETS_APP
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class AppPeerDataKeys(str, Enum):
    """Enum to access the app peer data keys."""

    managed_users_key = "managed-users-key"
    db_initialised = "db_initialised"
    role = "role"
    keyfile = "keyfile"
    external_connectivity = "external-connectivity"


class AppPeerReplicaSet(AbstractRelationState[DataPeerData]):
    """State collection for replicaset relation."""

    component: Application

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        role: MongoDBRoles,
    ):
        super().__init__(relation, data_interface, component)
        self.data_interface = data_interface
        self._role = role

    @override
    def update(self, items: dict[str, str]) -> None:
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

        Either from the app databag or from the default from config.
        """
        databag_role: str = str(self.relation_data.get(AppPeerDataKeys.role.value))
        if not self.relation or not databag_role:
            return self._role
        return MongoDBRoles(databag_role)

    @role.setter
    def role(self, value: str) -> None:
        self.update({"role": value})

    def is_role(self, role_name: str) -> bool:
        """Checks if the application is running in the provided role."""
        return self.role == role_name

    @property
    def db_initialised(self) -> bool:
        """Whether the db is initialised or not yet."""
        if not self.relation:
            return False
        return json.loads(self.relation_data.get(AppPeerDataKeys.db_initialised.value, "false"))

    @db_initialised.setter
    def db_initialised(self, value: bool):
        if isinstance(value, bool):
            self.update({AppPeerDataKeys.db_initialised.value: json.dumps(value)})
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
            json.loads(self.relation_data.get(AppPeerDataKeys.managed_users_key.value, "[]"))
        )

    @managed_users.setter
    def managed_users(self, value: set[str]) -> None:
        """Stores the managed users set."""
        self.update({AppPeerDataKeys.managed_users_key.value: json.dumps(sorted(value))})

    @property
    def keyfile(self) -> str:
        """Gets the keyfile from the app databag."""
        if not self.relation:
            return ""

        return self.relation_data.get(AppPeerDataKeys.keyfile.value, "")

    @keyfile.setter
    def keyfile(self, keyfile: str):
        """Stores the keyfile in the app databag."""
        self.update({AppPeerDataKeys.keyfile.value: keyfile})

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
            self.relation_data.get(AppPeerDataKeys.external_connectivity.value, "false")
        )

    @external_connectivity.setter
    def external_connectivity(self, value: bool) -> None:
        if isinstance(value, bool):
            self.update({AppPeerDataKeys.external_connectivity.value: json.dumps(value)})
        else:
            raise ValueError(
                f"'external-connectivity' must be a boolean value. Provided: {value} is of type {type(value)}"
            )
