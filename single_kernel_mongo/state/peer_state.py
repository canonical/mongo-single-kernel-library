# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer relation databag."""

import json

from ops.model import Application, Relation
from pydantic import BaseModel, Field
from typing_extensions import override

from single_kernel_mongo.config.literals import SECRETS_APP
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class AppPeerRelationModel(BaseModel):
    """Description of the model used in the replica set."""

    db_initialised: bool = False
    role: str = ""
    replica_set_hosts: list[str] = []
    operator_user_created: bool = Field(default=False, alias="operator-user-created")
    backup_user_created: bool = Field(default=False, alias="backup-user-created")
    monitor_user_created: bool = Field(default=False, alias="monitor-user-created")
    managed_users_key: list[str] = Field(default=[], alias="managed-users-key")
    operator_password: str | None = Field(default=None, alias="operator-password")
    backup_password: str | None = Field(default=None, alias="backup-password")
    monitor_password: str | None = Field(default=None, alias="monitor-password")
    keyfile: str | None = Field(default=None)
    external_connectivity: bool = Field(default=False, alias="external-connectivity")


class AppPeerReplicaSet(AbstractRelationState[AppPeerRelationModel, DataPeerData]):
    """State collection for replicaset relation."""

    component: Application

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
        role: str,
    ):
        super().__init__(relation, data_interface, component, None)
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
    def role(self) -> str:
        """The role.

        Either from the app databag or from the default from config.
        """
        if not self.relation:
            return ""
        return self.relation_data.role or self._role

    @role.setter
    def role(self, value: str) -> None:
        self.update({"role": value})

    @property
    def db_initialised(self) -> bool:
        """Whether the db is initialised or not yet."""
        if not self.relation:
            return False
        return self.relation_data.db_initialised

    @db_initialised.setter
    def db_initialised(self, value: bool):
        if isinstance(value, bool):
            self.update({"db_initialised": json.dumps(value)})
        else:
            raise ValueError(
                f"'db_initialised' must be a boolean value. Provided: {value} is of type {type(value)}"
            )

    @property
    def replica_set_hosts(self) -> list[str]:
        """Returns the stored list of replica set hosts."""
        if not self.relation:
            return []

        return self.relation_data.replica_set_hosts

    @replica_set_hosts.setter
    def replica_set_hosts(self, value: list[str]) -> None:
        self.update({"replica_set_hosts": json.dumps(value)})

    @property
    def managed_users_key(self) -> list[str]:
        """Returns the stored list of managed-users."""
        if not self.relation:
            return []

        return self.relation_data.managed_users_key

    @property
    def keyfile(self) -> str | None:
        """Gets the keyfile from the app databag."""
        if not self.relation:
            return None

        return self.relation_data.keyfile

    @keyfile.setter
    def keyfile(self, _keyfile: str):
        """Stores the keyfile in the app databag."""
        self.update({"keyfile": _keyfile})

    def set_user_created(self, user: str):
        """Stores the flag stating if user was created."""
        self.update({f"{user}-user-created": json.dumps(True)})

    def is_user_created(self, user: str) -> bool:
        """Has the user already been created?"""
        return getattr(self.relation_data, f"{user}-user-created")

    def set_user_password(self, user: str, password: str):
        """Stores a user password in the app databag."""
        self.update({f"{user}-password": password})

    @property
    def replica_set(self) -> str:
        """The replica set name."""
        return self.component.name

    @property
    def tls_enabled(self) -> bool:
        """Is TLS enabled?"""
        return False

    @property
    def external_connectivity(self) -> bool:
        """Is the external connectivity tag in the databag?"""
        return self.relation_data.external_connectivity

    @external_connectivity.setter
    def external_connectivity(self, value: bool) -> None:
        if isinstance(value, bool):
            self.update({"external-connectivity": json.dumps(value)})
        else:
            raise ValueError(
                f"'external-connectivity' must be a boolean value. Provided: {value} is of type {type(value)}"
            )

    @property
    def config_server_url(self) -> str:
        """The server config url."""
        return ""
