# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The peer relation databag."""

import json
from enum import Enum

from ops.model import Application, Model, Relation
from typing_extensions import override

from single_kernel_mongo.config.literals import FEATURE_VERSION, SECRETS_APP, Substrates
from single_kernel_mongo.core.structured_config import ExposeExternal, MongoDBRoles
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    DataPeerData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class AppPeerDataKeys(str, Enum):
    """Enum to access the app peer data keys."""

    # MongoDB
    MANAGED_USERS_KEY = "managed-users-key"
    MANAGED_ENTITIES_KEY = "managed-entities-key"
    REQUESTED_ENTITY_NAMES_KEY = "requested-entity-names-key"
    DB_INITIALISED = "db_initialised"
    KEYFILE = "keyfile"
    EXTERNAL_CONNECTIVITY = "external-connectivity"
    MONGOS_HOSTS = "mongos_hosts"
    ENABLE_ENCRYPTION_AT_REST = "enable-encryption-at-rest"

    # Shared
    ROLE = "role"
    FCV = "feature-compatibility-version"
    CLUSTER_ID = "cluster-id"

    # Mongos
    DATABASE = "database"
    EXTRA_USER_ROLES = "extra-user-roles"
    EXPOSE_EXTERNAL = "expose-external"
    USERNAME = "username"
    PASSWORD = "password"  # nosec: B105
    CLIENT_ENTITY_FIELDS = "client-entity-fields"


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
        self.update({"role": f"{value.value}"})

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
        self.update({AppPeerDataKeys.DB_INITIALISED.value: json.dumps(value)})

    @property
    def enable_encryption_at_rest(self) -> bool | None:
        """Should encryption at rest be enabled or not."""
        if not self.relation:
            return None
        return json.loads(
            self.relation_data.get(AppPeerDataKeys.ENABLE_ENCRYPTION_AT_REST.value, "null")
        )

    @enable_encryption_at_rest.setter
    def enable_encryption_at_rest(self, value: bool):
        self.update({AppPeerDataKeys.ENABLE_ENCRYPTION_AT_REST.value: json.dumps(value)})

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
    def managed_entities(self) -> dict[str, str]:
        """The roles created for entity relations, keyed by relation id."""
        if not self.relation:
            return {}
        return json.loads(self.relation_data.get(AppPeerDataKeys.MANAGED_ENTITIES_KEY.value, "{}"))

    @managed_entities.setter
    def managed_entities(self, value: dict[str, str]) -> None:
        """Stores the roles created for entity relations."""
        self.update({AppPeerDataKeys.MANAGED_ENTITIES_KEY.value: json.dumps(value, sort_keys=True)})

    @property
    def requested_entity_names(self) -> dict[str, str]:
        """The role names requested by entity relations, keyed by relation id.

        Kept apart from `managed_entities` so a role dropped while its relation lives on
        (a mongos-k8s router un-integrated from its config-server) is re-created under the
        same name: the requester removes its `requested-entity-secret` once the role exists.
        """
        if not self.relation:
            return {}
        return json.loads(
            self.relation_data.get(AppPeerDataKeys.REQUESTED_ENTITY_NAMES_KEY.value, "{}")
        )

    @requested_entity_names.setter
    def requested_entity_names(self, value: dict[str, str]) -> None:
        """Stores the role names requested by entity relations."""
        self.update(
            {AppPeerDataKeys.REQUESTED_ENTITY_NAMES_KEY.value: json.dumps(value, sort_keys=True)}
        )

    @property
    def client_entity_fields(self) -> dict[str, str]:
        """The client entity request a VM mongos forwards to its config-server."""
        if not self.relation:
            return {}
        return json.loads(self.relation_data.get(AppPeerDataKeys.CLIENT_ENTITY_FIELDS.value, "{}"))

    @client_entity_fields.setter
    def client_entity_fields(self, value: dict[str, str]) -> None:
        """Stores the client entity request to forward."""
        self.update({AppPeerDataKeys.CLIENT_ENTITY_FIELDS.value: json.dumps(value, sort_keys=True)})

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
                "",
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

    @property
    def feature_compatibility_version(self) -> str:
        """The value of the feature-compatibility-version."""
        return self.relation_data.get(AppPeerDataKeys.FCV.value, FEATURE_VERSION)

    @feature_compatibility_version.setter
    def feature_compatibility_version(self, value: str):
        self.update({AppPeerDataKeys.FCV.value: value})
