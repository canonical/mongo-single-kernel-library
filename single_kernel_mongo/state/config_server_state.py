#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Config Server / Shard state."""

import json
from enum import Enum
from typing import final

from ops import Application
from ops.model import Relation, Unit

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import Data
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class AppShardingComponentKeys(str, Enum):
    """Config Server State Model for the application."""

    DATABASE = "database"
    OPERATOR_PASSWORD = "charmed-operator-password"  # nosec B105
    BACKUP_PASSWORD = "charmed-backup-password"  # nosec B105
    HOST = "host"
    KEY_FILE = "key-file"
    INT_CA_SECRET = "int-ca-secret"  # nosec B105
    EXT_CA_SECRET = "ext-ca-secret"  # nosec B105
    BACKUP_CA_SECRET = "backup-ca-secret"  # nosec B105
    MONGOS_CIDRS = "mongos-cidrs"
    RS_HOSTS = "rs-hosts"
    AUTH_UPDATED = "auth-updated"

    # We don't use those except to check if we've received credentials
    USERNAME = "username"
    PASSWORD = "password"  # nosec B105


SECRETS_FIELDS = [
    "charmed-operator-password",
    "charmed-backup-password",
    "key-file",
    "int-ca-secret",
    "ext-ca-secret",
    "backup-ca-secret",
]


@final
class AppShardingComponentState(AbstractRelationState[Data]):
    """The stored state for the ConfigServer Relation."""

    component: Application

    def __init__(self, relation: Relation | None, data_interface: Data, component: Application):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface

    @property
    def mongos_hosts(self) -> list[str]:
        """The mongos hosts in the relation."""
        return json.loads(self.relation_data.get(AppShardingComponentKeys.HOST.value, "[]"))

    @mongos_hosts.setter
    def mongos_hosts(self, value: list[str]):
        self.update({AppShardingComponentKeys.HOST.value: json.dumps(sorted(value))})

    def has_received_credentials(self) -> bool:
        """Checks if the config-server has sent credentials."""
        if not self.relation:
            return False
        return (
            self.relation_data.get(AppShardingComponentKeys.OPERATOR_PASSWORD.value, None)
            is not None
            and self.relation_data.get(AppShardingComponentKeys.BACKUP_PASSWORD.value, None)
            is not None
        )

    @property
    def internal_ca_secret(self) -> str | None:
        """Returns the internal CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(AppShardingComponentKeys.INT_CA_SECRET.value, None)

    @property
    def external_ca_secret(self) -> str | None:
        """Returns the external CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(AppShardingComponentKeys.EXT_CA_SECRET.value, None)

    @property
    def keyfile(self) -> str | None:
        """Returns the keyfile."""
        if not self.relation:
            return None
        return self.relation_data.get(AppShardingComponentKeys.KEY_FILE.value, None)

    @property
    def operator_password(self) -> str | None:
        """Returns the charmed-operator password."""
        if not self.relation:
            return None
        return self.relation_data.get(AppShardingComponentKeys.OPERATOR_PASSWORD.value, None)

    @property
    def backup_password(self) -> str | None:
        """Returns the charmed-backup password."""
        if not self.relation:
            return None
        return self.relation_data.get(AppShardingComponentKeys.BACKUP_PASSWORD.value, None)

    @property
    def backup_ca_secret(self) -> list[str] | None:
        """Returns the backup ca secret."""
        if not self.relation:
            return None
        return json.loads(
            self.relation_data.get(AppShardingComponentKeys.BACKUP_CA_SECRET.value, "null")
        )

    @property
    def mongos_cidrs(self) -> list[str]:
        """The list of CIDRs for mongos apps."""
        if not self.relation:
            return []
        return json.loads(self.relation_data.get(AppShardingComponentKeys.MONGOS_CIDRS.value, "[]"))

    @property
    def rs_hosts(self) -> list[str]:
        """The shard resplicaset hosts in the relation."""
        if not self.relation:
            return []
        return json.loads(self.relation_data.get(AppShardingComponentKeys.RS_HOSTS.value, "[]"))

    @rs_hosts.setter
    def rs_hosts(self, value: list[str]):
        """Sets the rs_hosts key."""
        self.update({AppShardingComponentKeys.RS_HOSTS.value: json.dumps(sorted(value))})

    @property
    def auth_updated(self) -> bool:
        """Has the shard updated its host?."""
        if not self.relation:
            return False
        return json.loads(
            self.relation_data.get(AppShardingComponentKeys.AUTH_UPDATED.value, "false")
        )

    @auth_updated.setter
    def auth_updated(self, value: bool):
        """Sets the auth-updated field."""
        self.update({AppShardingComponentKeys.AUTH_UPDATED.value: json.dumps(value)})


class UnitShardingComponentState(AbstractRelationState[Data]):
    """The stored state for the ConfigServer Relation."""

    component: Unit

    def __init__(self, relation: Relation | None, data_interface: Data, component: Unit):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface
