#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Cluster state."""

import json
from enum import Enum

from ops import Application
from ops.model import Relation

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import Data
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class ConfigServerKeys(str, Enum):
    """Cluster State Model."""

    database = "database"
    operator_password = "operator-password"
    backup_password = "backup-password"
    host = "host"
    key_file = "key-file"
    int_ca_secret = "int-ca-secret"


SECRETS_FIELDS = ["operator-password", "backup-password", "key-file", "int-ca-secret"]


class ShardingComponentState(AbstractRelationState[Data]):
    """The stored state for the ConfigServer Relation."""

    component: Application

    def __init__(self, relation: Relation | None, data_interface: Data, component: Application):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface

    @property
    def mongos_hosts(self) -> list[str]:
        """The mongos hosts in the relation."""
        if not self.relation:
            return []
        return json.loads(self.relation_data.get(ConfigServerKeys, "[]"))

    @mongos_hosts.setter
    def mongos_hosts(self, value: list[str]):
        self.update({ConfigServerKeys.host.value: json.dumps(sorted(value))})

    @property
    def internal_ca_secret(self) -> str | None:
        """Returns the internal CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.int_ca_secret.value, None)

    @property
    def keyfile(self) -> str | None:
        """Returns the keyfile."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.key_file.value, None)

    @property
    def operator_password(self) -> str | None:
        """Returns the operator password."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.operator_password.value, None)

    @property
    def backup_password(self) -> str | None:
        """Returns the operator password."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.backup_password.value, None)
