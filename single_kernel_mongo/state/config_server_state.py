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

    DATABASE = "database"
    OPERATOR_PASSWORD = "operator-password"
    BACKUP_PASSWORD = "backup-password"
    HOST = "host"
    KEY_FILE = "key-file"
    INT_CA_SECRET = "int-ca-secret"
    STATUS_READY_FOR_UPGRADE = "status-shows-ready-for-upgrade"


SECRETS_FIELDS = ["operator-password", "backup-password", "key-file", "int-ca-secret"]


class ConfigServerState(AbstractRelationState[Data]):
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
        return json.loads(self.relation_data.get(ConfigServerKeys.HOST.value, "[]"))

    @mongos_hosts.setter
    def mongos_hosts(self, value: list[str]):
        self.update({ConfigServerKeys.HOST.value: json.dumps(sorted(value))})

    @property
    def internal_ca_secret(self) -> str | None:
        """Returns the internal CA secret."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.INT_CA_SECRET.value, None)

    @property
    def keyfile(self) -> str | None:
        """Returns the keyfile."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.KEY_FILE.value, None)

    @property
    def operator_password(self) -> str | None:
        """Returns the operator password."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.OPERATOR_PASSWORD.value, None)

    @property
    def backup_password(self) -> str | None:
        """Returns the operator password."""
        if not self.relation:
            return None
        return self.relation_data.get(ConfigServerKeys.BACKUP_PASSWORD.value, None)

    @property
    def status_ready_for_upgrade(self) -> bool:
        """Returns true if the shard is ready for upgrade."""
        if not self.relation:
            return True
        return json.loads(
            self.relation_data.get(ConfigServerKeys.STATUS_READY_FOR_UPGRADE.value, "false")
        )

    @status_ready_for_upgrade.setter
    def status_ready_for_upgrade(self, value: bool):
        self.update({ConfigServerKeys.STATUS_READY_FOR_UPGRADE.value: json.dumps(value)})
