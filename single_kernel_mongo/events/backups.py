#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling backup events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import ActionEvent, RelationJoinedEvent
from ops.framework import Object

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.lib.charms.data_platform_libs.v0.s3 import (
    CredentialsChangedEvent,
    S3Requirer,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.managers.backups import BackupManager


logger = logging.getLogger(__name__)


class BackupHandler(Object):
    """Event Handler for managing backups and S3 integration."""

    def __init__(self, dependent: BackupManager):
        super().__init__(dependent, key="client-relations")
        self.dependent = dependent
        self.charm: AbstractMongoCharm = dependent.charm
        self.relation_name = ExternalRequirerRelations.S3_CREDENTIALS
        self.s3_client = S3Requirer(self.charm, self.relation_name)

        self.framework.observe(
            self.charm.on[self.relation_name].relation_joined,
            self._on_s3_relation_joined,
        )
        self.framework.observe(
            self.s3_client.on.credentials_changed, self._on_s3_credential_changed
        )
        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    def _on_s3_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Checks for valid integration for s3-integrations."""
        pass

    def _on_s3_credential_changed(self, event: CredentialsChangedEvent):
        pass

    def _on_create_backup_action(self, event: ActionEvent):
        pass

    def _on_list_backups_action(self, event: ActionEvent):
        pass

    def _on_restore_action(self, event: ActionEvent):
        pass
