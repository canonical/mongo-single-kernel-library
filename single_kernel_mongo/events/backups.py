#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling backup events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops import MaintenanceStatus
from ops.charm import ActionEvent, RelationJoinedEvent
from ops.framework import Object

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.exceptions import (
    ListBackupError,
    PBMBusyError,
    RestoreError,
    ResyncError,
    SetPBMConfigError,
    WorkloadExecError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.s3 import (
    CredentialsChangedEvent,
    S3Requirer,
)
from single_kernel_mongo.utils.event_helpers import (
    defer_event_with_info_log,
    fail_action_with_error_log,
    success_action_with_info_log,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = logging.getLogger(__name__)

INVALID_INTEGRATION_STATUS = (
    "Relation to s3-integrator is not supported, config role must be config-server."
)


class BackupHandler(Object):
    """Event Handler for managing backups and S3 integration."""

    def __init__(self, dependent: MongoDBOperator):
        super().__init__(dependent, key="client-relations")
        self.dependent = dependent
        self.manager = self.dependent.backup
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
        if self.dependent.state.upgrade_in_progress:
            logger.warning(
                "Adding s3-relations is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return
        if not self.manager.is_valid_s3_integration():
            logger.info(
                "Shard does not support S3 relations. Please relate s3-integrator to config-server only."
            )
            self.charm.status_manager.to_blocked(INVALID_INTEGRATION_STATUS)

    def _on_s3_credential_changed(self, event: CredentialsChangedEvent):
        action = "configure-pbm"
        if self.dependent.state.upgrade_in_progress:
            logger.warning(
                "Changing s3-credentials is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return
        if not self.manager.is_valid_s3_integration():
            logger.debug(
                "Shard does not support s3 relations, please relate s3-integrator to config-server only."
            )
            self.charm.status_manager.to_blocked(INVALID_INTEGRATION_STATUS)
            return
        if not self.manager.workload.active():
            defer_event_with_info_log(
                logger, event, action, "Set PBM configurations, pbm-agent service not found."
            )
            return

        # Get the credentials from S3 connection
        credentials = self.s3_client.get_s3_connection_info()

        try:
            self.manager.set_config_options(credentials=credentials)
            self.manager.resync_config_options()
        except SetPBMConfigError:
            self.charm.status_manager.to_blocked("couldn't configure s3 backup options.")
            return
        except WorkloadServiceError as e:
            self.charm.status_manager.to_blocked("couldn't start pbm")
            logger.error("An exception occurred when starting pbm agent, error: %s.", str(e))
            return
        except ResyncError:
            self.charm.status_manager.to_waiting("waiting to sync s3 configurations.")
            defer_event_with_info_log(
                logger, event, action, "Sync-ing configurations needs more time."
            )
            return
        except PBMBusyError:
            self.charm.status_manager.to_waiting("waiting to sync s3 configurations.")
            defer_event_with_info_log(
                logger,
                event,
                action,
                "Cannot update configs while PBM is running, must wait for PBM action to finish.",
            )
            return
        except WorkloadExecError as e:
            self.charm.status_manager.to_blocked(self.manager.process_pbm_error(e.stdout))
            return

        self.charm.status_manager.set_and_share_status(self.manager.get_status())

    def _on_create_backup_action(self, event: ActionEvent):
        action = "backup"
        check, reason = self.pass_sanity_checks()
        if not check:
            fail_action_with_error_log(logger, event, action, reason)
            return
        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on leader unit."
            )

        check, reason = self.manager.can_backup()
        if not check:
            fail_action_with_error_log(logger, event, action, reason)
            return

        try:
            backup_id = self.manager.create_backup_action()
            self.charm.status_manager.set_and_share_status(
                MaintenanceStatus(f"backup started/running, backup id:'{backup_id}'")
            )
            success_action_with_info_log(
                logger,
                event,
                action,
                {"backup-status": f"backup started. backup id: {backup_id}"},
            )
        except Exception as e:
            fail_action_with_error_log(
                logger,
                event,
                action,
                str(e),
            )

    def _on_list_backups_action(self, event: ActionEvent):
        action = "list-backups"
        check, reason = self.pass_sanity_checks()
        if not check:
            fail_action_with_error_log(logger, event, action, reason)
            return

        check, reason = self.manager.can_list_backup()
        if not check:
            fail_action_with_error_log(logger, event, action, reason)
            return

        try:
            formatted_list = self.manager.list_backup_action()
            success_action_with_info_log(logger, event, action, {"backups": formatted_list})
        except ListBackupError as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return

    def _on_restore_action(self, event: ActionEvent):
        action = "restore"

        backup_id = str(event.params.get("backup-id", ""))
        remapping_pattern = str(event.params.get("remap-pattern", ""))

        if self.dependent.state.upgrade_in_progress:
            fail_action_with_error_log(
                logger, event, action, "Restoring a backup is not supported during an upgrade."
            )
            return
        check, message = self.pass_sanity_checks()
        if not check:
            fail_action_with_error_log(logger, event, action, message)
            return
        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on a leader unit."
            )
            return

        check, reason = self.manager.can_restore(
            backup_id,
            remapping_pattern,
        )
        if not check:
            fail_action_with_error_log(logger, event, action, reason)
            return

        try:
            self.manager.restore_backup(backup_id=backup_id, remapping_pattern=remapping_pattern)
            self.charm.status_manager.set_and_share_status(
                MaintenanceStatus(f"restore started/running, backup id:'{backup_id}'")
            )
            success_action_with_info_log(
                logger, event, action, {"restore-status": "restore started"}
            )
        except ResyncError:
            raise
        except RestoreError as restore_error:
            fail_action_with_error_log(logger, event, action, str(restore_error))

    def pass_sanity_checks(self) -> tuple[bool, str]:
        """Return True if basic pre-conditions for running backup actions are met.

        No matter what backup-action is being run, these requirements must be met.
        """
        if self.manager.state.s3_relation is None:
            return False, "Relation with s3-integrator charm missing, cannot restore from a backup."
        if not self.manager.is_valid_s3_integration():
            return (
                False,
                "Shards do not support backup operations, please run action on config-server.",
            )

        return True, ""
