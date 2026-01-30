#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling backup events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from botocore.exceptions import ConnectTimeoutError, SSLError
from ops.charm import ActionEvent, RelationBrokenEvent, RelationJoinedEvent
from ops.framework import Object

from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import BackupStatuses, MongoDBStatuses
from single_kernel_mongo.exceptions import (
    FailedToCreateS3BucketError,
    InvalidArgumentForActionError,
    InvalidPBMStatusError,
    InvalidS3CredentialsError,
    ListBackupError,
    NonDeferrableFailedHookChecksError,
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


class BackupEventsHandler(Object):
    """Event Handler for managing backups and S3 integration."""

    def __init__(self, dependent: MongoDBOperator):
        super().__init__(parent=dependent, key="backup")
        self.dependent = dependent
        self.manager = self.dependent.backup_manager
        self.charm: AbstractMongoCharm = dependent.charm
        self.relation_name = ExternalRequirerRelations.S3_CREDENTIALS
        self.s3_client = S3Requirer(self.charm, self.relation_name.value)

        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_joined,
            self._on_s3_relation_joined,
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_broken,
            self._on_s3_relation_broken,
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
            self.manager.state.statuses.add(
                MongoDBStatuses.INVALID_S3_REL.value,
                scope="unit",
                component=self.dependent.name,
            )

    def _on_s3_credential_changed(self, event: CredentialsChangedEvent) -> None:  # noqa: C901
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
            self.manager.state.statuses.add(
                MongoDBStatuses.INVALID_S3_REL.value,
                scope="unit",
                component=self.dependent.name,
            )
            return
        if not self.manager.workload.active():
            defer_event_with_info_log(
                logger,
                event,
                action,
                "Set PBM configurations, pbm-agent service not found.",
            )
            return

        if not self.manager.validate_s3_config():
            logger.warning(
                "Relation to S3 charm exists but not all necessary configurations have been set."
            )
            self.manager.state.statuses.set(
                BackupStatuses.PBM_MISSING_CONF.value,
                scope="unit",
                component=self.manager.name,
            )
            return

        # Get the credentials from S3 connection
        credentials = self.s3_client.get_s3_connection_info()

        try:
            # We can clear all statuses as they will get rewritten right after if needed.
            # The only ones we don't want to lose were checked earlier and returned early.
            self.manager.state.statuses.clear(
                scope="unit",
                component=self.manager.name,
            )
            # First create the bucket if it does not exist.
            self.manager.create_bucket(credentials=credentials)
            self.manager.set_certificate(credentials=credentials)
            if not self.charm.unit.is_leader():
                return
            # Then set the config options on PBM.
            self.manager.set_config_options(credentials=credentials)
            # Finally, resync the configuration.
            self.manager.resync_config_options()
            backup_state = BackupState.ACTIVE
        except InvalidS3CredentialsError:
            backup_state = BackupState.INCORRECT_CREDS
        except (FailedToCreateS3BucketError, SSLError, ConnectTimeoutError):
            backup_state = BackupState.FAILED_TO_CREATE_BUCKET
            event.defer()
        except SetPBMConfigError:
            backup_state = BackupState.CANT_CONFIGURE
            event.defer()
        except WorkloadServiceError:
            backup_state = BackupState.WAITING_PBM_START
        except (ResyncError, PBMBusyError):
            backup_state = BackupState.WAITING_TO_SYNC
            defer_event_with_info_log(
                logger, event, action, "Sync-ing configurations needs more time."
            )
        except WorkloadExecError as e:
            if status := self.manager.process_pbm_error_as_status(e.stdout):
                self.manager.state.statuses.add(status, scope="unit", component=self.manager.name)
            return

        pbm_status = self.manager.map_backup_state_to_status(backup_state)[0]
        self.manager.state.statuses.add(pbm_status, scope="unit", component=self.manager.name)

    def _on_s3_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Proceed on s3 relation broken."""
        self.manager.cleanup_certs_and_restart(event.relation)
        self.manager.state.statuses.clear(scope="unit", component=self.manager.name)

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        action = "backup"
        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on leader unit."
            )
            return

        # Get the credentials from S3 connection
        credentials = self.s3_client.get_s3_connection_info()

        try:
            self.assert_pass_sanity_checks()

            self.manager.create_bucket(credentials=credentials)

            self.manager.assert_can_backup()
            backup_id = self.manager.create_backup_action()
            self.charm.status_handler.set_running_status(
                BackupStatuses.backup_running(backup_id),
                scope="unit",
                is_action=True,
                statuses_state=self.manager.state.statuses,
                component_name=self.manager.name,
            )
            success_action_with_info_log(
                logger,
                event,
                action,
                {"backup-status": f"backup started. backup id: {backup_id}"},
            )
        except (
            NonDeferrableFailedHookChecksError,
            InvalidPBMStatusError,
            FailedToCreateS3BucketError,
            InvalidS3CredentialsError,
            SSLError,
            ConnectTimeoutError,
            Exception,
        ) as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        action = "list-backups"
        try:
            self.assert_pass_sanity_checks()
            self.manager.assert_can_list_backup()
            formatted_list = self.manager.list_backup_action()
            success_action_with_info_log(logger, event, action, {"backups": formatted_list})
        except (
            NonDeferrableFailedHookChecksError,
            InvalidPBMStatusError,
            ListBackupError,
        ) as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return

    def _on_restore_action(self, event: ActionEvent) -> None:
        action = "restore"

        backup_id = str(event.params.get("backup-id", ""))
        remapping_pattern = str(event.params.get("remap-pattern", ""))

        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on a leader unit."
            )
            return

        if self.dependent.state.upgrade_in_progress:
            fail_action_with_error_log(
                logger,
                event,
                action,
                "Restoring a backup is not supported during an upgrade.",
            )
            return

        try:
            self.assert_pass_sanity_checks()
            self.manager.assert_can_restore(
                backup_id,
                remapping_pattern,
            )
            self.manager.restore_backup(backup_id=backup_id, remapping_pattern=remapping_pattern)
            self.charm.status_handler.set_running_status(
                BackupStatuses.restore_running(backup_id),
                scope="unit",
                is_action=True,
                statuses_state=self.manager.state.statuses,
                component_name=self.manager.name,
            )
            success_action_with_info_log(
                logger, event, action, {"restore-status": "restore started"}
            )
        except (
            NonDeferrableFailedHookChecksError,
            InvalidPBMStatusError,
            InvalidArgumentForActionError,
            WorkloadExecError,
            RestoreError,
        ) as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return
        except ResyncError:
            raise

    def assert_pass_sanity_checks(self) -> None:
        """Return None if basic conditions for running backup actions are met, raises otherwise.

        No matter what backup-action is being run, these requirements must be met.
        """
        if self.manager.state.s3_relation is None:
            raise NonDeferrableFailedHookChecksError(
                "Relation with s3-integrator charm missing, cannot restore from a backup."
            )
        if not self.manager.is_valid_s3_integration():
            raise NonDeferrableFailedHookChecksError(
                "Shards do not support backup operations, please run action on config-server."
            )
        return
