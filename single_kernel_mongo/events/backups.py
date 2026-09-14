#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling backup events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, final

from botocore.exceptions import ConnectTimeoutError, SSLError
from ops import Relation
from ops.charm import ActionEvent, RelationBrokenEvent, RelationJoinedEvent
from ops.framework import Object

from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import BackupStatuses
from single_kernel_mongo.core.structured_config import MongoDBCharmConfig
from single_kernel_mongo.exceptions import (
    FailedToCreateBucketError,
    InvalidArgumentForActionError,
    InvalidPBMStatusError,
    InvalidStorageCredentialsError,
    InvalidStorageRelationError,
    ListBackupError,
    NonDeferrableFailedHookChecksError,
    RestoreError,
    ResyncError,
    SetPBMConfigError,
    WorkloadExecError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.gcs_storage import (
    GcsStorageRequires,
    StorageConnectionInfoChangedEvent,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.object_storage import (
    S3Requirer,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.object_storage import (
    StorageConnectionInfoChangedEvent as CredentialsChangedEvent,
)
from single_kernel_mongo.utils.event_helpers import (
    defer_event_with_info_log,
    fail_action_with_error_log,
    success_action_with_info_log,
)
from single_kernel_mongo.utils.helpers import json_or_b64_to_dict

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.managers.backups.common import CommonBackupManager
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = logging.getLogger(__name__)


@final
class BackupEventsHandler(Object):
    """Event Handler for managing backups and S3 integration."""

    def __init__(self, dependent: MongoDBOperator):
        super().__init__(parent=dependent, key="backup")
        self.dependent = dependent
        self.state = dependent.state
        self.s3_manager = self.dependent.s3_backup_manager
        self.gcs_manager = self.dependent.gcs_backup_manager
        self.charm: AbstractMongoCharm[MongoDBCharmConfig, MongoDBOperator] = dependent.charm
        self.s3_relation_name = ExternalRequirerRelations.S3_CREDENTIALS
        self.gcs_relation_name = ExternalRequirerRelations.GCS_CREDENTIALS

        self.s3_client = S3Requirer(self.charm, self.s3_relation_name.value)

        self.gcs_client = GcsStorageRequires(self.charm, self.gcs_relation_name.value)

        for relation in (self.s3_relation_name, self.gcs_relation_name):
            self.framework.observe(
                self.charm.on[relation.value].relation_joined,
                self._on_relation_joined,
            )
            self.framework.observe(
                self.charm.on[relation.value].relation_departed,
                self.dependent.check_relation_broken_or_scale_down,
            )
            self.framework.observe(
                self.charm.on[relation.value].relation_broken,
                self._on_relation_broken,
            )

        # S3 Handler
        self.framework.observe(
            self.s3_client.on.storage_connection_info_changed, self._on_credentials_changed
        )

        # GCS Handler
        self.framework.observe(
            self.gcs_client.on.storage_connection_info_changed, self._on_credentials_changed
        )

        self.framework.observe(self.charm.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.charm.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.charm.on.restore_action, self._on_restore_action)

    @property
    def current_relation(self) -> Relation | None:
        """Returns current relation."""
        if self.state.s3_relation:
            return self.state.s3_relation
        if self.state.gcs_relation:
            return self.state.gcs_relation
        return None

    def manager_for(self, relation_name: str) -> CommonBackupManager | None:
        """The manager that maps to this relation."""
        if relation_name == self.s3_relation_name.value:
            return self.s3_manager
        if relation_name == self.gcs_relation_name.value:
            return self.gcs_manager
        return None

    def credentials_for(self, relation: Relation) -> dict[str, str]:
        """This is the credentials."""
        if relation == self.state.s3_relation:
            return self.s3_client.get_storage_connection_info(relation)
        if relation == self.state.gcs_relation:
            initial_creds = self.gcs_client.get_storage_connection_info(relation)
            secret_dict = json_or_b64_to_dict(initial_creds.get("secret-key", "{}"))

            # Flatten the dict to make the mapping easy.
            # It's guaranteed that the secret-key field exists here, but let's not trust it though.
            return initial_creds | secret_dict
        return {}

    def _on_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Checks for valid integration for backup storage integrations."""
        manager = self.manager_for(event.relation.name)

        if not manager:
            logger.error(
                "Credentials changed event but no matching manager. This should not happen."
            )
            # This is a big no no, let's raise an error for once.
            raise InvalidStorageRelationError(f"No matching manager for {event.relation.name}")

        if self.dependent.refresh_in_progress:
            logger.warning(
                "Adding backup relations is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return

        if self.state.s3_relation and self.state.gcs_relation:
            logger.info("GCS and S3 relations are mutually exclusive.")
            manager.state.statuses.add(
                BackupStatuses.MUTUALLY_EXCLUSIVE.value,
                scope="unit",
                component=manager.name,
            )
            return

        if not manager.is_valid_integration():
            logger.info(
                "Shard does not support S3/GCS integration. Please relate s3/gcs-integrator to config-server only."
            )
            manager.state.statuses.add(
                manager.invalid_integration_status,
                scope="unit",
                component=self.dependent.name,
            )

    def _on_credentials_changed(  # noqa: C901
        self, event: CredentialsChangedEvent | StorageConnectionInfoChangedEvent
    ) -> None:
        action = "configure-pbm"
        manager = self.manager_for(event.relation.name)
        credentials = self.credentials_for(event.relation)

        if not manager:
            logger.error(
                "Credentials changed event but no matching manager. This should not happen."
            )
            # This is a big no no, let's raise an error for once.
            raise InvalidStorageRelationError(f"No matching manager for {event.relation.name}")

        if not credentials:
            logger.info("Still waiting for credentials")
            return

        if self.dependent.refresh_in_progress:
            logger.warning(
                "Changing backup storage credentials is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return

        if self.state.s3_relation and self.state.gcs_relation:
            logger.info("GCS and S3 relations are mutually exclusive.")
            manager.state.statuses.add(
                BackupStatuses.MUTUALLY_EXCLUSIVE.value,
                scope="unit",
                component=manager.name,
            )
            return

        if not manager.is_valid_integration():
            logger.debug(
                "Shard does not support S3/GCS integration, please relate s3/gcs-integrator to config-server only."
            )
            manager.state.statuses.add(
                manager.invalid_integration_status,
                scope="unit",
                component=self.dependent.name,
            )
            return

        if not manager.workload.active():
            defer_event_with_info_log(
                logger,
                event,
                action,
                "Set PBM configurations, pbm-agent service not found.",
            )
            return

        if not manager.validate_config():
            logger.warning(
                "Relation to Storage charm exists but not all necessary configurations have been set."
            )
            manager.state.statuses.set(
                BackupStatuses.pbm_missing_conf(manager.backend),
                scope="unit",
                component=manager.name,
            )
            return

        try:
            # We can clear all statuses as they will get rewritten right after if needed.
            # The only ones we don't want to lose were checked earlier and returned early.
            manager.state.statuses.clear(
                scope="unit",
                component=manager.name,
            )
            # First create the bucket if it does not exist.
            manager.create_bucket(credentials=credentials)
            manager.set_certificate(credentials=credentials)
            if not self.charm.unit.is_leader():
                return

            # Then set the config options on PBM.
            manager.set_config_options(credentials=credentials)
            backup_state = BackupState.ACTIVE
        except InvalidStorageCredentialsError:
            backup_state = BackupState.INCORRECT_CREDS
        except (FailedToCreateBucketError, SSLError, ConnectTimeoutError):
            backup_state = BackupState.FAILED_TO_CREATE_BUCKET
            event.defer()
        except SetPBMConfigError:
            backup_state = BackupState.CANNOT_CONFIGURE
            event.defer()
        except WorkloadServiceError:
            backup_state = BackupState.WAITING_PBM_START
        except ResyncError:
            backup_state = BackupState.WAITING_TO_SYNC
            defer_event_with_info_log(
                logger, event, action, "Sync-ing configurations needs more time."
            )
        except WorkloadExecError as e:
            if status := manager.process_pbm_error_as_status(e.stdout):
                manager.state.statuses.add(status, scope="unit", component=manager.name)
            return

        pbm_status = manager.map_backup_state_to_status(backup_state)[0]
        manager.state.statuses.add(pbm_status, scope="unit", component=manager.name)

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Proceed on s3/gcs relation broken."""
        if not (manager := self.manager_for(event.relation.name)):
            logger.warning("Two relations combined, exiting early.")
            return

        manager.cleanup_certs_and_restart(event.relation)
        manager.state.statuses.clear(scope="unit", component=manager.name)

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        action = "backup"

        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on leader unit."
            )
            return

        # Get the credentials from S3/GCS integration
        if not (relation := self.current_relation):
            event.fail("Missing valid relation for backups.")
            return

        if not (manager := self.manager_for(relation.name)):
            event.fail("Manager only existing for s3/gcs-credentials relation.")
            return
        if not (credentials := self.credentials_for(relation)):
            event.fail("Missing valid credentials in relation.")
            return

        try:
            self.assert_pass_sanity_checks(manager)

            manager.create_bucket(credentials=credentials)

            manager.assert_can_backup()
            backup_id = manager.create_backup_action()
            self.charm.status_handler.set_running_status(
                BackupStatuses.backup_running(backup_id),
                scope="unit",
                is_action=True,
                statuses_state=manager.state.statuses,
                component_name=manager.name,
            )
            success_action_with_info_log(
                logger,
                event,
                action,
                {"backup-status": f"backup started. backup id: {backup_id}"},
            )
        except Exception as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        action = "list-backups"
        if not (relation := self.current_relation):
            event.fail("Missing valid integration for backups.")
            return

        if not (manager := self.manager_for(relation.name)):
            event.fail("Manager only existing for s3/gcs-credentials relation.")
            return

        try:
            self.assert_pass_sanity_checks(manager)
            manager.assert_can_list_backup()
            formatted_list = manager.list_backup_action()
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

        if not (relation := self.current_relation):
            fail_action_with_error_log(
                logger, event, action, "No valid relation to restore backup from."
            )
            return

        if not (manager := self.manager_for(relation.name)):
            fail_action_with_error_log(
                logger, event, action, "Manager only existing for s3/gcs-credentials relation."
            )
            return

        if not self.charm.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "The action can be run only on a leader unit."
            )
            return

        if self.dependent.refresh_in_progress:
            fail_action_with_error_log(
                logger,
                event,
                action,
                "Restoring a backup is not supported during an upgrade.",
            )
            return

        try:
            self.assert_pass_sanity_checks(manager)
            manager.assert_can_restore(
                backup_id,
                remapping_pattern,
            )
            manager.restore_backup(backup_id=backup_id, remapping_pattern=remapping_pattern)
            self.charm.status_handler.set_running_status(
                BackupStatuses.restore_running(backup_id),
                scope="unit",
                is_action=True,
                statuses_state=manager.state.statuses,
                component_name=manager.name,
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

    def assert_pass_sanity_checks(self, manager: CommonBackupManager) -> None:
        """Return None if basic conditions for running backup actions are met, raises otherwise.

        No matter what backup-action is being run, these requirements must be met.
        """
        if manager.relation is None:
            raise NonDeferrableFailedHookChecksError(
                "Relation with s3-integrator charm missing, cannot restore from a backup."
            )
        if not manager.is_valid_integration():
            raise NonDeferrableFailedHookChecksError(
                "Shards do not support backup operations, please run action on config-server."
            )
        return
