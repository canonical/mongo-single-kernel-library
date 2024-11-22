#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The backup manager.

In this class, we manage backup configurations and actions.

Specifically backups are handled with Percona Backup MongoDB (pbm).
A user for PBM is created when MongoDB is first started during the start phase.
This user is named "backup".
"""

from __future__ import annotations

import json
import logging
import re
import time
from functools import cached_property
from typing import TYPE_CHECKING

from ops import Container
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, StatusBase, WaitingStatus
from tenacity import (
    Retrying,
    before_log,
    retry,
    retry_if_exception_type,
    retry_if_not_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from single_kernel_mongo.config.literals import MongoPorts, Substrates
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    BackupError,
    ListBackupError,
    PBMBusyError,
    RestoreError,
    ResyncError,
    SetPBMConfigError,
    WorkloadExecError,
)
from single_kernel_mongo.managers.config import BackupConfigManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.workload import get_pbm_workload_for_substrate
from single_kernel_mongo.workload.backup_workload import PBMWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

BACKUP_RESTORE_MAX_ATTEMPTS = 10
BACKUP_RESTORE_ATTEMPT_COOLDOWN = 15
REMAPPING_PATTERN = r"\ABackup doesn't match current cluster topology - it has different replica set names. Extra shards in the backup will cause this, for a simple example. The extra/unknown replica set names found in the backup are: ([\w\d\-,\s]+)([.] Backup has no data for the config server or sole replicaset)?\Z"

S3_PBM_OPTION_MAP = {
    "region": "storage.s3.region",
    "bucket": "storage.s3.bucket",
    "path": "storage.s3.prefix",
    "access-key": "storage.s3.credentials.access-key-id",
    "secret-key": "storage.s3.credentials.secret-access-key",
    "endpoint": "storage.s3.endpointUrl",
    "storage-class": "storage.s3.storageClass",
}
logger = logging.getLogger(__name__)


class BackupManager(Object, BackupConfigManager):
    """Manager for the S3 integrator and backups."""

    def __init__(
        self,
        charm: AbstractMongoCharm,
        substrate: Substrates,
        state: CharmState,
        container: Container | None,
    ) -> None:
        super().__init__(parent=charm, key="backup")
        super(Object, self).__init__(
            substrate=substrate, config=charm.parsed_config, state=state, container=container
        )
        self.charm = charm
        self.workload: PBMWorkload = get_pbm_workload_for_substrate(substrate)(container=container)
        self.state = state

    @cached_property
    def environment(self) -> dict[str, str]:
        """The environment used to run PBM commands."""
        return {self.workload.env_var: self.state.backup_config.uri}

    def is_valid_s3_integration(self) -> bool:
        """Returns true if relation to s3-integrator is valid.

        Only replica sets and config_servers can integrate to s3-integrator.
        """
        return (self.state.s3_relation is None) or (not self.state.is_role(MongoDBRoles.SHARD))

    def create_backup_action(self) -> str:  # type: ignore[return]
        """Try to create a backup and return the backup id.

        If PBM is resyncing, the function will retry to create backup
        (up to BACKUP_RESTORE_MAX_ATTEMPTS times)
        with BACKUP_RESTORE_ATTEMPT_COOLDOWN time between attempts.

        If PMB returen any other error, the function will raise BackupError.
        """
        for attempt in Retrying(  # noqa: RET503
            stop=stop_after_attempt(BACKUP_RESTORE_MAX_ATTEMPTS),
            retry=retry_if_not_exception_type(BackupError),
            wait=wait_fixed(BACKUP_RESTORE_ATTEMPT_COOLDOWN),
            reraise=True,
            before_sleep=_backup_restore_retry_before_sleep,
        ):
            with attempt:
                try:
                    output = self.workload.run_bin_command(
                        "backup",
                        environment=self.environment,
                    )
                    backup_id_match = re.search(
                        r"Starting backup '(?P<backup_id>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)'",
                        output,
                    )
                    return backup_id_match.group("backup_id") if backup_id_match else "N/A"
                except WorkloadExecError as e:
                    error_message = e.stdout
                    if "Resync" in error_message:
                        raise ResyncError from e

                    fail_message = f"Backup failed: {str(e)}"

                    raise BackupError(fail_message)

    def list_backup_action(self) -> str:
        """List the backups entries."""
        backup_list: list[tuple[str, str, str]] = []
        try:
            pbm_status_output = self.pbm_status
        except WorkloadExecError as e:
            raise ListBackupError from e
        pbm_status = json.loads(pbm_status_output)
        backups = pbm_status.get("backups", {}).get("snapshot", [])
        for backup in backups:
            backup_status = "finished"
            if backup["status"] == "error":
                # backups from a different cluster have an error status, but they should show as
                # finished
                if self._is_backup_from_different_cluster(backup.get("error", "")):
                    backup_status = "finished"
                else:
                    # display reason for failure if available
                    backup_status = "failed: " + backup.get("error", "N/A")
            if backup["status"] not in ["error", "done"]:
                backup_status = "in progress"
            backup_list.append((backup["name"], backup["type"], backup_status))

        # process in progress backups
        running_backup = pbm_status["running"]
        if running_backup.get("type", None) == "backup":
            # backups are sorted in reverse order
            last_reported_backup = backup_list[0]
            # pbm will occasionally report backups that are currently running as failed, so it is
            # necessary to correct the backup list in this case.
            if last_reported_backup[0] == running_backup["name"]:
                backup_list[0] = (
                    last_reported_backup[0],
                    last_reported_backup[1],
                    "in progress",
                )
            else:
                backup_list.append((running_backup["name"], "logical", "in progress"))

        return self._format_backup_list(sorted(backup_list, key=lambda pair: pair[0]))

    def restore_backup(self, backup_id: str, remapping_pattern: str | None = None) -> None:
        """Try to restore cluster a backup specified by backup id.

        If PBM is resyncing, the function will retry to create backup
        (up to  BACKUP_RESTORE_MAX_ATTEMPTS times) with BACKUP_RESTORE_ATTEMPT_COOLDOWN
        time between attempts.

        If PMB returen any other error, the function will raise RestoreError.
        """
        for attempt in Retrying(
            stop=stop_after_attempt(BACKUP_RESTORE_MAX_ATTEMPTS),
            retry=retry_if_not_exception_type(RestoreError),
            wait=wait_fixed(BACKUP_RESTORE_ATTEMPT_COOLDOWN),
            reraise=True,
            before_sleep=_backup_restore_retry_before_sleep,
        ):
            with attempt:
                try:
                    remapping_pattern = remapping_pattern or self._remap_replicaset(backup_id)
                    remapping_args = (
                        ["--replset-remapping", remapping_pattern] if remapping_pattern else []
                    )
                    self.workload.run_bin_command(
                        "restore",
                        [backup_id] + remapping_args,
                        environment=self.environment,
                    )
                except WorkloadExecError as e:
                    error_message = e.stdout
                    if "Resync" in e.stdout:
                        raise ResyncError

                    fail_message = f"Restore failed: {str(e)}"
                    if f"backup '{backup_id}' not found" in error_message:
                        fail_message = f"Restore failed: Backup id '{backup_id}' does not exist in list of backups, please check list-backups for the available backup_ids."

                    raise RestoreError(fail_message)

    def get_status(self) -> StatusBase | None:
        """Gets the PBM status."""
        if not self.workload.active():
            return WaitingStatus("waiting for pbm to start")
        if not self.state.s3_relation:
            logger.info("No configuration for backups, not relation to s3-charm")
            return None
        try:
            previous_status = self.charm.unit.status
            pbm_status = self.pbm_status
            pbm_error = self.process_pbm_error(pbm_status)
            if pbm_error:
                return BlockedStatus(pbm_error)

            processed_status = self.process_pbm_status(pbm_status)
            operation_result = self._get_backup_restore_operation_result(
                processed_status, previous_status
            )
            logger.info(operation_result)
            return processed_status
        except Exception as e:
            logger.error(f"Failed to get pbm status: {e}")
            return BlockedStatus("PBM error")

    def resync_config_options(self):
        """Attempts to resync config options and sets status in case of failure."""
        self.workload.start()

        # pbm has a flakely resync and it is necessary to wait for no actions to be running before
        # resync-ing. See: https://jira.percona.com/browse/PBM-1038
        for attempt in Retrying(
            stop=stop_after_attempt(20),
            wait=wait_fixed(5),
            reraise=True,
        ):
            with attempt:
                pbm_status = self.get_status()
                # wait for backup/restore to finish
                if isinstance(pbm_status, (MaintenanceStatus)):
                    raise PBMBusyError

                # if a resync is running restart the service
                if isinstance(pbm_status, (WaitingStatus)):
                    self.workload.restart()
                    raise PBMBusyError

        # wait for re-sync and update charm status based on pbm syncing status. Need to wait for
        # 2 seconds for pbm_agent to receive the resync command before verifying.
        self.workload.run_bin_command("config", ["--force-resync"])
        time.sleep(2)
        self._wait_pbm_status()

    def set_config_options(self, credentials: dict[str, str]) -> None:
        """Apply the configuration provided by S3 integrator.

        Args:
            credentials: A dictionary provided by backup event handler.
        """
        # Clear the current config file.
        self.clear_pbm_config_file()

        config = map_s3_config_to_pbm_config(credentials)

        for pbm_key, pbm_value in config.items():
            try:
                self.workload.run_bin_command("config", ["--set", f"{pbm_key}={pbm_value}"])
            except WorkloadExecError:
                logger.error(f"Failed to configure PBM option: {pbm_key}")
                raise SetPBMConfigError

    def clear_pbm_config_file(self) -> None:
        """Overwrites the PBM config file with the one provided by default."""
        self.workload.write(
            self.workload.paths.pbm_config,
            "# this file is to be left empty. Changes in this file will be ignored.\n",
        )
        self.workload.run_bin_command("config", ["--file", str(self.workload.paths.pbm_config)])

    def retrieve_error_message(self, pbm_status: dict) -> str:
        """Parses pbm status for an error message from the current unit.

        If pbm_agent is in the error state, the command `pbm status` does not raise an error.
        Instead, it is in the log messages. pbm_agent also shows all the error messages for other
        replicas in the set. This method tries to handle both cases at once.
        """
        try:
            clusters = pbm_status["cluster"]
            for cluster in clusters:
                if cluster["rs"] == self.charm.app.name:
                    break

            for host_info in cluster["nodes"]:
                replica_info = (
                    f"mongodb/{self.state.unit_peer_data.internal_address}:{MongoPorts.MONGOS_PORT}"
                )
                if host_info["host"] == replica_info:
                    break

            return str(host_info["errors"])
        except KeyError:
            return ""

    def get_backup_error_status(self, backup_id: str) -> str:
        """Get the error status for a provided backup."""
        pbm_status = self.pbm_status
        pbm_as_dict: dict = json.loads(pbm_status)
        backups = pbm_as_dict.get("backups", {}).get("snapshot", [])
        for backup in backups:
            if backup_id == backup["name"]:
                return backup.get("error", "")

        return ""

    def process_pbm_error(self, pbm_status: str) -> str:
        """Look up PBM status for errors."""
        error_message: str
        message = ""
        try:
            pbm_as_dict = json.loads(pbm_status)
            error_message = self.retrieve_error_message(pbm_as_dict)
        except json.JSONDecodeError:
            error_message = pbm_status

        if "status code: 403" in error_message:
            message = "s3 credentials are incorrect"
        elif "status code: 404" in error_message:
            message = "s3 configurations are incompatible."
        elif "status code: 301" in error_message:
            message = "s3 configurations are incompatible."
        return message

    def process_pbm_status(self, pbm_status: str) -> StatusBase:
        """Processes the pbm status if there's no error."""
        pbm_as_dict: dict[str, dict] = json.loads(pbm_status)
        current_op = pbm_as_dict.get("running", {})
        match current_op:
            case {}:
                return ActiveStatus("")
            case {"type": "backup", "name": backup_id}:
                return MaintenanceStatus(f"backup started/running, backup id: '{backup_id}'")
            case {"type": "restore", "name": backup_id}:
                return MaintenanceStatus(f"restore started/running, backup id: '{backup_id}'")
            case {"type": "resync"}:
                return WaitingStatus("waiting to sync s3 configurations.")
            case _:
                return ActiveStatus()

    def can_restore(self, backup_id: str, remapping_pattern: str) -> tuple[bool, str]:
        """Does the status allow to restore.

        Returns:
            check: boolean telling if the status allows to restore.
            reason: The reason if it is not possible to restore yet.
        """
        pbm_status = self.get_status()
        match pbm_status:
            case MaintenanceStatus():
                return (False, "Please wait for current backup/restore to finish.")
            case WaitingStatus():
                return (
                    False,
                    "Sync-ing configurations needs more time, must wait before listing backups.",
                )
            case BlockedStatus():
                return (False, pbm_status.message)
            case _:
                pass

        if not backup_id:
            return (False, "Missing backup-id to restore.")
        if self._needs_provided_remap_arguments(backup_id) and remapping_pattern == "":
            return (False, "Cannot restore backup, 'remap-pattern' must be set.")

        return True, ""

    def can_backup(self) -> tuple[bool, str]:
        """Is PBM is a state where it can backup?"""
        pbm_status = self.get_status()
        match pbm_status:
            case MaintenanceStatus():
                return (
                    False,
                    "Can only create one backup at a time, please wait for current backup to finish.",
                )
            case WaitingStatus():
                return (
                    False,
                    "Sync-ing configurations needs more time, must wait before creating backups.",
                )
            case BlockedStatus():
                return False, pbm_status.message
            case _:
                return True, ""

    def can_list_backup(self) -> tuple[bool, str]:
        """Is PBM in a state to list backup?"""
        pbm_status = self.get_status()
        match pbm_status:
            case WaitingStatus():
                return (
                    False,
                    "Sync-ing configurations needs more time, must wait before listing backups.",
                )
            case BlockedStatus():
                return False, pbm_status.message
            case _:
                return True, ""

    @retry(
        stop=stop_after_attempt(20),
        reraise=True,
        retry=retry_if_exception_type(ResyncError),
        before=before_log(logger, logging.DEBUG),
    )
    def _wait_pbm_status(self) -> None:
        """Wait for pbm_agent to resolve errors and return the status of pbm.

        The pbm status is set by the pbm_agent daemon which needs time to both resync and resolve
        errors in configurations. Resync-ing is a longer process and should take around 5 minutes.
        Configuration errors generally occur when the configurations change and pbm_agent is
        updating, this is generally quick and should take <15s. If errors are not resolved in 15s
        it means there is an incorrect configuration which will require user intervention.

        Retrying for resync is handled by decorator, retrying for configuration errors is handled
        within this function.
        """
        # on occasion it takes the pbm_agent daemon time to update its configs, meaning that it
        # will error for incorrect configurations for <15s before resolving itself.

        for attempt in Retrying(
            stop=stop_after_attempt(3),
            wait=wait_fixed(5),
            reraise=True,
        ):
            with attempt:
                try:
                    pbm_status = self.pbm_status
                    pbm_as_dict = json.loads(pbm_status)
                    current_pbm_op: dict[str, str] = pbm_as_dict.get("running", {})

                    if current_pbm_op.get("type", "") == "resync":
                        # since this process takes several minutes we should let the user know
                        # immediately.
                        self.charm.status_manager.set_and_share_status(
                            WaitingStatus("waiting to sync s3 configurations.")
                        )
                        raise ResyncError
                except WorkloadExecError as e:
                    self.charm.status_manager.set_and_share_status(
                        BlockedStatus(self.process_pbm_error(e.stdout))
                    )

    def _get_backup_restore_operation_result(
        self, current_pbm_status: StatusBase, previous_pbm_status: StatusBase
    ) -> str:
        """Returns a string with the result of the backup/restore operation.

        The function call is expected to be only for not failed operations.
        The operation is taken from previous status of the unit and expected
        to contain the operation type (backup/restore) and the backup id.
        """
        if (
            current_pbm_status.name == previous_pbm_status.name
            and current_pbm_status.message == previous_pbm_status.message
        ):
            return f"Operation is still in progress: '{current_pbm_status.message}'"

        if (
            isinstance(previous_pbm_status, MaintenanceStatus)
            and "backup id:" in previous_pbm_status.message
        ):
            backup_id = previous_pbm_status.message.split("backup id:")[-1].strip()
            if "restore" in previous_pbm_status.message:
                return f"Restore from backup {backup_id} completed successfully"
            if "backup" in previous_pbm_status.message:
                return f"Backup {backup_id} completed successfully"

        return "Unknown operation result"

    def _is_backup_from_different_cluster(self, backup_status: str) -> bool:
        """Returns if a given backup was made on a different cluster."""
        return re.search(REMAPPING_PATTERN, backup_status) is not None

    def _format_backup_list(self, backup_list: list[tuple[str, str, str]]) -> str:
        """Formats provided list of backups as a table."""
        backups = ["{:<21s} | {:<12s} | {:s}".format("backup-id", "backup-type", "backup-status")]

        backups.append("-" * len(backups[0]))
        for backup_id, backup_type, backup_status in backup_list:
            backups.append(f"{backup_id:<21s} | {backup_type:<12s} | {backup_status:s}")

        return "\n".join(backups)

    @cached_property
    def pbm_status(self) -> str:
        """Runs the pbm status command."""
        return self.workload.run_bin_command(
            "status",
            ["-o", "json"],
            environment=self.environment,
        ).rstrip()

    def _needs_provided_remap_arguments(self, backup_id: str) -> bool:
        """Returns true if remap arguments are needed to perform a restore command."""
        backup_error_status = self.get_backup_error_status(backup_id)

        # When a charm is running as a Replica set it can generate its own remapping arguments
        return self._is_backup_from_different_cluster(backup_error_status) and self.state.is_role(
            MongoDBRoles.CONFIG_SERVER
        )

    def _remap_replicaset(self, backup_id: str) -> str | None:
        """Returns options for remapping a replica set during a cluster migration restore.

        Args:
            backup_id: str of the backup to check for remapping

        Raises: CalledProcessError
        """
        pbm_status = self.pbm_status
        pbm_status = json.loads(pbm_status)

        # grab the error status from the backup if present
        backup_error_status = self.get_backup_error_status(backup_id)

        if not self._is_backup_from_different_cluster(backup_error_status):
            return None

        # TODO in the future when we support conf servers and shards this will need to be more
        # comprehensive.
        old_cluster_name_match = re.search(REMAPPING_PATTERN, backup_error_status)
        if not old_cluster_name_match:
            return None
        old_cluster_name = old_cluster_name_match.group(1)
        current_cluster_name = self.charm.app.name
        logger.debug(
            "Replica set remapping is necessary for restore, old cluster name: %s ; new cluster name: %s",
            old_cluster_name,
            current_cluster_name,
        )
        return f"{current_cluster_name}={old_cluster_name}"


def map_s3_config_to_pbm_config(credentials: dict[str, str]):
    """Simple mapping from s3 integration to current status."""
    pbm_configs = {"storage.type": "s3"}
    for s3_option, s3_value in credentials.items():
        if s3_option not in S3_PBM_OPTION_MAP:
            continue

        pbm_configs[S3_PBM_OPTION_MAP[s3_option]] = s3_value
    return pbm_configs


def _backup_restore_retry_before_sleep(retry_state) -> None:
    logger.error(
        f"Attempt {retry_state.attempt_number} failed. {BACKUP_RESTORE_MAX_ATTEMPTS - retry_state.attempt_number} attempts left."
        f"Retrying after {BACKUP_RESTORE_ATTEMPT_COOLDOWN} seconds."
    )
