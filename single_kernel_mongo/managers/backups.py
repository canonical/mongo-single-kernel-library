#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The backup manager.

In this class, we manage backup configurations and actions.

Specifically backups are handled with Percona Backup MongoDB (pbm).
A user for PBM is created when MongoDB is first started during the start phase.
This user is named "backup".
"""

import json
import logging
import re
from typing import TYPE_CHECKING

from ops.framework import Object
from tenacity import (
    Retrying,
    retry_if_not_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from single_kernel_mongo.exceptions import (
    BackupError,
    ListBackupError,
    ResyncError,
    WorkloadExecError,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.workload.backup_workload import PBMWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

BACKUP_RESTORE_MAX_ATTEMPTS = 10
BACKUP_RESTORE_ATTEMPT_COOLDOWN = 15
REMAPPING_PATTERN = r"\ABackup doesn't match current cluster topology - it has different replica set names. Extra shards in the backup will cause this, for a simple example. The extra/unknown replica set names found in the backup are: ([\w\d\-,\s]+)([.] Backup has no data for the config server or sole replicaset)?\Z"

logger = logging.getLogger(__name__)


class BackupManager(Object):
    """Manager for the S3 integrator and backups."""

    def __init__(
        self, charm: "AbstractMongoCharm", workload: PBMWorkload, state: CharmState
    ) -> None:
        self.charm = charm
        self.workload = workload
        self.state = state

    def create_backup_action(self) -> str | None:
        """Try to create a backup and return the backup id.

        If PBM is resyncing, the function will retry to create backup
        (up to BACKUP_RESTORE_MAX_ATTEMPTS times)
        with BACKUP_RESTORE_ATTEMPT_COOLDOWN time between attempts.

        If PMB returen any other error, the function will raise BackupError.
        """
        for attempt in Retrying(
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
                        environment={self.workload.env_var: self.state.backup_config.uri},
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
        return None

    def list_backup_action(self) -> str:
        """List the backups entries."""
        backup_list: list[tuple[str, str, str]] = []
        try:
            pbm_status_output = self.workload.run_bin_command(
                "status",
                ["--out=json"],
                environment={self.workload.env_var: self.state.backup_config.uri},
            )
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

    def _is_backup_from_different_cluster(self, backup_status: str) -> bool:
        """Returns if a given backup was made on a different cluster."""
        return re.search(REMAPPING_PATTERN, backup_status) is not None

    def _format_backup_list(self, backup_list: list[tuple[str, str, str]]) -> str:
        """Formats provided list of backups as a table."""
        backups = ["{:<21s} | {:<12s} | {:s}".format("backup-id", "backup-type", "backup-status")]

        backups.append("-" * len(backups[0]))
        for backup_id, backup_type, backup_status in backup_list:
            backups.append(f"{backup_id:<21!s} | {backup_type:<12!s} | {backup_status}!s")

        return "\n".join(backups)


def _backup_restore_retry_before_sleep(retry_state) -> None:
    logger.error(
        f"Attempt {retry_state.attempt_number} failed. {BACKUP_RESTORE_MAX_ATTEMPTS - retry_state.attempt_number} attempts left. Retrying after {BACKUP_RESTORE_ATTEMPT_COOLDOWN} seconds."
    )
