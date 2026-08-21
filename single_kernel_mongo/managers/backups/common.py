"""The Common backup manager.

This semi-abstract class provides the common code for s3 and gcs integrations.
This means, mainly the code for creating, listing, restoring backups + some checks.

The rest will be handled in child classes.

Specifically backups are handled with Percona Backup MongoDB (pbm).
A user for PBM is created when MongoDB is first started during the start phase.
This user is named "charmed-backup".
"""

from __future__ import annotations

import json
import logging
import re
import time
from abc import abstractmethod
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, Any, ClassVar, NewType, override

from botocore.exceptions import ConnectTimeoutError, SSLError
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import (
    AbstractManagerStatus,
)
from data_platform_helpers.advanced_statuses.types import Scope
from ops.framework import Object
from ops.model import (
    Container,
    Relation,
)
from tenacity import (
    retry,
    retry_if_exception_type,
    retry_if_not_exception_type,
    stop_after_attempt,
)
from tenacity.before import before_log
from tenacity.wait import wait_fixed
from yaml import safe_dump

from single_kernel_mongo.config.literals import (
    TRUST_STORE_PATH,
    MongoPorts,
    Substrates,
    TrustStoreFiles,
)
from single_kernel_mongo.config.models import BackupState, CharmSpec
from single_kernel_mongo.config.statuses import BackupStatuses
from single_kernel_mongo.core.structured_config import MongoDBCharmConfig, MongoDBRoles
from single_kernel_mongo.exceptions import (
    BackupError,
    FailedToCreateBucketError,
    InvalidArgumentForActionError,
    InvalidPBMStatusError,
    InvalidStorageCredentialsError,
    ListBackupError,
    RestoreError,
    ResyncError,
    SetPBMConfigError,
    WorkloadExecError,
)
from single_kernel_mongo.managers.config import BackupConfigManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.config_server_state import AppShardingComponentKeys
from single_kernel_mongo.workload import get_pbm_workload_for_substrate
from single_kernel_mongo.workload.backup_workload import PBMWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm  # pragma: nocover
    from single_kernel_mongo.managers.mongodb_operator import (
        MongoDBOperator,
    )  # pragma: nocover

BackupListType = NewType("BackupListType", list[tuple[str, str, str]])

BACKUP_RESTORE_MAX_ATTEMPTS = 10
BACKUP_RESTORE_ATTEMPT_COOLDOWN = 15
REMAPPING_PATTERN = r"\ABackup doesn't match current cluster topology - it has different replica set names. Extra shards in the backup will cause this, for a simple example. The extra/unknown replica set names found in the backup are: ([\w\d\-,\s]+)([.] Backup has no data for the config server or sole replicaset)?\Z"

# Already yaml encoded blackhole config to bootstrap pbm config
EMPTY_CONFIG = "storage:\n  type: blackhole\n"

logger = logging.getLogger(__name__)


class StatusCodeError(str, Enum):
    """Status codes returned in PBM."""

    MOVED_PERMANENTLY = "status code: 301"
    FORBIDDEN = "status code: 403"
    NOTFOUND = "status code: 404"


def _backup_restore_retry_before_sleep(retry_state) -> None:
    logger.error(
        f"Attempt {retry_state.attempt_number} failed. {BACKUP_RESTORE_MAX_ATTEMPTS - retry_state.attempt_number} attempts left."
        f"Retrying after {BACKUP_RESTORE_ATTEMPT_COOLDOWN} seconds."
    )


class CommonBackupManager(Object, BackupConfigManager, AbstractManagerStatus[CharmState]):
    """Common Manager for the backups and storage integrators."""

    CONFIG_MAP: ClassVar[dict[str, str]] = {}
    BASIC_CONFIG: ClassVar[dict[str, dict[str, str]]] = {}
    invalid_integration_status: StatusObject
    backend: ClassVar[str]

    def __init__(
        self,
        dependent: MongoDBOperator,
        role: CharmSpec,
        substrate: Substrates,
        state: CharmState,
        container: Container | None,
    ) -> None:
        super().__init__(parent=dependent, key=self.name)
        super(Object, self).__init__(
            role=role,
            substrate=substrate,
            config=dependent.charm.parsed_config,
            state=state,
            container=container,
        )
        self.dependent: MongoDBOperator = dependent
        self.charm: AbstractMongoCharm[MongoDBCharmConfig, MongoDBOperator] = dependent.charm
        self.substrate: Substrates = substrate
        self.workload: PBMWorkload = get_pbm_workload_for_substrate(substrate)(
            role=role, container=container
        )
        self.state: CharmState = state
        self._backup_id: str = ""

    @property
    def relation(self) -> Relation | None:
        """The relation for that manager."""
        raise NotImplementedError

    @property
    def backup_id(self) -> str:
        """The current backup id."""
        return self._backup_id

    @backup_id.setter
    def backup_id(self, value: str):
        self._backup_id = value

    @cached_property
    def environment(self) -> dict[str, str]:
        """The environment used to run PBM commands.

        For security reason, we never provide the URI via arguments to the PBM
        CLI. So we provide it as an environment variable.
        """
        return {self.workload.env_var: self.state.backup_config.uri}

    @abstractmethod
    def create_bucket(self, credentials: dict[str, str]):
        """Create a bucket if needed by the storage integrator."""
        pass

    def map_config_to_pbm_config(self, credentials: dict[str, str]) -> dict[str, Any]:
        """Simple mapping from integrator config to PBM config keys."""
        output_dict: dict[str, Any] = self.BASIC_CONFIG
        # Iterate on all configuration values
        for s3_option, s3_value in credentials.items():
            # Create a ref to the dict on which we'll walk
            tmp_dict = output_dict
            # Skip invalid values
            if not (path := self.CONFIG_MAP.get(s3_option)):
                continue
            # Split the path on the dots
            parts = path.split(".")
            # Create all the subdicts
            for part in parts[:-1]:
                tmp_dict = tmp_dict.setdefault(part, {})
            # Set the value
            tmp_dict[parts[-1]] = s3_value

        return output_dict

    @cached_property
    def credentials(self) -> dict[str, str]:
        """Returns the credentials for a relation."""
        if not self.relation:
            logger.info("No configuration for backups, no relation to integrator charm.")
            return {}
        return self.dependent.backup_events.credentials_for(self.relation)

    def is_valid_integration(self) -> bool:
        """Returns true if relation to the storage integrator is valid.

        Only replica sets and config_servers can integrate to a storage integrator.
        """
        return (
            self.relation is None
            or self.state.is_role(MongoDBRoles.REPLICATION)
            or self.state.is_role(MongoDBRoles.CONFIG_SERVER)
        )

    @abstractmethod
    def validate_config(self) -> bool:
        """Validates that the S3/GCS config is complete."""
        raise NotImplementedError

    def cleanup_certs_and_restart(self, relation: Relation) -> None:
        """On relation broken event, we need to remove the certificate from the trust store."""
        if self.state.is_scaling_down(relation.id):
            logger.info("Relation broken event occurring due to scale down.")
            return

        # We have to wait until the backup / restore finishes if it is running.
        while True:
            match self.backup_state():
                case BackupState.BACKUP_RUNNING | BackupState.RESTORE_RUNNING:
                    self.dependent.charm.status_handler.set_running_status(
                        BackupStatuses.ACTION_RUNNING.value,
                        scope="unit",
                        component_name=self.name,
                    )
                    # Wait for 10 seconds before retrying
                    time.sleep(10)
                case _:
                    break

        # cleanup local certificate if it exists
        local_cert_file = TRUST_STORE_PATH / TrustStoreFiles.PBM.value
        if local_cert_file.exists() and local_cert_file.is_file():
            local_cert_file.unlink()

        self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
        self.remove_cert_from_shards()
        self.configure_and_restart(force=True)

    @retry(
        stop=stop_after_attempt(BACKUP_RESTORE_MAX_ATTEMPTS),
        retry=retry_if_not_exception_type(BackupError),
        wait=wait_fixed(BACKUP_RESTORE_ATTEMPT_COOLDOWN),
        reraise=True,
        before_sleep=_backup_restore_retry_before_sleep,
    )
    def create_backup_action(self) -> str:  # type: ignore[return]
        """Try to create a backup and return the backup id.

        If PBM is resyncing, the function will retry to create backup
        (up to BACKUP_RESTORE_MAX_ATTEMPTS times)
        with BACKUP_RESTORE_ATTEMPT_COOLDOWN time between attempts.

        If PMB returen any other error, the function will raise BackupError.
        """
        try:
            output_str = self.workload.run_bin_command(
                "backup",
                ["--out", "json"],
                environment=self.environment,
            ).strip()
            output = json.loads(output_str)
            return output.get("name", "N/A")
        except WorkloadExecError as e:
            error_message = e.stdout
            if "Resync" in error_message:
                raise ResyncError from e

            fail_message = f"Backup failed: {str(e)}"
            raise BackupError(fail_message)
        except json.JSONDecodeError:
            fail_message = f"Backup failed: {output_str}"  # pyright: ignore[reportPossiblyUnboundVariable]
            raise BackupError(fail_message)

    def list_backup_action(self) -> str:
        """List the backups entries."""
        try:
            pbm_status_output = self.pbm_status
        except WorkloadExecError as e:
            raise ListBackupError from e
        pbm_status = json.loads(pbm_status_output)

        finished_backups = self.list_finished_backups(pbm_status=pbm_status)
        backup_list = self.list_with_backups_in_progress(
            pbm_status=pbm_status, backup_list=finished_backups
        )

        # process in progress backups

        return self._format_backup_list(sorted(backup_list, key=lambda pair: pair[0]))

    def list_finished_backups(self, pbm_status: dict) -> BackupListType:
        """Lists the finished backups from the status."""
        backup_list: BackupListType = BackupListType([])
        backups = (
            pbm_status.get("backups", {}).get("snapshot") or []
        )  # snapshot is list[str] | None so move default outside of get
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
        return backup_list

    def list_with_backups_in_progress(
        self, pbm_status: dict, backup_list: BackupListType
    ) -> BackupListType:
        """Lists all the backups with the one in progress from the status and finished list."""
        running_backup = pbm_status.get("running", {})
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
        return backup_list

    @retry(
        stop=stop_after_attempt(BACKUP_RESTORE_MAX_ATTEMPTS),
        retry=retry_if_not_exception_type(RestoreError),
        wait=wait_fixed(BACKUP_RESTORE_ATTEMPT_COOLDOWN),
        reraise=True,
        before_sleep=_backup_restore_retry_before_sleep,
    )
    def restore_backup(self, backup_id: str, remapping_pattern: str | None = None) -> None:
        """Try to restore cluster a backup specified by backup id.

        If PBM is resyncing, the function will retry to create backup
        (up to  BACKUP_RESTORE_MAX_ATTEMPTS times) with BACKUP_RESTORE_ATTEMPT_COOLDOWN
        time between attempts.

        If PMB returen any other error, the function will raise RestoreError.
        """
        try:
            remapping_pattern = remapping_pattern or self._remap_replicaset(backup_id)
            remapping_args = ["--replset-remapping", remapping_pattern] if remapping_pattern else []
            self.workload.run_bin_command(
                "restore",
                [backup_id, "--yes"] + remapping_args,
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

    def backup_in_progress(self) -> bool:
        """Checks if a backup is in progress using the backup statuses objects."""
        statuses = self.state.statuses.get(
            scope="unit",
            component=self.name,
            running_status_only=True,
            running_status_type="async",
        )
        return any(status.message.startswith("Backup started") for status in statuses)

    def restore_in_progress(self) -> bool:
        """Checks if a restore is in progress using the backup statuses objects."""
        statuses = self.state.statuses.get(
            scope="unit",
            component=self.name,
            running_status_only=True,
            running_status_type="async",
        )
        return any(status.message.startswith("Restore started") for status in statuses)

    def backup_state(self) -> BackupState:  # noqa:C901
        """Gets the backup state that can be mapped to a status."""
        if not self.state.db_initialised:
            return BackupState.EMPTY
        if not self.relation:
            logger.info("No configuration for backups, not relation to s3-charm")
            return BackupState.EMPTY
        if self.state.s3_relation and self.state.gcs_relation:
            return BackupState.MUTUALLY_EXCLUSIVE
        if not self.validate_config():
            logger.info(
                "Relation to S3/GCS charm exists but not all necessary configurations have been set."
            )
            return BackupState.MISSING_CONFIG
        if not self.workload.active():
            return BackupState.WAITING_PBM_START

        try:
            credentials = self.dependent.backup_events.credentials_for(self.relation)
            self.create_bucket(credentials)
        except InvalidStorageCredentialsError:
            return BackupState.INCORRECT_CREDS
        except (FailedToCreateBucketError, SSLError, ConnectTimeoutError):
            return BackupState.FAILED_TO_CREATE_BUCKET

        try:
            pbm_status = self.pbm_status
        except WorkloadExecError as err:
            pbm_status = err.stdout

        try:
            if pbm_error := self.process_pbm_error(pbm_status):
                return pbm_error
            return self.process_pbm_status(pbm_status)
        except Exception as e:
            logger.error(f"Failed to get pbm status: {e}")
            return BackupState.UNKNOWN_ERROR

    def map_backup_state_to_status(self, state: BackupState) -> list[StatusObject]:  # noqa: C901
        """Maps the state to a list of statuses."""
        match state:
            case BackupState.EMPTY:
                return []
            case BackupState.MUTUALLY_EXCLUSIVE:
                return [BackupStatuses.MUTUALLY_EXCLUSIVE.value]
            case BackupState.MISSING_CONFIG:
                return [BackupStatuses.pbm_missing_conf(self.backend)]
            case BackupState.WAITING_PBM_START:
                return [BackupStatuses.WAITING_FOR_PBM_START.value]
            case BackupState.INCORRECT_CREDS:
                return [BackupStatuses.pbm_incorrect_creds(self.backend)]
            case BackupState.INCOMPATIBLE_CONF:
                return [BackupStatuses.pbm_incompatible_conf(self.backend)]
            case BackupState.UNKNOWN_ERROR:
                return [BackupStatuses.pbm_unknown_error(self.backend)]
            case BackupState.WAITING_TO_SYNC:
                return [BackupStatuses.pbm_waiting_to_sync(self.backend)]
            case BackupState.FAILED_TO_CREATE_BUCKET:
                return [BackupStatuses.failed_to_create_bucket(self.backend)]
            case BackupState.CANNOT_CONFIGURE:
                return [BackupStatuses.cant_configure(self.backend)]
            case BackupState.BACKUP_RUNNING:
                if operation_result := self._get_backup_restore_operation_result(state):
                    logger.info(operation_result)
                return [BackupStatuses.backup_running(self.backup_id)]
            case BackupState.RESTORE_RUNNING:
                if operation_result := self._get_backup_restore_operation_result(state):
                    logger.info(operation_result)
                return [BackupStatuses.restore_running(self.backup_id)]
            case BackupState.ACTIVE:
                return [BackupStatuses.ACTIVE_IDLE.value]

    @override
    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Gets the PBM statuses."""
        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if not self.state.db_initialised:
            return []

        if scope == "app":
            return []

        return self.map_backup_state_to_status(self.backup_state())

    def get_main_status(self) -> StatusObject | None:
        """Returns the first status of the list."""
        pbm_statuses = self.get_statuses(scope="unit", recompute=True)
        return next(iter(pbm_statuses), None)

    def set_certificate(self, credentials: dict) -> None:
        """Sets the certificate on the file system if needed."""
        # Add certificate to trust store
        file_on_disk = self.dependent.get_ca_cert_from_trust_store(TrustStoreFiles.PBM)
        if cert_chain_list := credentials.get("tls-ca-chain", None):
            self.dependent.save_ca_cert_to_trust_store(TrustStoreFiles.PBM, cert_chain_list)
            self.share_certificate_with_shards(cert_chain_list)
            # Restart after setting all configurations
            should_restart = file_on_disk.strip() == "\n".join(cert_chain_list).strip()
            self.configure_and_restart(force=should_restart)

    def set_config_options(self, credentials: dict) -> None:
        """Apply the configuration provided by S3 integrator.

        Args:
            credentials: A dictionary provided by backup event handler.
        """
        config = self.map_config_to_pbm_config(credentials)

        try:
            _ = self.workload.run_bin_command(
                "config", ["--file=-"], environment=self.environment, input=safe_dump(config)
            )
            time.sleep(2)
            self._wait_pbm_status()
        except WorkloadExecError as err:
            # In case of resync in progress, raise a ResyncError that will set a waiting status.
            if "resync" in err.stderr.lower():
                logger.error(
                    "Waiting for resync to finish before setting configuration: %s",
                    {"return_code": err.return_code, "stdout": err.stdout, "stderr": err.stderr},
                )
                raise ResyncError
            # Don't log the credentials that are part of the cmd]
            logger.error(
                "Failed to configure PBM options: %s",
                {"return_code": err.return_code, "stdout": err.stdout, "stderr": err.stderr},
            )
            raise SetPBMConfigError(err.stderr)

    def retrieve_error_message(self, pbm_status: dict) -> str:
        """Parses pbm status for an error message from the current unit.

        If pbm_agent is in the error state, the command `pbm status` does not raise an error.
        Instead, it is in the log messages. pbm_agent also shows all the error messages for other
        replicas in the set. This method tries to handle both cases at once.
        """
        app_name = self.charm.app.name
        replica_info = f"{self.state.unit_peer_data.internal_address}:{MongoPorts.MONGODB_PORT}"

        clusters = pbm_status.get("cluster")

        # No clusters means no error message
        if not clusters:
            return ""

        cluster = next((_cluster for _cluster in clusters if _cluster.get("rs") == app_name), None)

        # No matching cluster means no error message
        if not cluster:
            return ""

        for host_info in cluster.get("nodes", []):
            if replica_info in host_info.get("host"):
                return str(host_info.get("errors", ""))

        # Default case, no error message
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

    def process_pbm_error(self, pbm_status: str) -> BackupState | None:
        """Look up PBM status for errors."""
        error_message: str

        try:
            pbm_as_dict = json.loads(pbm_status)
            error_message = self.retrieve_error_message(pbm_as_dict)
        except json.JSONDecodeError:
            error_message = pbm_status

        if StatusCodeError.FORBIDDEN.value in error_message:
            return BackupState.INCORRECT_CREDS
        if StatusCodeError.NOTFOUND.value in error_message:
            return BackupState.INCOMPATIBLE_CONF
        if StatusCodeError.MOVED_PERMANENTLY.value in error_message:
            return BackupState.INCOMPATIBLE_CONF

        if error_message:
            logger.info("PBM error: %s", error_message)
            return BackupState.UNKNOWN_ERROR

        return None

    def process_pbm_error_as_status(self, pbm_status: str) -> StatusObject | None:
        """Processes the pbm error and returns it as an optional status object."""
        if state := self.process_pbm_error(pbm_status):
            return next(iter(self.map_backup_state_to_status(state)), None)
        return None

    def process_pbm_status(self, pbm_status: str) -> BackupState:
        """Processes the pbm status if there's no error."""
        pbm_as_dict: dict[str, dict] = json.loads(pbm_status)
        current_op = pbm_as_dict.get("running", {})
        match current_op:
            case {"type": "backup", "name": backup_id}:
                self.backup_id = backup_id
                return BackupState.BACKUP_RUNNING
            case {"type": "restore", "name": backup_id}:
                self.backup_id = backup_id
                return BackupState.RESTORE_RUNNING
            case {"type": "resync"}:
                return BackupState.WAITING_TO_SYNC
            case _:
                return BackupState.ACTIVE

    def assert_can_restore(self, backup_id: str, remapping_pattern: str) -> None:
        """Does the status allow to restore.

        Returns:
            check: boolean telling if the status allows to restore.
            reason: The reason if it is not possible to restore yet.
        """
        backup_state = self.backup_state()

        match backup_state:
            case BackupState.EMPTY:
                return
            case BackupState.BACKUP_RUNNING | BackupState.RESTORE_RUNNING:
                raise InvalidPBMStatusError("Please wait for current backup/restore to finish.")
            case BackupState.WAITING_TO_SYNC:
                raise InvalidPBMStatusError(
                    "Sync-ing configurations needs more time, must wait before restoring backups."
                )
            case (
                BackupState.MISSING_CONFIG
                | BackupState.INCORRECT_CREDS
                | BackupState.INCOMPATIBLE_CONF
                | BackupState.UNKNOWN_ERROR
            ):
                raise InvalidPBMStatusError(self.map_backup_state_to_status(backup_state)[0])
            case _:
                pass

        if not backup_id:
            raise InvalidArgumentForActionError("Missing backup-id to restore.")
        if self._needs_provided_remap_arguments(backup_id) and remapping_pattern == "":
            raise InvalidArgumentForActionError(
                "Cannot restore backup, 'remap-pattern' must be set."
            )

    def assert_can_backup(self) -> None:
        """Is PBM is a state where it can backup?"""
        backup_state = self.backup_state()

        match backup_state:
            case BackupState.EMPTY:
                return
            case BackupState.BACKUP_RUNNING | BackupState.RESTORE_RUNNING:
                raise InvalidPBMStatusError(
                    "Can only create one backup at a time, please wait for current backup to finish."
                )
            case BackupState.WAITING_TO_SYNC:
                raise InvalidPBMStatusError(
                    "Sync-ing configurations needs more time, must wait before creating backups."
                )
            case (
                BackupState.MISSING_CONFIG
                | BackupState.INCORRECT_CREDS
                | BackupState.INCOMPATIBLE_CONF
                | BackupState.UNKNOWN_ERROR
            ):
                raise InvalidPBMStatusError(self.map_backup_state_to_status(backup_state)[0])
            case _:
                return

    def assert_can_list_backup(self) -> None:
        """Is PBM in a state to list backup?

        Note: we permit this logic based on status since we aren't checking
        `self.charm.unit.status`, instead `get_status` directly computes the status of pbm.
        """
        backup_state = self.backup_state()
        match backup_state:
            case BackupState.WAITING_TO_SYNC:
                raise InvalidPBMStatusError(
                    "Sync-ing configurations needs more time, must wait before listing backups."
                )
            case (
                BackupState.MISSING_CONFIG
                | BackupState.INCORRECT_CREDS
                | BackupState.INCOMPATIBLE_CONF
                | BackupState.UNKNOWN_ERROR
            ):
                raise InvalidPBMStatusError(self.map_backup_state_to_status(backup_state)[0])
            case _:
                return

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_fixed(10),
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
        try:
            pbm_status = self.pbm_status
            pbm_as_dict: dict[str, dict[str, str]] = json.loads(pbm_status)
            current_pbm_op: dict[str, str] = pbm_as_dict.get("running", {})

            if current_pbm_op.get("type", "") == "resync":
                # since this process takes several minutes we should let the user know
                # immediately.
                self.charm.status_handler.set_running_status(
                    BackupStatuses.pbm_waiting_to_sync(self.backend),
                    scope="unit",
                    statuses_state=self.state.statuses,
                    component_name=self.name,
                )
                raise ResyncError

            # We're done with the sync, let's clear the statuses.
            self.state.statuses.clear(scope="unit", component=self.name)
        except WorkloadExecError as e:
            if status := self.process_pbm_error_as_status(e.stdout):
                self.state.statuses.add(status, scope="unit", component=self.name)
                return
            raise

    def _get_backup_restore_operation_result(self, current_pbm_status: BackupState) -> str | None:
        """Returns a string with the result of the backup/restore operation.

        Note: current_pbm_status is a freshly calculated status from PBM directly, so we allow
        calculations based on its result.

        The function call is expected to be only for not failed operations.
        The operation is taken from previous status of the unit and expected
        to contain the operation type (backup/restore) and the backup id.

        This function does not work reliably for the following reasons.
        1. Another status could get set and then the use of the previous_pbm_status is meaningless
        2. If there was a PBM failure that wasn't noticed by a status check (i.e. in between hooks)
        there is a chance that this function it will incorrectly report the backup/restore
        succeeded.

        TODO: Rework this and integrate it with COS - see DPE-6868 on JIRA for more info.
        """
        previous_pbm_statuses = self.state.statuses.get(
            scope="unit",
            component=self.name,
            running_status_only=True,
            running_status_type="async",
        ).root
        # No previous PBM status, we can return.
        if previous_pbm_statuses == []:
            return None

        previous_pbm_status = previous_pbm_statuses[0]
        previous_operation = (
            BackupState.BACKUP_RUNNING
            if "Backup" in previous_pbm_status.message
            else BackupState.RESTORE_RUNNING
        )
        previous_backup_id = previous_pbm_status.message.split("backup id:")[-1].strip()

        # Same operation and same backup ID.
        if previous_operation == current_pbm_status and previous_backup_id == self.backup_id:
            return f"Operation is still in progress: '{previous_pbm_status.message}'"

        # Backup finished successfully.
        if previous_operation == BackupState.BACKUP_RUNNING:
            return f"Backup {previous_backup_id} completed successfully"

        # Restore finished successfully.
        return f"Restore from backup {previous_backup_id} completed successfully"

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

    @property
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

    def share_certificate_with_shards(self, ca_chain_list: list[str]):
        """Shares the certificates to shards if role is config-server."""
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER) and self.charm.unit.is_leader():
            for relation in self.state.config_server_relation:
                self.state.config_server_data_interface.update_relation_data(
                    relation.id,
                    {AppShardingComponentKeys.BACKUP_CA_SECRET.value: json.dumps(ca_chain_list)},
                )

    def remove_cert_from_shards(self):
        """Removes the certificates from the shards databag."""
        if self.state.is_role(MongoDBRoles.CONFIG_SERVER) and self.charm.unit.is_leader():
            # Remove the certificate from all relations
            for relation in self.state.config_server_relation:
                self.state.config_server_data_interface.delete_relation_data(
                    relation.id, [AppShardingComponentKeys.BACKUP_CA_SECRET.value]
                )
