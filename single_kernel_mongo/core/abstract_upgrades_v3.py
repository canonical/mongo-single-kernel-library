"""Common code for upgrades."""

import abc
import dataclasses
import logging

import charm_refresh
import poetry.core.constraints.version as poetry_version
from tenacity import RetryError
from typing_extensions import override

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.exceptions import (
    FailedToMovePrimaryError,
)
from single_kernel_mongo.managers.upgrade_v3 import MongoDBUpgradesManager
from single_kernel_mongo.state.charm_state import CharmState

logger = logging.getLogger()


@dataclasses.dataclass(eq=False)
class MongoDBRefresh(charm_refresh.CharmSpecificCommon, abc.ABC):
    """Common code for MongoDB Refreshes."""

    dependent: OperatorProtocol
    upgrades_manager: MongoDBUpgradesManager
    state: CharmState

    @classmethod
    @override
    def is_compatible(
        cls,
        *,
        old_charm_version: charm_refresh.CharmVersion,
        new_charm_version: charm_refresh.CharmVersion,
        old_workload_version: str,
        new_workload_version: str,
    ) -> bool:
        # Check charm version compatibility
        if not super().is_compatible(
            old_charm_version=old_charm_version,
            new_charm_version=new_charm_version,
            old_workload_version=old_workload_version,
            new_workload_version=new_workload_version,
        ):
            return False
        return cls.is_workload_compatible(
            old_workload_version=old_workload_version, new_workload_version=new_workload_version
        )

    @staticmethod
    def is_workload_compatible(
        old_workload_version: str,
        new_workload_version: str,
    ) -> bool:
        """Check if the workload versions are compatible.

        This method is called on the new charm code version. This means that it is responsible for
        determining which versions the charm code supports refreshing from - not refreshing to.
        """
        try:
            old_version = poetry_version.Version.parse(old_workload_version)
            new_version = poetry_version.Version.parse(new_workload_version)
        except ValueError:
            # Not enough values to unpack or cannot convert
            logger.error(
                "Unable to parse workload versions."
                f"Got {old_workload_version} to {new_workload_version}"
            )
            return False

        if old_version.major != new_version.major:
            logger.info(
                "Refreshing to a different major version workload is not supported. "
                f"Got {old_version.major} to {new_version.major}"
            )
            return False

        if old_version > new_version:
            logger.info(
                "Refreshing to an older minor version workload is not supported. "
                f"Got {old_version} to {new_version}"
            )
            return False

        return True

    def _mongodb_checks(self) -> None:
        """MongoDB specific checks."""
        try:
            self.upgrades_manager.wait_for_cluster_healthy()
        except RetryError as e:
            logger.error(
                "Cannot proceed with refresh. Failed to check cluster health, error: %s", e
            )
            raise charm_refresh.PrecheckFailed("Cluster is not healthy")

        try:
            self.upgrades_manager.move_primary_to_last_upgrade_unit()
        except FailedToMovePrimaryError:
            logger.error("Cluster failed to move primary before re-election.")
            raise charm_refresh.PrecheckFailed("Primary switchover failed")

        if not self.upgrades_manager.is_cluster_able_to_read_write():
            logger.error("Cluster cannot read/write to replicas")
            raise charm_refresh.PrecheckFailed("Cluster is not able to read/write to replicas")

        fcv = self.state.app_peer_data.feature_compatibility_version
        if not self.upgrades_manager.is_feature_compatibility_version(fcv):
            logger.info(
                "Not all replicas have the expected feature compatibility: %s",
                fcv,
            )
            raise charm_refresh.PrecheckFailed(f"Not all replicas have the expected FCV {fcv}.")

    def run_pre_refresh_checks_after_1_unit_refreshed(self):
        """Implement pre-refresh checks."""
        if not self.state.db_initialised:
            return

        if self.dependent.name == CharmKind.MONGOS:
            if not self.upgrades_manager.is_mongos_able_to_read_write():
                raise charm_refresh.PrecheckFailed("mongos is not able to read/write")
            return

        backup_state = self.dependent.backup_manager.backup_state()

        if backup_state == BackupState.BACKUP_RUNNING:
            raise charm_refresh.PrecheckFailed("Backup in progress.")
        if backup_state == BackupState.RESTORE_RUNNING:
            raise charm_refresh.PrecheckFailed("Restore in progress.")

        self._mongodb_checks()

        if not self.upgrades_manager.are_pre_upgrade_operations_config_server_successful():
            raise charm_refresh.PrecheckFailed("Failed to disabled balancer.")

    def run_pre_refresh_checks_before_any_units_refreshed(self):
        """Runs before the upgrade."""
        if not self.state.db_initialised:
            return
        if self.dependent.name == CharmKind.MONGOD:
            if not self.dependent.mongo_manager.mongod_ready():
                logger.error("Cannot proceed with refresh. Service mongod is not running.")
                raise charm_refresh.PrecheckFailed("mongod is not running")
        self.run_pre_refresh_checks_after_1_unit_refreshed()
