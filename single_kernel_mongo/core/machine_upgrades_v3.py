"""Machine code for upgrades."""

import dataclasses
import logging

import charm_refresh

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.core.abstract_upgrades_v3 import MongoDBRefresh
from single_kernel_mongo.exceptions import FailedToElectNewPrimaryError, MongoDBUpgradeError

logger = logging.getLogger(__name__)


@dataclasses.dataclass(eq=False)
class MachineMongoDBRefresh(
    MongoDBRefresh,
    charm_refresh.CharmSpecificMachines,
):
    """Machine specific refresh code."""

    def refresh_snap(
        self, *, snap_name: str, snap_revision: str, refresh: charm_refresh.Machines
    ) -> None:
        """Refreshes a snap."""
        self.dependent.stop_charm_services()

        if self.dependent.name == CharmKind.MONGOD:
            try:
                if self.dependent.charm.unit.name == self.dependent.primary_unit_name:
                    self.dependent.mongo_manager.step_down_primary_and_wait_reelection()
            except FailedToElectNewPrimaryError:
                logger.error("Failed to reelect primary before upgrading unit.")
                return

        revision_before_refresh = self.dependent.workload.snap_revision()
        assert (
            snap_revision != revision_before_refresh
        ), "current snap revision and target revision are equal"

        logger.info("Updating snap installation")
        if not self.dependent.workload.install(revision=snap_revision, retry_and_raise=False):
            logger.exception("Snap refresh failed")

            if self.charm.workload.snap_revision() == revision_before_refresh:
                self.dependent.start_charm_services()
            else:
                refresh.update_snap_revision()

            # Ensures that the unit receives another juju event.
            raise MongoDBUpgradeError("Snap Refresh failed.")

        refresh.update_snap_revision()
        logger.info(f"Updated snap to revision {snap_revision}")
