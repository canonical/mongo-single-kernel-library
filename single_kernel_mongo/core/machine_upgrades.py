# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In-place upgrades on machines.

Derived from specification: DA058 - In-Place Upgrades - Kubernetes v2
(https://docs.google.com/document/d/1tLjknwHudjcHs42nzPVBNkHs98XxAOT2BXGGpP7NyEU/)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from data_platform_helpers.advanced_statuses.models import StatusObject

from single_kernel_mongo.config.literals import SNAP, CharmKind, UnitState
from single_kernel_mongo.config.statuses import UpgradeStatuses
from single_kernel_mongo.core.abstract_upgrades import (
    AbstractUpgrade,
)
from single_kernel_mongo.exceptions import FailedToElectNewPrimaryError

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger(__name__)


class MachineUpgrade(AbstractUpgrade):
    """In-place upgrades on machines."""

    @property
    def unit_state(self) -> UnitState | None:
        """Returns the unit state."""
        if (
            self.state.unit_workload_container_version is not None
            and self.state.unit_workload_container_version
            != self.state.app_workload_container_version
        ):
            logger.debug("Unit refresh state: outdated")
            return UnitState.OUTDATED
        return super().unit_state

    @unit_state.setter
    def unit_state(self, value: UnitState) -> None:
        # Super call
        AbstractUpgrade.unit_state.fset(self, value)  # type: ignore[attr-defined]

    def _get_unit_healthy_status(self) -> StatusObject:
        if self.state.unit_workload_container_version == self.state.app_workload_container_version:
            return UpgradeStatuses.vm_active_upgrade(
                self._unit_workload_version,
                self.state.unit_workload_container_version,
                self._current_versions["charm"],
            )

        return UpgradeStatuses.vm_active_upgrade(
            self._unit_workload_version,
            self.state.unit_workload_container_version,
            self._current_versions["charm"],
            outdated=True,
        )

    @property
    def app_status(self) -> StatusObject | None:
        """App upgrade status."""
        if not self.is_compatible:
            logger.info(
                "Refresh incompatible. Rollback with `juju refresh`. "
                "If you accept potential *data loss* and *downtime*, you can continue by running `force-refresh-start`"
                "action on each remaining unit"
            )
            return UpgradeStatuses.INCOMPATIBLE_UPGRADE.value
        return super().app_status

    @property
    def _unit_workload_version(self) -> str | None:
        """Installed MongoDB version for this unit."""
        return self._current_versions["workload"]

    def reconcile_partition(self, *, from_event: bool = False, force: bool = False) -> str | None:
        """Handle Juju action to confirm first upgraded unit is healthy and resume upgrade."""
        if from_event:
            self.upgrade_resumed = True
            return "Refresh resumed."
        return None

    @property
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action.

        Reset to `False` after each `juju refresh`
        VM-only.
        """
        return self.state.app_upgrade_peer_data.upgrade_resumed

    @upgrade_resumed.setter
    def upgrade_resumed(self, value: bool):
        # Trigger peer relation_changed event even if value does not change
        # (Needed when leader sets value to False during `ops.UpgradeCharmEvent`)
        self.state.app_upgrade_peer_data.upgrade_resumed = value

    @property
    def authorized(self) -> bool:
        """Whether this unit is authorized to upgrade.

        Only applies to machine charm.

        Raises:
            PrecheckFailed: App is not ready to upgrade
        """
        assert (
            self.state.unit_workload_container_version != self.state.app_workload_container_version
        )
        assert self.state.app_upgrade_peer_data.versions
        for index, unit in enumerate(self.state.units_upgrade_peer_data):
            # Higher number units have already upgraded
            if unit.name == self.unit_name:
                if index == 0:
                    if (
                        self.state.app_upgrade_peer_data.versions["charm"]
                        == self._current_versions["charm"]
                    ):
                        # Assumes charm version uniquely identifies charm revision
                        logger.debug("Rollback detected. Skipping pre-refresh check")
                    else:
                        # Run pre-upgrade check
                        # (in case user forgot to run pre-upgrade-check action)
                        self.pre_upgrade_check()
                        logger.debug("Pre-refresh check after `juju refresh` successful")
                elif index == 1 and self.dependent.name == CharmKind.MONGOD:
                    # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                    logger.debug(f"Second unit authorized to refresh if {self.upgrade_resumed=}")
                    return self.upgrade_resumed
                return True
            state = unit.unit_state
            if (
                self.state.unit_workload_container_versions.get(unit.name)
                != self.state.app_workload_container_version
                or state is not UnitState.HEALTHY
            ):
                # Waiting for higher number units to upgrade
                return False
        return False

    def upgrade_unit(self, *, dependent: OperatorProtocol) -> None:
        """Runs the upgrade procedure.

        Only applies to machine charm.
        """
        if dependent.name == CharmKind.MONGOD:
            # According to the MongoDB documentation, before upgrading the
            # primary, we must ensure a safe primary re-election.
            try:
                if self.unit_name == dependent.primary_unit_name:  # type: ignore
                    logger.debug("Stepping down current primary, before upgrading service...")
                    dependent.upgrade_manager.step_down_primary_and_wait_reelection()
            except FailedToElectNewPrimaryError:
                # by not setting the snap revision and immediately returning, this function will be
                # called again, and an empty re-elect a primary will occur again.
                logger.error("Failed to reelect primary before upgrading unit.")
                return

        logger.debug(f"Upgrading {self.unit_name=}")
        self.unit_state = UnitState.UPGRADING
        dependent.workload.install()
        # Start charm services if they were not running after refresh
        dependent._configure_workloads()
        dependent.start_charm_services()
        if dependent.name == CharmKind.MONGOD:
            dependent._restart_related_services()  # type: ignore[attr-defined]

        self.state.unit_upgrade_peer_data.snap_revision = SNAP.revision
        logger.debug(f"Saved {SNAP.revision} in unit databag after refresh")

        self.charm.unit.set_workload_version(self.workload.get_version())
        if dependent.name == CharmKind.MONGOD:
            self.state.unit_upgrade_peer_data.current_revision = (
                dependent.cross_app_version_checker.version  # type: ignore
            )

        # post upgrade check should be retried in case of failure, for this it is necessary to
        # emit a separate event.
        dependent.upgrade_events.post_app_upgrade_event.emit()

    def save_snap_revision_after_first_install(self):
        """Set snap revision on first install."""
