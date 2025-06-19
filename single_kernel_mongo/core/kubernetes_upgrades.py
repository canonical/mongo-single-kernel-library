#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Kubernetes Upgrade Code.

This code is slightly different from the code which was written originally.
It is required to deploy the application with `--trust` for this code to work
as it has to interact with the Kubernetes StatefulSet.
"""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from data_platform_helpers.advanced_statuses.models import StatusObject
from lightkube.core.exceptions import ApiError
from overrides import override

from single_kernel_mongo.config.literals import CharmKind, UnitState
from single_kernel_mongo.config.statuses import UpgradeStatuses
from single_kernel_mongo.core.abstract_upgrades import (
    AbstractUpgrade,
)
from single_kernel_mongo.exceptions import ActionFailedError, DeployedWithoutTrustError
from single_kernel_mongo.state.upgrade_state import UnitUpgradePeerData
from single_kernel_mongo.utils.helpers import unit_number

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = getLogger()


class KubernetesUpgrade(AbstractUpgrade):
    """Code for Kubernetes Upgrade.

    This is the implementation of Kubernetes Upgrade methods.
    """

    def __init__(self, dependent: OperatorProtocol, *args, **kwargs):
        super().__init__(dependent, *args, **kwargs)

        self.k8s_manager = self.state.k8s_manager
        try:
            self.k8s_manager.get_partition()
        except ApiError as err:
            if err.status.code == 403:
                raise DeployedWithoutTrustError(app_name=dependent.charm.app.name)
            raise

    @override
    def _get_unit_healthy_status(self) -> StatusObject:
        version = self.state.unit_workload_container_version
        if version == self.state.app_workload_container_version:
            return UpgradeStatuses.k8s_active_upgrade(
                self._current_versions["workload"], self._current_versions["charm"]
            )

        return UpgradeStatuses.k8s_active_upgrade(
            self._current_versions["workload"],
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
    def partition(self) -> int:
        """Specifies which units should upgrade.

        Unit numbers >= partition should upgrade
        Unit numbers < partition should not upgrade

        https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#partitions

        For Kubernetes, unit numbers are guaranteed to be sequential.
        """
        return self.k8s_manager.get_partition()

    @partition.setter
    def partition(self, value: int) -> None:
        """Sets the partition number."""
        self.k8s_manager.set_partition(value)

    @property
    def upgrade_resumed(self) -> bool:
        """Whether user has resumed upgrade with Juju action."""
        return self.partition < unit_number(self.state.units_upgrade_peer_data[0])

    def _determine_partition(
        self, units: list[UnitUpgradePeerData], from_event: bool, force: bool
    ) -> int:
        """Determine the new partition to use.

        We get the current state of each unit, and according to `action_event`,
        `force` and the state, we decide the new value of the partition.
        A specific case:
         * If we don't have action event and the upgrade_order_index is 1, we
         return because it means we're waiting for the resume-refresh/force-refresh event to run.
        """
        if not self.state.upgrade_in_progress:
            return 0
        logger.debug(f"{self.state.unit_upgrade_peer_data.relation_data=}")
        for upgrade_order_index, unit in enumerate(units):
            # Note: upgrade_order_index != unit number
            state = unit.unit_state
            if (
                not force and state is not UnitState.HEALTHY
            ) or self.state.unit_workload_container_versions[
                unit.name
            ] != self.state.app_workload_container_version:
                if self.dependent.name == CharmKind.MONGOD:
                    if not from_event and upgrade_order_index == 1:
                        # User confirmation needed to resume upgrade (i.e. upgrade second unit)
                        return unit_number(units[0])
                return unit_number(unit)
        return 0

    def reconcile_partition(self, *, from_event: bool = False, force: bool = False) -> str | None:  # noqa: C901
        """If ready, lower partition to upgrade next unit.

        If upgrade is not in progress, set partition to 0. (If a unit receives a stop event, it may
        raise the partition even if an upgrade is not in progress.)

        Automatically upgrades next unit if all upgraded units are healthy—except if only one unit
        has upgraded (need manual user confirmation [via Juju action] to upgrade next unit)

        Handle Juju action to:
        - confirm first upgraded unit is healthy and resume upgrade
        - force upgrade of next unit if 1 or more upgraded units are unhealthy
        """
        message: str | None = None
        if self.dependent.name == CharmKind.MONGOD:
            force = from_event and force
        else:
            force = from_event

        units = self.state.units_upgrade_peer_data

        partition_ = self._determine_partition(
            units,
            from_event,
            force,
        )
        logger.debug(f"{self.partition=}, {partition_=}")
        # Only lower the partition—do not raise it.
        # If this method is called during the action event and then called during another event a
        # few seconds later, `determine_partition()` could return a lower number during the action
        # and then a higher number a few seconds later.
        # This can cause the unit to hang.
        # Example: If partition is lowered to 1, unit 1 begins to upgrade, and partition is set to
        # 2 right away, the unit/Juju agent will hang
        # Details: https://chat.charmhub.io/charmhub/pl/on8rd538ufn4idgod139skkbfr
        # This does not address the situation where another unit > 1 restarts and sets the
        # partition during the `stop` event, but that is unlikely to occur in the small time window
        # that causes the unit to hang.
        if from_event:
            assert len(units) >= 2
            if partition_ > unit_number(units[1]):
                message = "Highest number unit is unhealthy. Refresh will not resume."
                raise ActionFailedError(message)
            if force:
                # If a unit was unhealthy and the upgrade was forced, only
                # the next unit will upgrade. As long as 1 or more units
                # are unhealthy, the upgrade will need to be forced for
                # each unit.

                # Include "Attempting to" because (on Kubernetes) we only
                # control the partition, not which units upgrade.
                # Kubernetes may not upgrade a unit even if the partition
                # allows it (e.g. if the charm container of a higher unit
                # is not ready). This is also applicable `if not force`,
                # but is unlikely to happen since all units are healthy `if
                # not force`.
                message = f"Attempting to refresh unit {partition_}."
            else:
                message = f"Refresh resumed. Unit {partition_} is refreshing next."
        if partition_ < self.partition:
            self.partition = partition_
            logger.debug(
                f"Lowered partition to {partition_} {from_event=} {force=} {self.state.upgrade_in_progress=}"
            )
        return message
