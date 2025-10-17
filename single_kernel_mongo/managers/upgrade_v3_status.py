"""Manager for upgrades, only to convert statuses to advanced statuses."""

import logging

import charm_refresh
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, StatusBase, WaitingStatus

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.statuses import CharmStatuses, UpgradeStatuses
from single_kernel_mongo.core.workload import WorkloadBase
from single_kernel_mongo.exceptions import DeployedWithoutTrustError
from single_kernel_mongo.state.charm_state import CharmState

logger = logging.getLogger()


class MongoDBUpgradesStatusManager(ManagerStatusProtocol):
    """Manage upgrades statuses but nothing else."""

    name: str = "upgrades"

    def __init__(
        self, state: CharmState, workload: WorkloadBase, refresh: charm_refresh.Common | None
    ) -> None:
        self.state = state
        self.workload = workload
        self.refresh = refresh

        if self.state.substrate == Substrates.K8S:
            try:
                self.state.k8s_manager.get_pod()
            except DeployedWithoutTrustError:
                self.state.statuses.add(
                    CharmStatuses.DEPLOYED_WITHOUT_TRUST.value, scope="unit", component=self.name
                )
                if self.charm.unit.is_leader():
                    self.state.statuses.add(
                        CharmStatuses.DEPLOYED_WITHOUT_TRUST.value, scope="app", component=self.name
                    )

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Compute the upgrades-relevant statuses.

        Advanced Statuses defines the status priority order per component. It is not possible to
        have some statuses of a component more important and some other statuses of the same
        component less important.

        While `refresh.[app|unit]_status_higher_priority` must be of higher priority than any other
        status, `refresh.unit_status_lower_priority()` should only be set it if there is no other
        status at all. We achieve this by setting the field `approved_critical_component` to True
        if the refresh_status is of higher priority than any other status.

        For more information: see https://canonical-charm-refresh.readthedocs-hosted.com/latest/add-to-charm/status/
        """
        status_list: list[StatusObject] = []

        # Check if Juju app was deployed with `--trust` (needed to patch StatefulSet partition)
        if self.state.substrate == Substrates.K8S:
            try:
                self.state.k8s_manager.get_pod()
            except DeployedWithoutTrustError:
                return [CharmStatuses.DEPLOYED_WITHOUT_TRUST.value]

        if not self.refresh:
            return [UpgradeStatuses.ACTIVE_IDLE.value]

        if scope == "app" and (refresh_app_status := self.refresh.app_status_higher_priority):
            app_status = self._convert_ops_status_to_advanced_status(refresh_app_status)
            status_list.append(app_status)
            return status_list

        if self.refresh.in_progress and not self.refresh.next_unit_allowed_to_refresh:
            if not self.dependent.mongo_manager.mongod_ready():
                status_list.append(UpgradeStatuses.HEALTH_CHECK_FAILED.value)
            else:
                status_list.append(UpgradeStatuses.CLUSTER_CHECK_FAILED.value)

        if refresh_unit_status := self.refresh.unit_status_higher_priority:
            unit_status = self._convert_ops_status_to_advanced_status(refresh_unit_status)
            status_list.append(unit_status)

        if refresh_lower_unit_status := self.refresh.unit_status_lower_priority(
            workload_is_running=self.workload.active()
        ):
            lower_unit_status = self._convert_ops_status_to_advanced_status(
                refresh_lower_unit_status, critical=False
            )
            status_list.append(lower_unit_status)

        return status_list if status_list else [CharmStatuses.ACTIVE_IDLE.value]

    @staticmethod
    def _convert_ops_status_to_advanced_status(
        ops_status: StatusBase, critical: bool = True
    ) -> StatusObject:
        """Convert an ops status into an advanced statuses StatusObject.

        Args:
            ops_status (ops.StatusBase): the status to convert into an advanced status
            critical (bool): whether the returned StatusObject should have the field
                            `approved_critical_component` set to True or False
        """
        # this code may not be very concise, focus is on readability
        match ops_status:
            case BlockedStatus():
                return StatusObject(
                    status="blocked",
                    message=ops_status.message,
                    approved_critical_component=critical,
                )

            case MaintenanceStatus():
                return StatusObject(
                    status="maintenance",
                    message=ops_status.message,
                    approved_critical_component=critical,
                )

            case WaitingStatus():
                return StatusObject(
                    status="waiting",
                    message=ops_status.message,
                    approved_critical_component=critical,
                )

            case ActiveStatus():
                return StatusObject(status="active", message=ops_status.message)

            case _:
                raise ValueError(f"Unknown status type: {ops_status.name}: {ops_status.message}")
