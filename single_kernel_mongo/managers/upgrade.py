# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling MongoDB in-place upgrades."""

from __future__ import annotations

import logging
from typing import Generic, TypeVar

from ops import ActionEvent
from ops.model import ActiveStatus
from tenacity import RetryError

from single_kernel_mongo.config.literals import (
    FEATURE_VERSION_6,
    UNHEALTHY_UPGRADE,
    WAITING_POST_UPGRADE_STATUS,
    CharmKind,
    Substrates,
    UnitState,
)
from single_kernel_mongo.core.abstract_upgrades import GenericMongoDBUpgradeManager, UpgradeActions
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    ActionFailedError,
    BalancerNotEnabledError,
    ContainerNotReadyError,
    DeferrableError,
    PrecheckFailedError,
    UnhealthyUpgradeError,
)
from single_kernel_mongo.utils.mongo_connection import MongoConnection

T = TypeVar("T", bound=OperatorProtocol)

logger = logging.getLogger()
ROLLBACK_INSTRUCTIONS = "To rollback, `juju refresh` to the previous revision"


class MongoUpgradeManager(Generic[T], GenericMongoDBUpgradeManager[T]):
    """Upgrade manager for Mongo upgrades."""

    def on_upgrade_charm(self):
        """Upgrade event handler.

        On K8S, during an upgrade event, it will set the version in all relations,
        replan the container and process the upgrade statuses. If the upgrade
        is compatible, it will end up emitting a post upgrade event that
        verifies the health of the cluster.
        On VM, during an upgrade event, it will call the reconcile upgrade
        after setting the version across all relations.
        """
        if self.dependent.substrate == Substrates.VM:
            self._on_vm_upgrade()
        else:
            self._on_kubernetes_upgrade()

    def _on_kubernetes_upgrade(self) -> None:
        assert self._upgrade
        if self.charm.unit.is_leader() and self.dependent.name == CharmKind.MONGOD:
            self.dependent.cross_app_version_checker.set_version_across_all_relations()  # type: ignore
        try:
            # Start services.
            self.dependent.on_install()
            self.dependent._configure_workloads()
            if self.dependent.name == CharmKind.MONGOS:
                if keyfile := self.state.cluster.keyfile:
                    self.dependent.update_keyfile(keyfile)  # type: ignore
                    self.dependent.start_charm_services()
            else:
                self.dependent.start_charm_services()
                self.state.unit_upgrade_peer_data.current_revision = (
                    self.dependent.cross_app_version_checker.version  # type: ignore
                )
        except ContainerNotReadyError:
            self.charm.status_manager.set_and_share_status(UNHEALTHY_UPGRADE)
            self._reconcile_upgrade(during_upgrade=True)
            raise DeferrableError

        self.charm.status_manager.set_and_share_status(WAITING_POST_UPGRADE_STATUS)

        self._reconcile_upgrade(during_upgrade=True)

        if self._upgrade.is_compatible:
            # Post upgrade event verifies the success of the upgrade.
            self.dependent.upgrade_events.post_app_upgrade_event.emit()

    def _on_vm_upgrade(self):
        if not self.state.upgrade_in_progress and self.dependent.name == CharmKind.MONGOD:
            self.state.unit_upgrade_peer_data.current_revision = (
                self.dependent.cross_app_version_checker.version  # type: ignore
            )
        if self.charm.unit.is_leader():
            if not self.state.upgrade_in_progress:
                logger.info("Charm refreshed. MongoDB version unchanged")
            if self.dependent.name == CharmKind.MONGOD:
                self.state.app_upgrade_peer_data.upgrade_resumed = False
                self.dependent.cross_app_version_checker.set_version_across_all_relations()  # type: ignore

        if self.dependent.name == CharmKind.MONGOD and self.charm.unit.is_leader():
            # MONGODB: Only call `_reconcile_upgrade` on leader unit to
            # avoid race conditions with `upgrade_resumed`
            self._reconcile_upgrade()
        elif self.dependent.name == CharmKind.MONGOS:
            # All units call it on mongos
            self._reconcile_upgrade()

    def on_pre_upgrade_check_action(self) -> None:
        """Pre upgrade checks."""
        if not self.charm.unit.is_leader():
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader {UpgradeActions.PRECHECK_ACTION_NAME.value}`)"
            raise ActionFailedError(message)
        if not self._upgrade:
            message = "No upgrade relation found."
            raise ActionFailedError(message)
        if not self._upgrade or self.state.upgrade_in_progress:
            message = "Refresh already in progress"
            raise ActionFailedError(message)
        try:
            self._upgrade.pre_upgrade_check()
        except PrecheckFailedError as exception:
            message = (
                f"Charm is not ready for refresh. Pre-refresh check failed: {exception.message}"
            )
            raise ActionFailedError(message)

    def on_resume_upgrade_action(self, force: bool = False) -> str | None:
        """Resume upgrade action handler."""
        if not self.charm.unit.is_leader():
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader {UpgradeActions.RESUME_ACTION_NAME.value}`)"
            raise ActionFailedError(message)
        if not self._upgrade or not self.state.upgrade_in_progress:
            message = "No refresh in progress"
            raise ActionFailedError(message)
        return self._upgrade.reconcile_partition(from_event=True, force=force)

    def on_force_upgrade_action(self: MongoUpgradeManager[T], event: ActionEvent) -> str:
        """Force upgrade action handler."""
        if not self._upgrade or not self.state.upgrade_in_progress:
            message = "No refresh in progress"
            raise ActionFailedError(message)

        if self.substrate == Substrates.VM and self._upgrade.unit_state != UnitState.OUTDATED:
            message = "Unit already refreshed"
            raise ActionFailedError(message)

        if self.substrate == Substrates.K8S and not self.charm.unit.is_leader():
            message = f"Must run action on leader unit. (e.g. `juju run {self.charm.app.name}/leader force-refresh-start`)"
            raise ActionFailedError(message)

        if self.dependent.name == CharmKind.MONGOD and not self._upgrade.upgrade_resumed:
            message = f"Run `juju run {self.charm.app.name}/leader {UpgradeActions.RESUME_ACTION_NAME.value}` before trying to force refresh"
            raise ActionFailedError(message)

        logger.debug("Forcing refresh")
        event.log(f"Forcefully refreshing {self.charm.unit.name}")
        if self.substrate == Substrates.VM:
            self._upgrade.upgrade_unit(dependent=self.dependent)  # type: ignore
        else:
            self._upgrade.reconcile_partition(from_event=True, force=True)
        logger.debug("Forced refresh")
        return f"Forcefully refreshed {self.charm.unit.name}"


class MongoDBUpgradeManager(MongoUpgradeManager[T]):
    """MongoDB specific upgrade mechanism."""

    def run_post_app_upgrade_task(self):
        """Runs the post upgrade check to verify that the cluster is healthy.

        By deferring before setting unit state to HEALTHY, the user will either:
            1. have to wait for the unit to resolve itself.
            2. have to run the force-refresh-start action (to upgrade the next unit).
        """
        logger.debug("Running post refresh checks to verify cluster is not broken after refresh")
        self.run_post_upgrade_checks(finished_whole_cluster=False)

        if self._upgrade.unit_state != UnitState.HEALTHY:
            return

        logger.debug("Cluster is healthy after refreshing unit %s", self.charm.unit.name)

        # Leader of config-server must wait for all shards to be upgraded before finalising the
        # upgrade.
        if not self.charm.unit.is_leader() or not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return

        self.dependent.upgrade_events.post_cluster_upgrade_event.emit()

    def run_post_cluster_upgrade_task(self) -> None:
        """Waits for entire cluster to be upgraded before enabling the balancer."""
        # Leader of config-server must wait for all shards to be upgraded before finalising the
        # upgrade.
        if not self.charm.unit.is_leader() or not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return

        # We can because we now we are a config server.
        if not self.dependent.cross_app_version_checker.are_related_apps_valid():  # type: ignore
            raise DeferrableError("Waiting to finalise refresh, one or more shards need refresh.")

        logger.debug(
            "Entire cluster has been refreshed, checking health of the cluster and enabling balancer."
        )
        self.run_post_upgrade_checks(finished_whole_cluster=True)

        try:
            with MongoConnection(self.state.mongos_config) as mongos:
                mongos.start_and_wait_for_balancer()
        except BalancerNotEnabledError:
            raise DeferrableError(
                "Need more time to enable the balancer after finishing the refresh. Deferring event."
            )

        self.set_mongos_feature_compatibilty_version(FEATURE_VERSION_6)

    # END: Event handlers

    # BEGIN: Helpers
    def run_post_upgrade_checks(self, finished_whole_cluster: bool = False) -> None:
        """Runs post-upgrade checks for after a shard/config-server/replset/cluster upgrade."""
        assert self._upgrade
        upgrade_type = "unit." if not finished_whole_cluster else "sharded cluster"
        try:
            self.wait_for_cluster_healthy()  # type: ignore
        except RetryError:
            logger.error(
                "Cluster is not healthy after refreshing %s. Will retry next juju event.",
                upgrade_type,
            )
            raise UnhealthyUpgradeError

        if not self.is_cluster_able_to_read_write():  # type: ignore
            logger.error(
                "Cluster is not healthy after refreshing %s, writes not propagated throughout cluster. Deferring post refresh check.",
                upgrade_type,
            )
            raise UnhealthyUpgradeError

        if self.charm.unit.status == UNHEALTHY_UPGRADE:
            self.charm.status_manager.set_and_share_status(ActiveStatus())

        self._upgrade.unit_state = UnitState.HEALTHY


class MongosUpgradeManager(MongoUpgradeManager[T]):
    """Mongos specific upgrade mechanism."""

    def run_post_app_upgrade_task(self):
        """Runs the post upgrade check to verify that the mongos router is healthy."""
        logger.debug("Running post refresh checks to verify monogs is not broken after refresh")
        if not self.state.db_initialised:
            self._upgrade.unit_state = UnitState.HEALTHY
            return

        self.run_post_upgrade_checks()

        if self._upgrade.unit_state != UnitState.HEALTHY:
            return

        logger.debug("Cluster is healthy after refreshing unit %s", self.charm.unit.name)

        # Leader of config-server must wait for all shards to be upgraded before finalising the
        # upgrade.
        if not self.charm.unit.is_leader() or not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            return

        self.dependent.upgrade_events.post_cluster_upgrade_event.emit()

    # Unused parameter only present for typing.
    def run_post_upgrade_checks(self, finished_whole_cluster: bool = False) -> None:
        """Runs post-upgrade checks for after a shard/config-server/replset/cluster upgrade."""
        assert self._upgrade
        if not self.dependent.is_mongos_running():  # type: ignore
            raise DeferrableError(
                "Waiting for mongos router to be ready before finalising refresh."
            )

        if not self.is_mongos_able_to_read_write():  # type: ignore
            self.charm.status_manager.set_and_share_status(UNHEALTHY_UPGRADE)
            logger.info(ROLLBACK_INSTRUCTIONS)
            raise DeferrableError("mongos is not able to read/write after refresh.")

        if self.charm.unit.status == UNHEALTHY_UPGRADE:
            self.charm.status_manager.to_active()

        logger.debug("refresh of unit succeeded.")
        self._upgrade.unit_state = UnitState.HEALTHY
