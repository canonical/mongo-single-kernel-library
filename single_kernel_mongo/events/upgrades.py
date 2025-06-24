#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handler for upgrades."""

from __future__ import annotations

from logging import getLogger
from typing import TYPE_CHECKING

from ops.charm import ActionEvent, RelationCreatedEvent, UpgradeCharmEvent
from ops.framework import EventBase, EventSource, Object
from ops.model import ModelError

from single_kernel_mongo.config.literals import CharmKind
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import UpgradeStatuses
from single_kernel_mongo.core.abstract_upgrades import UpgradeActions
from single_kernel_mongo.exceptions import (
    ActionFailedError,
    DeferrableError,
    UnhealthyUpgradeError,
)
from single_kernel_mongo.managers.upgrade import ROLLBACK_INSTRUCTIONS
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol


logger = getLogger(__name__)


class _PostUpgradeCheckMongoDB(EventBase):
    """Run post upgrade check on MongoDB to verify that the cluster is healhty."""


class UpgradeEventHandler(Object):
    """Handler for upgrade related events."""

    post_app_upgrade_event = EventSource(_PostUpgradeCheckMongoDB)
    post_cluster_upgrade_event = EventSource(_PostUpgradeCheckMongoDB)

    def __init__(self, dependent: OperatorProtocol):
        self.dependent = dependent
        self.manager = self.dependent.upgrade_manager
        self.charm: AbstractMongoCharm = dependent.charm
        self.relation_name = RelationNames.UPGRADE_VERSION.value
        super().__init__(parent=dependent, key=self.relation_name)

        self.framework.observe(
            self.charm.on[UpgradeActions.PRECHECK_ACTION_NAME].action,
            self._on_pre_upgrade_check_action,
        )

        self.framework.observe(
            self.charm.on[self.relation_name].relation_created,
            self._on_upgrade_peer_relation_created,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._reconcile_upgrade
        )
        self.framework.observe(self.charm.on.upgrade_charm, self._on_upgrade_charm)
        self.framework.observe(
            self.charm.on[UpgradeActions.FORCE_REFRESH_START].action,
            self._on_force_upgrade_action,
        )
        self.framework.observe(self.post_app_upgrade_event, self._run_post_app_upgrade_task)

        if self.dependent.name == CharmKind.MONGOD:
            self.framework.observe(
                self.charm.on[UpgradeActions.RESUME_ACTION_NAME].action,
                self._on_resume_upgrade_action,
            )
            self.framework.observe(
                self.post_cluster_upgrade_event, self._run_post_cluster_upgrade_task
            )

    def _on_pre_upgrade_check_action(self, event: ActionEvent):
        try:
            self.manager.run_pre_refresh_checks()
            event.set_results({"result": "Charm is ready for refresh."})
        except ActionFailedError as e:
            logger.debug(f"Pre-refresh check failed: {e}")
            event.fail(str(e))

    def _on_upgrade_peer_relation_created(self, event: RelationCreatedEvent) -> None:
        # We have to catch a possible ModelError here.
        # TODO: remove try/catch when https://bugs.launchpad.net/juju/+bug/2093129 is fixed.
        try:
            self.manager.store_initial_revisions()
        except ModelError as err:
            logger.info(f"Deferring because of model error: {err}")
            event.defer()

    def _reconcile_upgrade(self, _) -> None:
        self.manager._reconcile_upgrade(during_upgrade=True)

    def _on_upgrade_charm(self, event: UpgradeCharmEvent) -> None:
        try:
            self.manager.upgrade_charm()
        except DeferrableError as err:
            logger.info(f"Deferring upgrade because of {err}")
            event.defer()

    def _on_resume_upgrade_action(self, event: ActionEvent) -> None:
        try:
            force: bool = event.params.get("force", False)
            message = self.manager.resume_upgrade(force=force)
            event.set_results({"result": message})
        except ActionFailedError as e:
            logger.debug(f"Resume refresh failed: {e}")
            event.fail(str(e))

    def _on_force_upgrade_action(self, event: ActionEvent) -> None:
        try:
            message = self.manager.force_upgrade(event)
            event.set_results({"result": message})
        except ActionFailedError as e:
            logger.debug(f"Resume refresh failed: {e}")
            event.fail(str(e))

    def _run_post_app_upgrade_task(self, event: _PostUpgradeCheckMongoDB) -> None:
        try:
            self.manager.run_post_app_upgrade_task()
        except DeferrableError as e:
            logger.info(ROLLBACK_INSTRUCTIONS)
            defer_event_with_info_log(logger, event, "post cluster upgrade checks", str(e))
        except UnhealthyUpgradeError:
            logger.info(ROLLBACK_INSTRUCTIONS)
            self.manager.state.statuses.add(
                UpgradeStatuses.UNHEALTHY_UPGRADE.value,
                scope="unit",
                component=self.manager.name,
            )
            event.defer()

    def _run_post_cluster_upgrade_task(self, event: _PostUpgradeCheckMongoDB) -> None:
        """Runs after a sharded cluster has been upgraded.

        It is necessary to check that the entire cluster is healthy.
        """
        try:
            self.manager.run_post_cluster_upgrade_task()
        except DeferrableError as e:
            logger.info(ROLLBACK_INSTRUCTIONS)
            defer_event_with_info_log(logger, event, "post cluster upgrade checks", str(e))
        except UnhealthyUpgradeError:
            logger.info(ROLLBACK_INSTRUCTIONS)
            self.manager.state.statuses.add(
                UpgradeStatuses.UNHEALTHY_UPGRADE.value,
                scope="unit",
                component=self.manager.name,
            )
            event.defer()
