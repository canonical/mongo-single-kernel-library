#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling database events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops import RelationBrokenEvent
from ops.charm import RelationChangedEvent, RelationEvent
from ops.framework import Object
from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DatabaseRequestedHasNotRunYetError,
    FailedToGetHostsError,
    UpgradeInProgressError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import DatabaseProvides
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger()


class DatabaseEventsHandler(Object):
    """Manager for handling database events."""

    def __init__(self, dependent: OperatorProtocol, relation_name: RelationNames):
        super().__init__(parent=dependent, key=relation_name.value)
        self.dependent = dependent
        self.manager = dependent.mongo_manager
        self.charm = dependent.charm
        self.relation_name = relation_name
        self.database_provides = DatabaseProvides(self.charm, relation_name=self.relation_name)

        self.framework.observe(
            self.charm.on[relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_broken, self._on_relation_event
        )
        self.framework.observe(
            self.charm.on[relation_name].relation_changed, self._on_relation_event
        )
        self.framework.observe(
            self.database_provides.on.database_requested, self._on_relation_event
        )

    def _on_relation_event(self, event: RelationEvent):
        """Handle relation joined events.

        When relations join, change, or depart, the :class:`MongoDBClientRelation`
        creates or drops MongoDB users and sets credentials into relation
        data. As a result, related charm gets credentials for accessing the
        MongoDB database.
        """
        relation_departing = False
        relation_changed = False
        if (
            self.dependent.substrate == Substrates.VM
            and self.relation_name == RelationNames.MONGOS_PROXY
        ):
            self.dependent.update_proxy_connection(event.relation)  # type: ignore[attr-defined]
            return

        try:
            if not self.pass_hook_checks(event):
                logger.info(f"Skipping {type(event)}: Hook checks did not pass")
                return
        except UpgradeInProgressError:
            logger.warning(
                "Adding relations is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            logger.info(f"Skipping {type(event)}: Hook checks did not pass")
            event.defer()
            return

        if isinstance(event, RelationBrokenEvent):
            relation_departing = True
            if not self.dependent.state.has_departed_run(event.relation.id):
                defer_event_with_info_log(
                    logger,
                    event,
                    "relation broken",
                    "must wait for relation departed hook to decide if relation should be removed.",
                )
                return
            if self.dependent.state.is_scaling_down(event.relation.id):
                logger.info(
                    "Relation broken event due to scale down, do not proceed to remove users."
                )
                return
            logger.info("Relation broken event due to relation removal, proceed to remove user.")
        if isinstance(event, RelationChangedEvent):
            relation_changed = True
            logger.info("Relation changed event, updating relation data.")

        try:
            self.manager.reconcile_mongo_users_and_dbs(
                event.relation, relation_departing, relation_changed
            )
        except (PyMongoError, FailedToGetHostsError, DatabaseRequestedHasNotRunYetError) as e:
            # Failed to get hosts error is unique to mongos-k8s charm. In other charms we do not
            # foresee issues to retrieve hosts. However in external mongos-k8s, the leader can
            # attempt to retrieve hosts while non-leader units are still enabling node port
            # resulting in an exception.
            logger.error("Deferring _on_relation_event since: error=%r", e)
            event.defer()
            return

    # Checks:
    def pass_hook_checks(self, event: RelationEvent) -> bool:
        """Runs the pre-hooks checks for MongoDBProvider, returns True if all pass."""
        # First, ensure that the relation is valid, useless to do anything else otherwise
        if not self.dependent.state.is_role(MongoDBRoles.MONGOS) and (
            status := self.dependent.get_relation_feasible_status(self.relation_name)
        ):
            self.dependent.state.statuses.add(status, scope="unit", component=self.dependent.name)
            return False

        # We shouldn't try to create or update users if the database is not
        # initialised. We will create users as part of initialisation.
        if not self.dependent.state.db_initialised:
            return False

        if not self.charm.unit.is_leader():
            return False

        if self.dependent.state.upgrade_in_progress:
            logger.warning(
                "Adding relations is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            raise UpgradeInProgressError

        return True
