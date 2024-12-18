#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handlers for cluster relation: mongos and config server events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import RelationBrokenEvent, RelationChangedEvent, RelationCreatedEvent
from ops.framework import Object

from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseCreatedEvent,
    DatabaseProviderEventHandlers,
    DatabaseRequestedEvent,
    DatabaseRequirerEventHandlers,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator
    from single_kernel_mongo.managers.mongos_operator import MongosOperator

logger = logging.getLogger(__name__)


class ClusterConfigServerEventHandler(Object):
    """Event Handler for managing config server side events."""

    def __init__(self, dependent: MongoDBOperator):
        self.dependent = dependent
        self.charm = self.dependent.charm
        self.manager = self.dependent.cluster_manager
        self.relation_name = self.manager.relation_name
        super().__init__(parent=self.manager, key=dependent.cluster_manager.relation_name)

        self.database_provider_events = DatabaseProviderEventHandlers(
            self.charm, self.manager.data_interface
        )

        self.framework.observe(
            self.database_provider_events.on.database_requested, self._on_database_requested
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken, self._on_relation_broken_event
        )

    def _on_database_requested(self, event: DatabaseRequestedEvent):
        """Relation joined events."""
        try:
            self.manager.on_database_requested(event.relation)
        except DeferrableFailedHookChecksError as e:
            logger.info("Skipping database requested event: hook checks did not pass.")
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_event(self, event: RelationChangedEvent):
        """Handle relation changed and relation broken events."""
        try:
            self.manager.on_relation_changed(event.relation)
            self.charm.status_manager.process_and_share_statuses()
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_broken_event(self, event: RelationBrokenEvent):
        try:
            self.manager.on_relation_broken(event.relation)
            self.charm.status_manager.process_and_share_statuses()
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")


class ClusterMongosEventHandler(Object):
    """Event Handler for managing config server side events."""

    def __init__(self, dependent: MongosOperator):
        self.dependent = dependent
        self.charm = self.dependent.charm
        self.manager = self.dependent.cluster_manager
        self.relation_name = self.manager.relation_name
        super().__init__(parent=self.manager, key=dependent.cluster_manager.relation_name)

        self.database_requirer_events = DatabaseRequirerEventHandlers(
            self.charm, self.manager.data_interface
        )

        self.framework.observe(
            self.charm.on[self.relation_name].relation_created,
            self._on_relation_created,
        )
        self.framework.observe(
            self.database_requirer_events.on.database_created, self._on_database_created
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_changed
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    def _on_relation_created(self, event: RelationCreatedEvent):
        self.manager.relation_created()

    def _on_database_created(self, event: DatabaseCreatedEvent):
        try:
            self.manager.on_database_created(event.username, event.password)
        except (
            DeferrableFailedHookChecksError,
            WaitingForSecretsError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_changed(self, event: RelationChangedEvent):
        try:
            self.manager.relation_changed()
        except (
            DeferrableError,
            DeferrableFailedHookChecksError,
            WaitingForSecretsError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_broken(self, event: RelationBrokenEvent):
        try:
            self.manager.relation_broken(event.relation)
        except (DeferrableFailedHookChecksError, DeferrableError) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
