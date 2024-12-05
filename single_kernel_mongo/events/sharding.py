#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for sharding and config server events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import (
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    RelationJoinedEvent,
    SecretChangedEvent,
)
from ops.framework import Object

from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    FailedToUpdateCredentialsError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderEventHandlers,
    DatabaseRequirerEventHandlers,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log
from single_kernel_mongo.utils.mongo_connection import NotReadyError

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)


class ConfigServerEventHandler(Object):
    """Event Handler for managing config server side events."""

    def __init__(self, dependent: MongoDBOperator):
        self.dependent = dependent
        self.charm = self.dependent.charm
        self.manager = self.dependent.config_server_manager
        self.relation_name = self.manager.relation_name
        super().__init__(parent=self.manager, key=dependent.config_server_manager.relation_name)

        self.database_provider_events = DatabaseProviderEventHandlers(
            self.charm, self.manager.data_interface
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_joined, self._on_relation_joined
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken, self._on_relation_event
        )

    def _on_relation_event(self, event: RelationChangedEvent):
        """Handle relation changed and relation broken events."""
        is_leaving = isinstance(event, RelationBrokenEvent)
        try:
            self.manager.on_relation_event(event.relation, is_leaving)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_joined(self, event: RelationJoinedEvent):
        """Relation joined events."""
        try:
            self.manager.on_relation_joined(event.relation)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")


class ShardEventHandler(Object):
    """Event Handler for managing shard side events."""

    def __init__(self, dependent: MongoDBOperator):
        self.dependent = dependent
        self.charm = self.dependent.charm
        self.manager = self.dependent.shard_manager
        self.relation_name = self.manager.relation_name
        super().__init__(parent=self.manager, key=dependent.shard_manager.relation_name)

        self.database_require_events = DatabaseRequirerEventHandlers(
            self.charm, self.manager.data_requirer
        )

        self.framework.observe(
            self.charm.on[self.relation_name].relation_created, self._on_relation_created
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_changed
        )

        self.framework.observe(
            getattr(self.charm.on, "secret_changed"), self._handle_changed_secrets
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

    def _on_relation_changed(self, event: RelationChangedEvent):
        try:
            self.manager.relation_changed(event.relation)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _handle_changed_secrets(self, event: SecretChangedEvent):
        try:
            self.manager.handle_secret_changed(event.secret.label or "")
        except (NotReadyError, FailedToUpdateCredentialsError):
            event.defer()
        except WaitingForSecretsError:
            logger.info("Missing secrets, ignoring")

    def _on_relation_broken(self, event: RelationBrokenEvent):
        try:
            self.manager.relation_broken(event.relation)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
