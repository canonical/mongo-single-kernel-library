#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handlers for cluster relation: mongos and config server events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import RelationBrokenEvent, RelationChangedEvent, RelationCreatedEvent
from ops.framework import Object

from single_kernel_mongo.config.statuses import MongosStatuses
from single_kernel_mongo.exceptions import (
    DatabaseRequestedHasNotRunYetError,
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
    WorkloadServiceError,
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
            self.database_provider_events.on.database_requested,
            self._on_database_requested,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_changed, self._on_relation_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken,
            self._on_relation_broken_event,
        )

    def _on_database_requested(self, event: DatabaseRequestedEvent) -> None:
        """Relation joined events.

        Calls the manager to share the secrets with mongos charm.
        """
        try:
            self.manager.share_secret_to_mongos(event.relation)
        except DeferrableFailedHookChecksError as e:
            logger.info("Skipping database requested event: hook checks did not pass.")
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_event(self, event: RelationChangedEvent) -> None:
        """Handle relation changed events."""
        try:
            self.manager.update_keyfile_and_hosts_on_mongos(event.relation)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_broken_event(self, event: RelationBrokenEvent) -> None:
        """During a relation broken event, the manager will cleanup the users."""
        try:
            self.manager.cleanup_users(event.relation)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
        except DatabaseRequestedHasNotRunYetError:
            logger.info("Not cleaning users, relation was not established yet.")


class ClusterMongosEventHandler(Object):
    """Event Handler for managing mongos side events."""

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
            self.charm.on[self.relation_name].relation_changed,
            self._on_relation_changed,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken, self._on_relation_broken
        )

    def _on_relation_created(self, event: RelationCreatedEvent) -> None:
        """Relation created event handler."""
        self.manager.set_relation_created_status()

    def _on_database_created(self, event: DatabaseCreatedEvent) -> None:
        """Database Created event handler.

        When the database created event is received, we can proceed to store
        credentials and share it to the client applications.
        """
        try:
            self.manager.share_credentials_to_clients(event.username, event.password)
        except (DeferrableFailedHookChecksError,) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except (WaitingForSecretsError, NonDeferrableFailedHookChecksError) as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Relation changed event handler.

        The manager will update the mongos configuration and restart it.
        """
        try:
            self.manager.update_mongos_and_restart()
        except (
            DeferrableError,
            DeferrableFailedHookChecksError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except (NonDeferrableFailedHookChecksError, WaitingForSecretsError) as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
        except WaitingForSecretsError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
            self.dependent.state.statuses.add(
                MongosStatuses.WAITING_FOR_SECRETS.value,
                scope="unit",
                component=self.charm.name,
            )
        except WorkloadServiceError:
            # Some status was already set and a log was already displayed in
            # `restart_charm_services`
            return

    def _on_relation_broken(self, event: RelationBrokenEvent) -> None:
        """On relation broken event, we cleanup the users and mongos instance."""
        try:
            self.manager.remove_users_and_cleanup_mongo(event.relation)
        except (DeferrableFailedHookChecksError, DeferrableError) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
