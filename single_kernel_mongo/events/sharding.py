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
    SecretChangedEvent,
)
from ops.framework import Object
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import TrustStoreFiles
from single_kernel_mongo.config.statuses import ShardStatuses
from single_kernel_mongo.exceptions import (
    BalancerNotEnabledError,
    DeferrableFailedHookChecksError,
    FailedToUpdateCredentialsError,
    NonDeferrableFailedHookChecksError,
    NotDrainedError,
    ShardAuthError,
    WaitingForCertificatesError,
    WaitingForSecretsError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseCreatedEvent,
    DatabaseProviderEventHandlers,
    DatabaseRequestedEvent,
    DatabaseRequirerEventHandlers,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log
from single_kernel_mongo.utils.mongo_connection import NotReadyError

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


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
            self.database_provider_events.on.database_requested, self._on_database_requested
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
            self.manager.reconcile_shards_for_relation(event.relation, is_leaving)
        except (
            DeferrableFailedHookChecksError,
            ServerSelectionTimeoutError,
            ShardAuthError,
            NotDrainedError,
            NotReadyError,
            BalancerNotEnabledError,
            PyMongoError,
            OperationFailure,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _on_database_requested(self, event: DatabaseRequestedEvent):
        """Relation joined events."""
        try:
            self.manager.prepare_sharding_config(event.relation)
        except DeferrableFailedHookChecksError as e:
            logger.info("Skipping database requested event: hook checks did not pass.")
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
            self.charm.on[self.relation_name].relation_changed, self._on_database_created
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
        """Prepare to add the shard."""
        self.manager.prepare_to_add_shard()

    def _on_database_created(self, event: DatabaseCreatedEvent):
        """When we receive a database created event, we synchronize the cluster secrets locally."""
        try:
            self.manager.synchronise_cluster_secrets(event.relation)
        except (
            DeferrableFailedHookChecksError,
            WaitingForSecretsError,
            WaitingForCertificatesError,
            NotReadyError,
            FailedToUpdateCredentialsError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _handle_changed_secrets(self, event: SecretChangedEvent):
        """SecretChanged event handler, which is used to propagate the updated passwords."""
        try:
            self.manager.handle_secret_changed(event.secret.label or "")
        except (NotReadyError, FailedToUpdateCredentialsError):
            event.defer()
        except WaitingForSecretsError:
            logger.info("Missing secrets, ignoring")

    def _on_relation_broken(self, event: RelationBrokenEvent):
        """On relation broken, we drain the shard before allowing it to disconnect."""
        try:
            self.manager.drain_shard_from_cluster(event.relation)
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            self.manager.state.statuses.set(
                ShardStatuses.MISSING_CONF_SERVER_REL.value,
                scope="unit",
                component=self.manager.name,
            )
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
