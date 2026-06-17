#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for sharding and config server events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from charmlibs.rollingops import RollingOpsNoRelationError
from ops.charm import (
    RelationBrokenEvent,
    RelationChangedEvent,
    RelationCreatedEvent,
    SecretChangedEvent,
)
from ops.framework import Object
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import TrustStoreFiles
from single_kernel_mongo.config.statuses import ConfigServerStatuses, ShardStatuses
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
        super().__init__(
            parent=self.manager, key=dependent.config_server_manager.relation_name.value
        )

        self.database_provider_events = DatabaseProviderEventHandlers(
            self.charm, self.manager.data_interface
        )
        self.framework.observe(
            self.database_provider_events.on.database_requested, self._on_database_requested
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_changed, self._on_relation_event
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_broken, self._on_relation_event
        )

    def _on_relation_event(self, event: RelationChangedEvent):
        """Handle relation changed and relation broken events."""
        is_leaving = isinstance(event, RelationBrokenEvent)
        try:
            self.manager.state.statuses.delete(
                ConfigServerStatuses.MISSING_CONF_SERVER_REL.value,
                scope="unit",
                component=self.manager.name,
            )
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
            self.manager.state.statuses.add(
                ConfigServerStatuses.MISSING_CONF_SERVER_REL.value,
                scope="unit",
                component=self.manager.name,
            )
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
            self.charm.on[self.relation_name.value].relation_created, self._on_relation_created
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_changed, self._store_certificates
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_changed, self._synchronize_passwords
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_changed, self._synchronize_member_auth
        )
        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_changed, self._handle_pbm_restarts
        )

        self.framework.observe(
            getattr(self.charm.on, "secret_changed"), self._handle_changed_secrets
        )

        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_departed,
            self.dependent.check_relation_broken_or_scale_down,
        )

        self.framework.observe(
            self.charm.on[self.relation_name.value].relation_broken, self._on_relation_broken
        )

    def _on_relation_created(self, event: RelationCreatedEvent):
        """Prepare to add the shard."""
        self.manager.prepare_to_add_shard()

    def _store_certificates(self, event: RelationChangedEvent):
        """When we receive certificates, we want to store them immediately on the file system."""
        try:
            self.manager.update_config_server_certs()
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _synchronize_passwords(self, event: RelationChangedEvent):
        """Upon receiving the operator and backup user passwords, we want to update them locally."""
        try:
            self.manager.synchronize_user_passwords(event.relation)
        except (
            DeferrableFailedHookChecksError,
            FailedToUpdateCredentialsError,
            NotReadyError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _synchronize_member_auth(self, event: RelationChangedEvent):
        """When we receive a new keyfile /TLS CA we want to restart mongodb with the right files."""
        try:
            self.manager.synchronize_member_auth(event.relation)
        except (
            DeferrableFailedHookChecksError,
            NotReadyError,
            WaitingForSecretsError,
            FailedToUpdateCredentialsError,
            RollingOpsNoRelationError,
            WaitingForCertificatesError,
        ) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")

    def _handle_pbm_restarts(self, event: RelationChangedEvent):
        """If everything is working and we're added to the cluster, we want to finally start PBM."""
        try:
            self.manager.handle_pbm(event.relation)
        except (
            DeferrableFailedHookChecksError,
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
        except (NotReadyError, FailedToUpdateCredentialsError, DeferrableFailedHookChecksError):
            event.defer()
        except NonDeferrableFailedHookChecksError as e:
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
        except WaitingForSecretsError:
            logger.info("Missing secrets, ignoring")

    def _on_relation_broken(self, event: RelationBrokenEvent):
        """On relation broken, we drain the shard before allowing it to disconnect."""
        try:
            self.manager.drain_shard_from_cluster(event.relation)
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as e:
            defer_event_with_info_log(logger, event, str(type(event)), str(e))
            return
        except NonDeferrableFailedHookChecksError as e:
            self.manager.state.statuses.set(
                ShardStatuses.MISSING_CONF_SERVER_REL.value,
                scope="unit",
                component=self.manager.name,
            )
            self.dependent.remove_ca_cert_from_trust_store(TrustStoreFiles.PBM)
            logger.info(f"Skipping {str(type(event))}: {str(e)}")
            return

        self.manager.cleanup_cluster_id()
