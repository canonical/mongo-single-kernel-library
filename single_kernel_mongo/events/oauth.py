#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handlers for the OAuth relation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from charmlibs.interfaces.oauth import (
    InvalidClientConfigEvent,
    OAuthInfoChangedEvent,
    OAuthInfoRemovedEvent,
)
from charmlibs.rollingops import RollingOpsNoRelationError
from ops.charm import RelationBrokenEvent, RelationChangedEvent, RelationEvent
from ops.framework import Object

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import OAuthStatuses
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger(__name__)


class OAuthEventHandler(Object):
    """Dispatch OAuth relation events to the OAuth manager."""

    def __init__(self, dependent: OperatorProtocol):
        super().__init__(parent=dependent, key=ExternalRequirerRelations.OAUTH.value)
        self.dependent = dependent
        self.charm = dependent.charm
        self.manager = dependent.oauth_manager
        # Mongos receives its issuer through cluster events and has no OAuth endpoint.
        if ExternalRequirerRelations.OAUTH.value not in self.charm.meta.requires:
            return
        relation_events = self.charm.on[ExternalRequirerRelations.OAUTH.value]
        self.framework.observe(relation_events.relation_created, self._on_relation_status_changed)
        self.framework.observe(relation_events.relation_changed, self._on_relation_status_changed)
        self.framework.observe(relation_events.relation_broken, self._on_relation_status_changed)
        self.framework.observe(
            self.manager.oauth_requirer.on.oauth_info_changed, self._on_oauth_info_changed
        )
        self.framework.observe(
            self.manager.oauth_requirer.on.oauth_info_removed, self._on_oauth_info_removed
        )
        self.framework.observe(
            self.manager.oauth_requirer.on.invalid_client_config, self._on_invalid_client_config
        )

        self.framework.observe(
            self.charm.on[self.charm.peer_rel_name.value].relation_changed,
            self._on_peer_relation_changed,
        )

    def _on_relation_status_changed(self, event: RelationEvent) -> None:
        """Set or clear the blocked status as the OAuth relation changes."""
        status = OAuthStatuses.INVALID_OAUTH_REL_ON_SHARD.value
        if isinstance(event, RelationBrokenEvent):
            self.manager.state.statuses.delete(status, scope="unit", component=self.manager.name)
            return
        if status in self.manager.get_statuses(scope="unit", recompute=True):
            self.manager.state.statuses.add(status, scope="unit", component=self.manager.name)
        else:
            self.manager.state.statuses.delete(status, scope="unit", component=self.manager.name)

    def _on_peer_relation_changed(self, event: RelationChangedEvent) -> None:
        """Reconcile the shared issuer on follower units."""
        if self.charm.unit.is_leader():
            return
        try:
            self.manager.restart_when_ready()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, "oauth-peer-changed", str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_changed(self, event: OAuthInfoChangedEvent) -> None:
        """Handle available or updated provider information."""
        try:
            self.manager.configure()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, "oauth-info-changed", str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_removed(self, event: OAuthInfoRemovedEvent) -> None:
        """Handle removal of provider information."""
        try:
            self.manager.remove()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, "oauth-info-removed", str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_invalid_client_config(self, event: InvalidClientConfigEvent) -> None:
        """Report rejected OAuth client configuration."""
        logger.error("Invalid OAuth client configuration: %s", event.error)
