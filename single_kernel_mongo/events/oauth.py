#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handlers for the OAuth relation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from charmlibs.interfaces.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
)
from charmlibs.interfaces.oauth import (
    OAuthInfoChangedEvent,
    OAuthInfoRemovedEvent,
)
from charmlibs.rollingops import RollingOpsNoRelationError
from ops.charm import RelationChangedEvent
from ops.framework import Object

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = logging.getLogger(__name__)


class OAuthEventHandler(Object):
    """Dispatch OAuth relation events to the OAuth manager."""

    def __init__(self, dependent: MongoDBOperator):
        super().__init__(parent=dependent, key=ExternalRequirerRelations.OAUTH.value)
        self.dependent = dependent
        self.charm = dependent.charm
        self.manager = dependent.oauth_manager
        self.framework.observe(
            self.manager.oauth_requirer.on.oauth_info_changed, self._on_oauth_info_changed
        )
        self.framework.observe(
            self.manager.oauth_requirer.on.oauth_info_removed, self._on_oauth_info_removed
        )
        self.framework.observe(
            self.manager.certificate_transfer.on.certificate_set_updated,
            self._on_certificate_available,
        )
        self.framework.observe(
            self.manager.certificate_transfer.on.certificates_removed,
            self._on_certificate_removed,
        )
        self.framework.observe(
            self.charm.on[self.charm.peer_rel_name.value].relation_changed,
            self._on_peer_relation_changed,
        )

    def _on_certificate_available(self, event: CertificatesAvailableEvent) -> None:
        """Store the identity provider certificates on replica-set units."""
        try:
            self.manager.store_certificates(event.certificates)
        except (
            DeferrableFailedHookChecksError,
            WorkloadServiceError,
            RollingOpsNoRelationError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_certificate_removed(self, event: CertificatesRemovedEvent) -> None:
        """Delete the identity provider certificates on replica-set units."""
        try:
            self.manager.remove_certificates()
        except (
            WorkloadServiceError,
            RollingOpsNoRelationError,
            DeferrableFailedHookChecksError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_peer_relation_changed(self, event: RelationChangedEvent) -> None:
        """Reconcile the shared issuer on follower units."""
        if self.charm.unit.is_leader():
            return
        try:
            self.manager.restart_when_ready()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_changed(self, event: OAuthInfoChangedEvent) -> None:
        """Handle available or updated provider information."""
        try:
            self.manager.configure()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_removed(self, event: OAuthInfoRemovedEvent) -> None:
        """Handle removal of provider information."""
        try:
            self.manager.remove()
        except (DeferrableFailedHookChecksError, RollingOpsNoRelationError) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)
