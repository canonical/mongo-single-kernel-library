#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handlers for the oauth and oauth-certificate-transfer relations."""

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
from ops.charm import RelationChangedEvent, SecretChangedEvent, UpdateStatusEvent
from ops.framework import Object

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.secrets import generate_secret_label
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    LdapAndOauthConflictError,
    NonDeferrableFailedHookChecksError,
    OauthIssuerUnreachableError,
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

        self.framework.observe(self.charm.on.update_status, self._on_update_status)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)
        self.framework.observe(
            self.charm.on[self.charm.peer_rel_name.value].relation_changed,
            self._on_peer_relation_changed,
        )

    def _on_peer_relation_changed(self, event: RelationChangedEvent | SecretChangedEvent) -> None:
        """Reconcile the replica set follower units' OIDC configuration.

        This fires after the leader writes the validated OAuth configuration
        to the application databag.
        """
        try:
            self.manager.restart_replica_set_when_ready()
        except (
            DeferrableFailedHookChecksError,
            RollingOpsNoRelationError,
            LdapAndOauthConflictError,
            OauthIssuerUnreachableError,
            WorkloadServiceError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_changed(self, event: OAuthInfoChangedEvent) -> None:
        """Store and propagate new or updated OAuth provider information."""
        try:
            self.manager.configure_oauth()
        except (
            DeferrableFailedHookChecksError,
            RollingOpsNoRelationError,
            LdapAndOauthConflictError,
            OauthIssuerUnreachableError,
            WorkloadServiceError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_oauth_info_removed(self, event: OAuthInfoRemovedEvent) -> None:
        """Remove and propagate the removal of the OAuth issuer."""
        try:
            self.manager.remove_oauth()
        except (
            DeferrableFailedHookChecksError,
            RollingOpsNoRelationError,
            LdapAndOauthConflictError,
            WorkloadServiceError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_secret_changed(self, event: SecretChangedEvent) -> None:
        """Apply CA rotations stored in the application peer secret on followers.

        When the CA certificate is available, the leader stores the OAuth CA
        in the application peer secret. Updating its content creates a new revision
        with the same ID and label. This is why replica set followers need to
        catch up with a secret-changed event.
        """
        label = generate_secret_label(
            self.charm.app.name, Scope.APP, self.charm.peer_rel_name.value
        )
        if event.secret.label != label:
            return
        self._on_peer_relation_changed(event)

    def _on_certificate_available(self, event: CertificatesAvailableEvent) -> None:
        """Store and propagate the identity provider's CA certificates."""
        if not (
            ca_certs := self.manager.certificate_transfer.get_all_certificates(
                relation_id=event.relation_id
            )
        ):
            logger.info(
                "No OAuth CA certificates available on relation %s, skipping.",
                event.relation_id,
            )
            return
        try:
            self.manager.store_ca_certificate(ca_certs)
        except (
            DeferrableFailedHookChecksError,
            LdapAndOauthConflictError,
            OauthIssuerUnreachableError,
            RollingOpsNoRelationError,
            DeferrableError,
            WorkloadServiceError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_certificate_removed(self, event: CertificatesRemovedEvent) -> None:
        """Remove and propagate the removal of the identity provider's CA."""
        try:
            self.manager.remove_certificates()
        except (
            RollingOpsNoRelationError,
            DeferrableFailedHookChecksError,
            LdapAndOauthConflictError,
            OauthIssuerUnreachableError,
            WorkloadServiceError,
        ) as err:
            defer_event_with_info_log(logger, event, str(type(event)), str(err))
        except NonDeferrableFailedHookChecksError as err:
            logger.error("%s", err)

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Reconcile the OAuth configuration and restart if needed."""
        try:
            self.manager._update_status()
        except (
            DeferrableFailedHookChecksError,
            RollingOpsNoRelationError,
            NonDeferrableFailedHookChecksError,
            LdapAndOauthConflictError,
            OauthIssuerUnreachableError,
            WorkloadServiceError,
        ) as err:
            logger.warning(
                "Update Status could not reconcile oauth integration. Please investigate. %s",
                str(err),
            )
            # Statuses will be updated in the handler for advanced statuses.
            return
