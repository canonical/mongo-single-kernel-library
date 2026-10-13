# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handlers for the identity provider CA relation: oauth-certificate-transfer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from charmlibs.interfaces.certificate_transfer import (
    CertificatesAvailableEvent,
    CertificatesRemovedEvent,
)
from ops.charm import UpdateStatusEvent
from ops.framework import Object

from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger(__name__)


class OAuthEventHandler(Object):
    """Event handler for the identity provider CA relation, shaped like LDAPEventHandler.

    Routers hold no relation: they receive the bundle over `cluster` (see ClusterRequirer).
    On update-status the certificates are reconciled with the relation.
    """

    def __init__(self, dependent: OperatorProtocol):
        self.dependent: OperatorProtocol = dependent
        self.charm: AbstractMongoCharm = dependent.charm
        self.manager = dependent.oauth_manager

        super().__init__(parent=dependent, key=self.manager.name)

        if self.manager.certificate_transfer is not None:
            self.framework.observe(
                self.manager.certificate_transfer.on.certificate_set_updated,
                self._on_certificate_set_updated,
            )
            self.framework.observe(
                self.manager.certificate_transfer.on.certificates_removed,
                self._on_certificates_removed,
            )
            self.framework.observe(self.charm.on.update_status, self._on_update_status)

    def _on_certificate_set_updated(self, event: CertificatesAvailableEvent) -> None:
        """The CA provider published or changed its certificate set."""
        action = "oauth-certificates-updated"
        try:
            self.manager.store_certificates(event.certificates)
        except (DeferrableFailedHookChecksError, WorkloadServiceError) as err:
            defer_event_with_info_log(logger, event, action, f"{err}")
        except NonDeferrableFailedHookChecksError as err:
            logger.error(f"{err}")

    def _on_certificates_removed(self, event: CertificatesRemovedEvent) -> None:
        """The CA relation is gone: the bundle files are removed."""
        try:
            self.manager.remove_certificates()
        except WorkloadServiceError as err:
            defer_event_with_info_log(logger, event, "oauth-certificates-removed", f"{err}")

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Brings the stored certificates, the bundle files and the routers in line."""
        try:
            self.manager.reconcile_certificates()
        except WorkloadServiceError as err:
            logger.warning("Update status could not reconcile the OAuth CA certificates: %s", err)
