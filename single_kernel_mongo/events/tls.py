#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling TLS events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import ActionEvent, RelationBrokenEvent, RelationJoinedEvent
from ops.framework import Object

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import MongosStatuses, TLSStatuses
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    UnknownCertificateAvailableError,
    UnknownCertificateExpiringError,
)
from single_kernel_mongo.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV3,
)
from single_kernel_mongo.utils.event_helpers import (
    fail_action_with_error_log,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


logger = logging.getLogger(__name__)


class TLSEventsHandler(Object):
    """Event Handler for managing TLS events."""

    def __init__(self, dependent: OperatorProtocol):
        super().__init__(parent=dependent, key="tls")
        self.dependent = dependent
        self.manager = self.dependent.tls_manager
        self.charm: AbstractMongoCharm = dependent.charm
        self.relation_name = ExternalRequirerRelations.TLS.value
        self.certs_client = TLSCertificatesRequiresV3(self.charm, self.relation_name)

        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_joined,
            self._on_tls_relation_joined,
        )
        self.framework.observe(
            self.charm.on[self.relation_name].relation_broken,
            self._on_tls_relation_broken,
        )
        self.framework.observe(
            self.certs_client.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.certs_client.on.certificate_expiring, self._on_certificate_expiring
        )

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        """Set the TLS private key which will be used for requesting the certificates."""
        logger.debug("Request to set TLS private key received.")
        if (
            self.manager.state.is_role(MongoDBRoles.MONGOS)
            and self.manager.state.config_server_name is None
        ):
            logger.info(
                "mongos is not running (not integrated to config-server) deferring renewal of certificates."
            )
            event.fail("Mongos cannot set TLS keys until integrated to config-server.")
            return
        if self.manager.state.upgrade_in_progress:
            fail_action_with_error_log(
                logger,
                event,
                "set-tls-private-key",
                "Setting TLS keys during an upgrade is not supported.",
            )
            return
        try:
            for internal in (True, False):
                param = "internal-key" if internal else "external-key"
                key = event.params.get(param, None)
                csr = self.manager.generate_certificate_request(key, internal=internal)
                self.certs_client.request_certificate_creation(certificate_signing_request=csr)
                self.manager.set_waiting_for_cert_to_update(internal=internal, waiting=True)
        except ValueError as e:
            event.fail(str(e))

    def _on_tls_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Handler for relation joined."""
        if (
            self.manager.state.is_role(MongoDBRoles.MONGOS)
            and self.manager.state.config_server_name is None
        ):
            logger.info(
                "mongos is not running (not integrated to config-server) deferring renewal of certificates."
            )
            event.defer()
            return
        if self.manager.state.upgrade_in_progress:
            logger.warning(
                "Enabling TLS is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return

        # When we can integrate, clean the mongos requires tls status.
        if self.manager.state.is_role(MongoDBRoles.MONGOS):
            self.manager.state.statuses.delete(
                MongosStatuses.MISSING_TLS_REL.value, scope="unit", component=self.dependent.name
            )

        for internal in (True, False):
            csr = self.manager.generate_certificate_request(None, internal=internal)
            self.certs_client.request_certificate_creation(certificate_signing_request=csr)
            self.manager.set_waiting_for_cert_to_update(internal=internal, waiting=True)

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handler for relation joined."""
        if not self.manager.state.db_initialised:
            logger.info(f"Deferring {str(type(event))}. db is not initialised.")
            event.defer()
            return

        if self.manager.state.upgrade_in_progress:
            logger.warning(
                "Disabling TLS is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
        logger.debug("Disabling external and internal TLS for unit: %s", self.charm.unit.name)
        self.charm.status_handler.set_running_status(
            TLSStatuses.DISABLING_TLS.value,
            scope="unit",
        )
        self.manager.disable_certificates_for_unit()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handler for the certificate available event.

        This event is emitted by the TLS charm when the some certificates are available.
        """
        if (
            self.manager.state.is_role(MongoDBRoles.MONGOS)
            and self.manager.state.config_server_name is None
        ):
            logger.info(
                "mongos is not running (not integrated to config-server) deferring renewal of certificates."
            )
            event.defer()
            return
        if not self.manager.state.db_initialised and not self.dependent.state.is_role(
            MongoDBRoles.MONGOS
        ):
            logger.info(f"Deferring {str(type(event))}: db is not initialised")
            event.defer()
            return
        if self.manager.state.upgrade_in_progress:
            logger.warning(
                "Enabling TLS is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
            event.defer()
            return
        try:
            self.manager.set_certificates(
                event.certificate_signing_request,
                event.chain,
                event.certificate,
                event.ca,
            )
            self.dependent.state.update_ca_secrets(event.ca)

            # If we don't have both certificates, we early return, the next
            # certificate available event will enable certificates for this
            # unit.
            if self.manager.is_waiting_for_both_certs():
                logger.info(
                    "Waiting for both internal and external TLS certificates available to avoid second restart."
                )
                event.defer()
                return

            self.manager.enable_certificates_for_unit()
        except UnknownCertificateAvailableError:
            logger.error("An unknown certificate is available -- ignoring.")
            return

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Handle certificate expiring events."""
        if (
            self.manager.state.is_role(MongoDBRoles.MONGOS)
            and not self.manager.state.config_server_name is not None
        ):
            logger.info(
                "mongos is not running (not integrated to config-server) deferring renewal of certificates."
            )
            event.defer()
            return
        try:
            old_csr, new_csr = self.manager.renew_expiring_certificate(event.certificate)
            self.certs_client.request_certificate_renewal(
                old_certificate_signing_request=old_csr,
                new_certificate_signing_request=new_csr,
            )
        except UnknownCertificateExpiringError:
            logger.debug("An unknown certificate is expiring.")
