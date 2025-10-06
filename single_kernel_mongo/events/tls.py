#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling TLS events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import RelationBrokenEvent, RelationJoinedEvent
from ops.framework import EventBase, EventSource, Object

from single_kernel_mongo.config.literals import TLSType
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import MongosStatuses, TLSStatuses
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles

# from single_kernel_mongo.exceptions import (
#    UnknownCertificateAvailableError,
# )
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV4,
)
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
from single_kernel_mongo.state.tls_state import TlsManagementState

logger = logging.getLogger(__name__)


class RefreshTLSCertificatesEvent(EventBase):
    """Event for refreshing TLS certificates."""


class TLSEventsHandler(Object):
    """Event Handler for managing TLS events."""

    refresh_tls_certificates_event = EventSource(RefreshTLSCertificatesEvent)

    def __init__(self, dependent: OperatorProtocol):
        super().__init__(parent=dependent, key="tls")
        self.dependent = dependent
        self.manager = self.dependent.tls_manager
        self.charm: AbstractMongoCharm = dependent.charm

        self.peer_certificate = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=ExternalRequirerRelations.PEER_TLS.value,
            certificate_requests=[self.manager.get_certificate_request_attributes(internal=True)],
            private_key=None,
            refresh_events=[self.refresh_tls_certificates_event],
        )

        self.client_certificate = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=ExternalRequirerRelations.CLIENT_TLS.value,
            certificate_requests=[self.manager.get_certificate_request_attributes(internal=False)],
            private_key=None,
            refresh_events=[self.refresh_tls_certificates_event],
        )

        for cert_requires in [self.peer_certificate, self.client_certificate]:
            self.framework.observe(
                cert_requires.on.certificate_available, self._on_certificate_available
            )

        for relation_name in [
            ExternalRequirerRelations.PEER_TLS.value,
            ExternalRequirerRelations.CLIENT_TLS.value,
        ]:
            self.framework.observe(
                self.charm.on[relation_name].relation_joined, self._on_tls_relation_joined
            )
            self.framework.observe(
                self.charm.on[relation_name].relation_broken, self._on_tls_relation_broken
            )

    def _on_tls_relation_joined(self, event: RelationJoinedEvent) -> None:
        """Handler for relation joined."""
        state = self.manager.get_tls_management_state()
        match state:
            case (
                TlsManagementState.MONGOS_MISSING_CONFIG_SERVER
                | TlsManagementState.UPGRADE_IN_PROGRESS
            ):
                defer_event_with_info_log(logger, event, str(type(event)), state.value)
                return

        # When we can integrate, clean the mongos requires tls status.
        if self.manager.state.is_role(MongoDBRoles.MONGOS):
            self.manager.state.statuses.delete(
                MongosStatuses.MISSING_TLS_REL.value, scope="unit", component=self.dependent.name
            )

        # internal = event.relation.name == ExternalRequirerRelations.PEER_TLS.value
        # self.manager.set_certificate_requested(internal)

    def request_certificate(self) -> None:
        """Request refresh of certificates."""
        logger.info("Requesting refresh certificate.")
        self.refresh_tls_certificates_event.emit()
        # self.manager.set_certificate_requested(internal)

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle the `certificates-broken` event.

        Args:
            event (RelationBrokenEvent): The event object.
        """
        state = self.manager.get_tls_management_state()
        match state:
            case (
                TlsManagementState.DB_NOT_INTIALIZED
                | TlsManagementState.MONGOS_DB_NOT_INITIALIZED
                | TlsManagementState.UPGRADE_IN_PROGRESS
            ):
                defer_event_with_info_log(logger, event, str(type(event)), state.value)
                return

        logger.debug("Disabling TLS for unit: %s", self.charm.unit.name)

        cert_type = (
            TLSType.PEER
            if event.relation.name == ExternalRequirerRelations.PEER_TLS.value
            else TLSType.CLIENT
        )
        status = (
            TLSStatuses.DISABLING_PEER_TLS.value
            if cert_type == TLSType.PEER
            else TLSStatuses.DISABLING_CLIENT_TLS.value
        )
        self.charm.status_handler.set_running_status(status, scope="unit")
        internal = cert_type == TLSType.PEER
        self.manager.disable_certificates_for_unit(internal)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handler for the certificate available event.

        This event is emitted by the TLS charm when the some certificates are available.
        """
        state = self.manager.get_tls_management_state()
        match state:
            case TlsManagementState.DB_NOT_INTIALIZED | TlsManagementState.UPGRADE_IN_PROGRESS:
                defer_event_with_info_log(logger, event, str(type(event)), state.value)
                return
            case TlsManagementState.MONGOS_MISSING_CONFIG_SERVER:
                logger.info(f"{state.value}. Ignoring certificate.")
                return

        logger.info("Certificate available.")

        cert = event.certificate
        client_certificates, client_private_key = (
            self.client_certificate.get_assigned_certificates()
        )
        peer_certificates, peer_private_key = self.peer_certificate.get_assigned_certificates()

        if client_certificates and client_certificates[0].certificate == cert:
            cert_type = TLSType.CLIENT
            provider_cert = client_certificates[0]
            private_key = client_private_key.raw if client_private_key else None
        elif peer_certificates and peer_certificates[0].certificate == cert:
            cert_type = TLSType.PEER
            provider_cert = peer_certificates[0]
            private_key = peer_private_key.raw if peer_private_key else None
        else:
            logger.error("Received certificate does not match any assigned certificates.")
            return

        logger.debug(f"Received {cert_type} certificate.")

        internal = cert_type == TLSType.PEER

        self.manager.set_certificates(
            # certificate_signing_request=provider_cert.certificate_signing_request,
            secret_chain=[c.raw for c in provider_cert.chain],
            certificate=provider_cert.certificate.raw,
            ca=provider_cert.ca.raw,
            private_key=private_key,
            internal=internal,
        )
        if internal:
            self.dependent.state.update_internal_ca_secrets(provider_cert.ca.raw)

        self.manager.enable_certificates_for_unit(internal)
        # except UnknownCertificateAvailableError:
        #    logger.error("An unknown certificate is available -- ignoring.")
        #    return
