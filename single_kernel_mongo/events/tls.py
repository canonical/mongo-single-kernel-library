#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Manager for handling TLS events."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops import ConfigChangedEvent
from ops.charm import RelationBrokenEvent, RelationCreatedEvent
from ops.framework import EventBase, EventSource, Object

from single_kernel_mongo.config.literals import CharmKind, TLSType
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import (
    MongosStatuses,
    ShardStatuses,
    TLSStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import DeferrableFailedHookChecksError
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV4,
)
from single_kernel_mongo.state.tls_state import TlsManagementState
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol

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
            certificate_requests=[self.manager.get_certificate_request_attributes()],
            private_key=self.manager.state.tls.peer_private_key,
            refresh_events=[self.refresh_tls_certificates_event],
        )

        self.client_certificate = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=ExternalRequirerRelations.CLIENT_TLS.value,
            certificate_requests=[self.manager.get_certificate_request_attributes()],
            private_key=self.manager.state.tls.client_private_key,
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
                self.charm.on[relation_name].relation_created,
                self._on_tls_relation_created,
            )
            self.framework.observe(
                self.charm.on[relation_name].relation_broken,
                self._on_tls_relation_broken,
            )

        self.framework.observe(self.charm.on.config_changed, self._on_config_changed)
        self.framework.observe(self.charm.on.secret_changed, self._on_secret_changed)

    @property
    def tls_mapping(self) -> dict[bool, TLSCertificatesRequiresV4]:
        """Mapping of boolean to a TLS requirer instance.

        The boolean value is True if the requirer is for internal certificates,
        and False for the client certificates.
        """
        return {True: self.peer_certificate, False: self.client_certificate}

    def _on_tls_relation_created(self, event: RelationCreatedEvent) -> None:
        """Handler for relation created."""
        if self.manager.state.is_role(MongoDBRoles.MONGOS):
            self.manager.state.statuses.delete(
                MongosStatuses.MISSING_PEER_TLS_REL.value,
                scope="unit",
                component=self.dependent.name,
            )
            self.manager.state.statuses.delete(
                MongosStatuses.MISSING_CLIENT_TLS_REL.value,
                scope="unit",
                component=self.dependent.name,
            )

        if self.manager.state.is_role(MongoDBRoles.SHARD):
            self.manager.state.statuses.delete(
                ShardStatuses.MISSING_PEER_TLS_REL.value,
                scope="unit",
                component=self.dependent.name,
            )
            self.manager.state.statuses.delete(
                ShardStatuses.MISSING_CLIENT_TLS_REL.value,
                scope="unit",
                component=self.dependent.name,
            )

    def refresh_certificates(self) -> None:
        """Trigger refresh TLS certificates event."""
        logger.info(f"Requesting refresh certificates for unit: {self.charm.unit.name}.")
        self.refresh_tls_certificates_event.emit()

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Handle the relation broken event."""
        state = self.manager.get_tls_management_state()
        match state:
            case TlsManagementState.UPGRADE_IN_PROGRESS:
                defer_event_with_info_log(logger, event, str(type(event)), state.value)
                return
            case (
                TlsManagementState.DB_NOT_INTIALIZED
                | TlsManagementState.MONGOS_DB_NOT_INITIALIZED
            ):
                logger.info("DB never initialised, removing the TLS relation.")
                return
            case _:
                pass

        internal = event.relation.name == ExternalRequirerRelations.PEER_TLS.value
        logger.debug(
            f"Disabling {TLSType.PEER.value if internal else TLSType.CLIENT.value} TLS for unit: {self.charm.unit.name}"
        )

        status = (
            TLSStatuses.DISABLING_PEER_TLS.value
            if internal
            else TLSStatuses.DISABLING_CLIENT_TLS.value
        )
        self.charm.status_handler.set_running_status(status, scope="unit")
        self.manager.disable_certificates_for_unit(internal)
        # Recomputes the statuses for those components as the tls changes are impactful
        self._recompute_statuses()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Handler for the certificate available event.

        This event is emitted by the TLS charm when a certificates is available.
        """
        state = self.manager.get_tls_management_state()
        match state:
            case TlsManagementState.DB_NOT_INTIALIZED | TlsManagementState.UPGRADE_IN_PROGRESS:
                defer_event_with_info_log(logger, event, str(type(event)), state.value)
                return
            case TlsManagementState.MONGOS_MISSING_CONFIG_SERVER:
                logger.info(f"{state.value} Ignoring certificate.")
                return
            case _:
                pass

        logger.info("Certificate available.")

        cert = event.certificate
        client_certificates, client_private_key = (
            self.client_certificate.get_assigned_certificates()
        )
        peer_certificates, peer_private_key = self.peer_certificate.get_assigned_certificates()

        if client_certificates and client_certificates[0].certificate == cert:
            internal = False
            provider_cert = client_certificates[0]
            private_key = client_private_key.raw if client_private_key else None
        elif peer_certificates and peer_certificates[0].certificate == cert:
            internal = True
            provider_cert = peer_certificates[0]
            private_key = peer_private_key.raw if peer_private_key else None
        else:
            logger.error("Received certificate does not match any assigned certificates.")
            return

        logger.debug(
            f"Received {TLSType.PEER.value if internal else TLSType.CLIENT.value} certificate."
        )

        self.manager.set_certificates(
            secret_chain=[c.raw for c in provider_cert.chain],
            certificate=provider_cert.certificate.raw,
            csr=provider_cert.certificate_signing_request.raw,
            ca=provider_cert.ca.raw,
            private_key=private_key,
            internal=internal,
        )
        if internal:
            self.dependent.state.update_peer_ca_secrets(provider_cert.ca.raw)
        else:
            self.dependent.state.update_client_ca_secrets(provider_cert.ca.raw)

        self.manager.enable_certificates_for_unit(internal)
        self._recompute_statuses()

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """On Config Changed, validate private keys and refresh certs if needed."""
        try:
            self.manager.update_private_keys()
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, "set-private-key", f"{e}")
            return

    def _on_secret_changed(self, event: ConfigChangedEvent) -> None:
        """On Secret Changed, validate private keys and refresh certs if needed."""
        try:
            self.manager.update_private_keys()
        except DeferrableFailedHookChecksError as e:
            defer_event_with_info_log(logger, event, "set-private-key", f"{e}")
            return

    def _recompute_statuses(self):
        """Recomputes the statuses for those components as the tls changes are impactful."""
        if self.dependent.name == CharmKind.MONGOD:
            self.charm.status_handler._recompute_statuses_for_scope(
                "unit", self.dependent.shard_manager
            )
        else:
            self.charm.status_handler._recompute_statuses_for_scope("unit", self.dependent)
            if self.charm.unit.is_leader():
                self.charm.status_handler._recompute_statuses_for_scope("app", self.dependent)
