#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Handlers for ldap relations: ldap, ldap-certificates and ldap-peer."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.framework import EventBase, EventSource, Object
from pydantic import ValidationError

from single_kernel_mongo.config.relations import ExternalRequirerRelations, PeerRelationNames
from single_kernel_mongo.config.statuses import LdapStatuses
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    InvalidLdapWithShardError,
    LDAPSNotEnabledError,
    NonDeferrableFailedHookChecksError,
    WaitingForLdapDataError,
)
from single_kernel_mongo.lib.charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateAvailableEvent,
    CertificateRemovedEvent,
)
from single_kernel_mongo.lib.charms.glauth_k8s.v0.ldap import LdapReadyEvent, LdapUnavailableEvent
from single_kernel_mongo.utils.event_helpers import defer_event_with_info_log

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = logging.getLogger(__name__)


class RestartIfReadyEvent(EventBase):
    """Handles the restart of the units if they are ready."""


class LDAPEventHandler(Object):
    """Event Handler for all ldap related relations."""

    restart_if_ready_event = EventSource(RestartIfReadyEvent)

    def __init__(self, dependent: OperatorProtocol):
        self.dependent: OperatorProtocol = dependent
        self.charm: AbstractMongoCharm = dependent.charm
        self.manager = dependent.ldap_manager
        self.relation_name = ExternalRequirerRelations.LDAP.value
        self.cert_relation_name = ExternalRequirerRelations.LDAP_CERT.value

        super().__init__(parent=dependent, key=self.relation_name)

        self.framework.observe(self.manager.ldap_requirer.on.ldap_ready, self._on_ldap_ready)
        self.framework.observe(
            self.manager.ldap_requirer.on.ldap_unavailable, self._on_ldap_unavailable
        )
        self.framework.observe(
            self.manager.certificate_transfer.on.certificate_available,
            self._on_certificate_available,
        )
        self.framework.observe(
            self.manager.certificate_transfer.on.certificate_removed, self._on_certificate_removed
        )
        self.framework.observe(self.restart_if_ready_event, self._on_restart_if_ready)

        self.framework.observe(
            self.charm.on[PeerRelationNames.LDAP_PEERS.value].relation_changed,
            self._on_restart_if_ready,
        )

    def _on_ldap_ready(self, event: LdapReadyEvent) -> None:
        """Handles the ops event that indicates that ldap relation is ready."""
        action = "ldap-ready"
        try:
            self.charm.status_handler.set_running_status(
                LdapStatuses.CONFIGURING_LDAP.value,
                scope="unit",
            )
            self.manager.store_ldap_credentials_and_uri(event.relation)
        except (WaitingForLdapDataError, ValidationError) as err:
            self.manager.state.statuses.add(
                LdapStatuses.WAITING_FOR_LDAP_DATA.value,
                scope="unit",
                component=self.manager.name,
            )
            defer_event_with_info_log(logger, event, action, f"{err}")
        except (DeferrableError, DeferrableFailedHookChecksError) as err:
            defer_event_with_info_log(logger, event, action, f"{err}")
        except LDAPSNotEnabledError:
            self.manager.state.statuses.add(
                LdapStatuses.LDAPS_NOT_ENABLED.value, scope="unit", component=self.manager.name
            )
        except InvalidLdapWithShardError:
            self.manager.state.statuses.add(
                LdapStatuses.INVALID_LDAP_REL_ON_SHARD.value,
                scope="unit",
                component=self.manager.name,
            )
        except NonDeferrableFailedHookChecksError as err:
            logger.error(f"{err}")
            self.manager.state.statuses.add(
                LdapStatuses.on_error_status(err), scope="unit", component=self.manager.name
            )

    def _on_ldap_unavailable(self, event: LdapUnavailableEvent) -> None:
        """Handles the ops event that indicates that ldap relation is now unavailable."""
        self.manager.clean_ldap_credentials_and_uri()

    def _on_certificate_available(self, event: CertificateAvailableEvent):
        """Handles the ops event that indicates that ldap-certificates relation is ready."""
        try:
            self.manager.store_ldap_certificates(event.certificate, event.ca, event.chain)
        except DeferrableFailedHookChecksError as err:
            defer_event_with_info_log(logger, event, "ldap-cert-ready", f"{err}")
        except InvalidLdapWithShardError:
            self.manager.state.statuses.add(
                LdapStatuses.INVALID_LDAP_REL_ON_SHARD.value,
                scope="unit",
                component=self.manager.name,
            )
        except NonDeferrableFailedHookChecksError as err:
            logger.error(f"{err}")
            self.manager.state.statuses.add(
                LdapStatuses.on_error_status(err), scope="unit", component=self.manager.name
            )

    def _on_certificate_removed(self, event: CertificateRemovedEvent) -> None:
        """Handles the ops event that indicates that ldap-certificates relation is unavailable."""
        self.manager.remove_ldap_certificates()

    def _on_restart_if_ready(self, event: RestartIfReadyEvent) -> None:
        """Custom ops revent to trigger restart of leader with a single source of truth."""
        action = "restart-ldap-if-ready"
        try:
            self.manager.restart_when_ready()
        except (DeferrableFailedHookChecksError, DeferrableError) as err:
            defer_event_with_info_log(logger, event, action, f"{err}")
        except InvalidLdapWithShardError:
            self.manager.state.statuses.add(
                LdapStatuses.INVALID_LDAP_REL_ON_SHARD.value,
                scope="unit",
                component=self.manager.name,
            )
        except NonDeferrableFailedHookChecksError as err:
            logger.error(f"{err}")
            self.manager.state.statuses.add(
                LdapStatuses.on_error_status(err), scope="unit", component=self.manager.name
            )
