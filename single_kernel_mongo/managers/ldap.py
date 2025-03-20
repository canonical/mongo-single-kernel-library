# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The managers for the ldap relations between glauth-k8s and mongo charms."""

from __future__ import annotations

import ssl
from logging import getLogger
from typing import TYPE_CHECKING

import jinja2
from ldap3 import Connection as LDAPConnection
from ldap3 import Server as LDAPServer
from ldap3 import Tls as LDAPTls
from ops import MaintenanceStatus
from ops.framework import Object
from ops.model import ActiveStatus, BlockedStatus, Relation, StatusBase, WaitingStatus

from single_kernel_mongo.config.literals import (
    Substrates,
)
from single_kernel_mongo.config.models import LDAP_CONFIG
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.status_provider import StatusProvider
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    LDAPSNotEnabledError,
    NonDeferrableFailedHookChecksError,
    WaitingForLdapDataError,
)
from single_kernel_mongo.lib.charms.certificate_transfer_interface.v0.certificate_transfer import (
    CertificateTransferRequires,
)
from single_kernel_mongo.lib.charms.glauth_k8s.v0.ldap import LdapRequirer
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.core.operator import OperatorProtocol

logger = getLogger(__name__)

CANNOT_INTEGRATE_WITH_SHARD_STATUS = BlockedStatus("Cannot integrate LDAP with shard.")


class LDAPManager(Object, StatusProvider):
    """Manages the relation between glauth-k8s and replica set, config-sever or mongos router."""

    def __init__(
        self,
        dependent: OperatorProtocol,
        state: CharmState,
        substrate: Substrates,
        relation_name: ExternalRequirerRelations = ExternalRequirerRelations.LDAP,
        cert_relation_name: ExternalRequirerRelations = ExternalRequirerRelations.LDAP_CERT,
    ):
        super().__init__(parent=dependent, key=relation_name)
        self.dependent = dependent
        self.charm = dependent.charm
        self.workload = self.dependent.workload
        self.state = state
        self.substrate = substrate
        self.relation_name = relation_name
        self.cert_relation_name = cert_relation_name
        self.ldap_requirer = LdapRequirer(self.charm, self.relation_name)
        self.certificate_transfer = CertificateTransferRequires(self.charm, self.cert_relation_name)

    def assert_pass_hook_checks(self) -> None:
        """Runs some hook checks before allowing the hook to run."""
        if not self.state.db_initialised:
            raise DeferrableFailedHookChecksError("DB is not initialised")
        if self.state.is_role(MongoDBRoles.SHARD):
            self.charm.status_manager.set_and_share_status(CANNOT_INTEGRATE_WITH_SHARD_STATUS)
            raise NonDeferrableFailedHookChecksError("Cannot integrate LDAP with shard.")
        if self.state.upgrade_in_progress:
            raise DeferrableFailedHookChecksError(
                "Adding LDAP is not supported during an upgrade. The charm may be in a broken, unrecoverable state."
            )
        return

    def is_valid_ldap_integration(self) -> bool:
        """Returns True if the integration to ldap is valid."""
        return (self.state.ldap_relation is not None) and not self.state.is_role(MongoDBRoles.SHARD)

    def ldap_ready(self, relation: Relation) -> None:
        """Runs when LDAP is ready."""
        self.assert_pass_hook_checks()

        self.charm.status_manager.set_and_share_status(MaintenanceStatus("Configuring LDAP"))

        ldap_data = self.ldap_requirer.consume_ldap_relation_data(relation=relation)
        if not ldap_data:
            logger.info("Waiting for LDAP data.")
            raise WaitingForLdapDataError("Waiting for LDAP data.")

        if not ldap_data.ldaps_urls:
            logger.error("You must configure Glauth with LDAPS (ldaps_enabled=true) support")
            raise LDAPSNotEnabledError("LDAPS not enabled.")

        if self.charm.unit.is_leader():
            self.state.ldap.set_from(ldap_data)
            # ops event to restart if ready for the leader.
            # The other units will restart during the ldap-peers-relation-changed hook.
            self.dependent.ldap_events.restart_if_ready_event.emit()

    def restart_when_ready(self) -> None:
        """Restarts when we are ready."""
        match self.get_status():
            case None:
                return
            case ActiveStatus():
                logger.info("Restarting mongodb server for LDAP integration")
                self.dependent.restart_charm_services()
                self.charm.status_manager.set_and_share_status(ActiveStatus())
            case status:
                self.charm.status_manager.set_and_share_status(status)

    def ldap_unavailable(self) -> None:
        """Runs when the LDAP integration is broken."""
        self.state.ldap.clean_databag()

        self.dependent.restart_charm_services()
        self.charm.status_manager.set_and_share_status(self.get_status() or ActiveStatus())

    def certificate_available(self, certificate: str, ca: str, chain: list[str]) -> None:
        """Runs when we receive the LDAP certificates."""
        self.assert_pass_hook_checks()
        self.state.ldap.set_certificates(certificate, ca, chain)

        self.save_certificates(chain)

        self.dependent.ldap_events.restart_if_ready_event.emit()

    def save_certificates(self, chain: list[str] | None) -> None:
        """Saves the certificates in different files."""
        if not chain:
            return

        full_chain = "\n".join(chain)

        template_data = LDAP_CONFIG.ldap_conf_template.read_text()
        template = jinja2.Template(template_data)

        rendered_template = template.render(
            ldap_certificate_file=f"{self.workload.paths.ldap_certificates_file}"
        )

        self.workload.write(self.workload.paths.ldap_conf_path, rendered_template)

        self.workload.write(self.workload.paths.ldap_certificates_file, full_chain)

    def certificate_removed(self):
        """Runs when the certificate is removed."""
        self.state.ldap.clean_certificates()

        # Conditional removal of the certificates
        if self.workload.exists(self.workload.paths.ldap_certificates_file):
            self.workload.delete(self.workload.paths.ldap_certificates_file)

        self.dependent.restart_charm_services()

        self.charm.status_manager.set_and_share_status(self.get_status() or ActiveStatus())

    def get_status(self) -> StatusBase | None:
        """Generates the status of a unit based on its status reported by mongod."""
        if self.state.ldap_relation is None and self.state.ldap_cert_relation is None:
            return None

        if self.state.is_role(MongoDBRoles.SHARD):
            return BlockedStatus("Cannot integrate LDAP with shard.")

        if self.state.ldap_cert_relation is None:
            logger.info(
                "Integrate the certificate interface between glauth and charm using "
                f"`juju integrate {self.state.ldap_relation.app.name}:send-ca-cert"  # type: ignore[union-attr]
                f"{self.charm.app.name}:{ExternalRequirerRelations.LDAP_CERT}`"
            )
            return BlockedStatus("TLS is mandatory for LDAP transport.")
        if self.state.ldap_relation is None:
            logger.info(
                "Integrate glauth with ldap using"
                f"`juju integrate {self.state.ldap_cert_relation.app.name}:ldap {self.charm.app.name}:{ExternalRequirerRelations.LDAP}`"
            )
            return BlockedStatus("GLauth TLS is integrated but LDAP is not.")

        ldap_relation_status = self.state.ldap.ldap_ready()

        # We can ignore the typing error because we'll end up here only if both are not None.
        ldap_certificate_integration_status = self.state.ldap.ldap_certs_ready()

        match (ldap_relation_status, ldap_certificate_integration_status):
            case False, False:
                return WaitingStatus("Waiting for both LDAP data and Glauth certificates.")
            case True, False:
                return WaitingStatus("Waiting for Glauth certificates.")
            case False, True:
                logger.info("Waiting for LDAP data.")
                return WaitingStatus("Missing LDAP data from Glauth.")
            case _:
                return self.get_ldap_connection_status()

    def get_ldap_connection_status(self) -> StatusBase:
        """Checks if the LDAP connection is working or not.

        Helpful to prevent restarts that would fail.
        """
        bind_dn = self.state.ldap.bind_user
        bind_password = self.state.ldap.bind_password
        base_dn = self.state.ldap.base_dn
        cert_chain = self.state.ldap.chain

        if not base_dn:
            return BlockedStatus("Missing base DN.")

        if not cert_chain:
            return BlockedStatus("Missing chain.")

        if not self.state.ldap.ldaps_urls:
            return BlockedStatus("Missing LDAPS URLs.")

        try:
            for ldap_uri in self.state.ldap.ldaps_urls:
                tls = LDAPTls(
                    validate=ssl.CERT_REQUIRED,
                    version=ssl.PROTOCOL_TLSv1_2,
                    ca_certs_data="\n".join(cert_chain),
                )
                server = LDAPServer(host=ldap_uri, use_ssl=True, tls=tls)
                conn = LDAPConnection(server, user=bind_dn, password=bind_password)
                conn.bind()  # We consider sufficient to be able to bind.
                conn.unbind()
        except Exception as err:
            logger.error(f"Could not bind: {err}", exc_info=True)
            return BlockedStatus("Could not bind with ldap")

        return ActiveStatus()
