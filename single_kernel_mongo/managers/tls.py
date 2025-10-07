#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS Manager.

Handles MongoDB TLS Files.
"""

from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING, TypedDict

from single_kernel_mongo.config.literals import TLSType
from single_kernel_mongo.config.statuses import TLSStatuses
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.tls_state import (
    SECRET_CA_LABEL,
    SECRET_CERT_LABEL,
    SECRET_CHAIN_LABEL,
    SECRET_KEY_LABEL,
    TlsManagementState,
)

# from single_kernel_mongo.utils.helpers import parse_tls_file
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    pass


class Sans(TypedDict):
    """A Typed Dict for a Sans."""

    sans_ips: list[str]
    sans_dns: list[str]


logger = logging.getLogger(__name__)


class TLSManager:
    """Manager for building necessary files for mongodb."""

    def __init__(
        self,
        dependent: OperatorProtocol,
        workload: MongoDBWorkload | MongosWorkload,
        state: CharmState,
    ) -> None:
        self.dependent = dependent
        self.charm = dependent.charm
        self.workload = workload
        self.state = state

    def get_certificate_request_attributes(self) -> CertificateRequestAttributes:
        """Generate a certificate signing request attributes."""
        subject_name = self._get_subject_name()
        sans = self.get_new_sans()
        return CertificateRequestAttributes(
            common_name=subject_name,
            sans_ip=frozenset(sans["sans_ips"]),
            sans_dns=frozenset(sans["sans_dns"]),
            organization=subject_name,
        )

    def get_new_sans(self) -> Sans:
        """Create a list of DNS names and IPs for a MongoDB unit.

        Returns:
            A list representing the hostnames of the MongoDB unit.
        """
        unit_id = self.charm.unit.name.split("/")[1]

        sans = Sans(
            sans_dns=[
                f"{self.charm.app.name}-{unit_id}",
                socket.getfqdn(),
                "localhost",
                f"{self.charm.app.name}-{unit_id}.{self.charm.app.name}-endpoints",
            ],
            sans_ips=[str(self.state.bind_address)],
        )

        if self.state.is_role(MongoDBRoles.MONGOS) and self.state.is_external_client:
            if host := self.state.unit_host:
                sans["sans_ips"].append(host)

        return sans

    def get_tls_file_contents(self, internal: bool) -> tuple[str | None, str | None]:
        """Prepare TLS files in special MongoDB way.

        MongoDB needs two files:
        — CA file should have a full chain.
        — PEM file should have private key and certificate without certificate chain.
        """
        scope = "internal" if internal else "external"
        if not self.state.tls.is_tls_enabled(internal):
            logging.debug(f"TLS disabled for {scope}")
            return None, None
        logging.debug(f"TLS *enabled* for {scope}, fetching data for CA and PEM files ")

        ca = self.state.tls.get_secret(internal, SECRET_CA_LABEL)
        chain = self.state.tls.get_secret(internal, SECRET_CHAIN_LABEL)
        ca_file = chain if chain else ca

        key = self.state.tls.get_secret(internal, SECRET_KEY_LABEL)
        cert = self.state.tls.get_secret(internal, SECRET_CERT_LABEL)
        pem_file = key
        if cert:
            pem_file = key + "\n" + cert if key else cert

        return ca_file, pem_file

    def disable_certificates_for_unit(self, internal: bool):
        """Disables the certificates on relation broken."""
        self.state.tls.set_secret(internal, SECRET_CA_LABEL, None)
        self.state.tls.set_secret(internal, SECRET_CERT_LABEL, None)
        self.state.tls.set_secret(internal, SECRET_CHAIN_LABEL, None)
        self.state.tls.set_secret(internal, SECRET_KEY_LABEL, None)

        if internal:
            self.state.update_internal_ca_secrets(new_ca=None)

        self.delete_certificates_from_workload(internal)
        self.dependent.restart_charm_services(force=True)

    def enable_certificates_for_unit(self, internal: bool):
        """Enables the new certificates for this unit."""
        self.delete_certificates_from_workload(internal)
        self.push_tls_files_to_workload(internal)

        if not self.state.db_initialised and self.state.is_role(MongoDBRoles.MONGOS):
            logger.info(
                "Mongos has not yet been initialized, will enable TLS when it is set up with the config-server."
            )
            return

        self.charm.status_handler.set_running_status(
            TLSStatuses.ENABLING_TLS.value,
            scope="unit",
            statuses_state=self.state.statuses,
            component_name=self.charm.name,
        )
        try:
            self.dependent.restart_charm_services(force=True)
        except WorkloadServiceError as e:
            # TODO should we defer or just error
            logger.error("An exception occurred when starting mongod agent, error: %s.", str(e))
            return

    def delete_certificates_from_workload(self, internal: bool) -> None:
        """Deletes the certificates from the workload."""
        logger.info(
            f"Deleting {TLSType.PEER if internal else TLSType.CLIENT} TLS certificates from filesystem"
        )

        path = (
            self.workload.paths.tls_peer_files if internal else self.workload.paths.tls_client_files
        )
        for file in path:
            if self.workload.exists(file):
                self.workload.delete(file)

    def push_tls_files_to_workload(self, internal: bool) -> None:
        """Pushes the TLS files on the workload."""
        logger.info(
            f"Pushing {TLSType.PEER if internal else TLSType.CLIENT} TLS certificates to filesystem"
        )
        ca, pem = self.get_tls_file_contents(internal=internal)

        if internal:
            if ca is not None:
                self.workload.write(self.workload.paths.int_ca_file, ca)
            if pem is not None:
                self.workload.write(self.workload.paths.int_pem_file, pem)
        else:
            if ca is not None:
                self.workload.write(self.workload.paths.ext_ca_file, ca)
            if pem is not None:
                self.workload.write(self.workload.paths.ext_pem_file, pem)

    def set_certificates(
        self,
        secret_chain: list[str] | None,
        certificate: str | None,
        ca: str | None,
        private_key: str | None,
        internal: bool,
    ):
        """Sets the certificates."""
        self.state.tls.set_secret(
            internal,
            SECRET_CHAIN_LABEL,
            "\n".join(secret_chain) if secret_chain is not None else None,
        )
        self.state.tls.set_secret(internal, SECRET_KEY_LABEL, private_key)
        self.state.tls.set_secret(internal, SECRET_CERT_LABEL, certificate)
        self.state.tls.set_secret(internal, SECRET_CA_LABEL, ca)
        logger.info(f"{TLSType.PEER if internal else TLSType.CLIENT} certificate secrets updated.")

    def is_waiting_for_a_cert(self) -> bool:
        """Returns a boolean indicating whether additional certs are needed."""
        if not self.state.tls.get_secret(internal=True, label_name=SECRET_CERT_LABEL):
            logger.debug("Waiting for internal certificate.")
            return True
        if not self.state.tls.get_secret(internal=False, label_name=SECRET_CERT_LABEL):
            logger.debug("Waiting for external certificate.")
            return True

        return False

    def _get_subject_name(self) -> str:
        """Generate the subject name for CSR."""
        # In sharded MongoDB deployments it is a requirement that all subject names match across
        # all cluster components. The config-server name is the source of truth across mongos and
        # shard deployments.
        if not self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            # until integrated with config-server use current app name as
            # subject name
            return self.state.config_server_name or self.charm.app.name

        return self.charm.app.name

    def get_tls_management_state(self) -> TlsManagementState:
        """Pre-checks on TLS certificates management."""
        if self.state.upgrade_in_progress:
            return TlsManagementState.UPGRADE_IN_PROGRESS
        if self.state.is_role(MongoDBRoles.MONGOS) and self.state.config_server_name is None:
            return TlsManagementState.MONGOS_MISSING_CONFIG_SERVER
        if not self.state.db_initialised:
            if self.state.is_role(MongoDBRoles.MONGOS):
                return TlsManagementState.MONGOS_DB_NOT_INITIALIZED
            return TlsManagementState.DB_NOT_INTIALIZED
        return TlsManagementState.EMPTY
