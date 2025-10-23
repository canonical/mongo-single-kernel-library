#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS Manager.

Handles MongoDB TLS Files.
"""

from __future__ import annotations

import base64
import logging
import re
import socket
from typing import TYPE_CHECKING, TypedDict

from data_platform_helpers.advanced_statuses.protocol import (
    ManagerStatusProtocol,
    Scope,
    StatusObject,
)
from ops.model import ModelError, SecretNotFoundError

from single_kernel_mongo.config.literals import Substrates, TLSType
from single_kernel_mongo.config.statuses import TLSStatuses
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import WorkloadServiceError
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    PrivateKey,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.tls_state import (
    SECRET_CA_LABEL,
    SECRET_CERT_LABEL,
    SECRET_CHAIN_LABEL,
    SECRET_CSR_LABEL,
    SECRET_KEY_LABEL,
    TlsManagementState,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload
from single_kernel_mongo.workload.mongos_workload import MongosWorkload

if TYPE_CHECKING:
    pass


class Sans(TypedDict):
    """A Typed Dict for a Sans."""

    sans_ips: list[str]
    sans_dns: list[str]


logger = logging.getLogger(__name__)


class TLSManager(ManagerStatusProtocol):
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
        self.state: CharmState = state
        self.substrate = self.dependent.substrate
        self.name = "tls"

    def get_certificate_request_attributes(self) -> CertificateRequestAttributes:
        """Generate a certificate signing request attributes."""
        subject_name = self.state.get_subject_name()
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

        if (
            self.state.is_role(MongoDBRoles.MONGOS)
            and self.substrate == Substrates.VM
            and not self.state.app_peer_data.external_connectivity
        ):
            sans["sans_dns"].append(f"{self.state.paths.socket_path}")

        return sans

    def get_tls_file_contents(self, internal: bool) -> tuple[str | None, str | None]:
        """Prepare TLS files in special MongoDB way.

        MongoDB needs two files:
        — CA file should have a full chain.
        — PEM file should have private key and certificate without certificate chain.
        """
        scope = TLSType.PEER.value if internal else TLSType.CLIENT.value
        if not self.state.tls.is_tls_enabled(internal):
            logging.debug(f"{scope} TLS disabled.")
            return None, None
        logging.debug(f"{scope} TLS *enabled*, fetching data for CA and PEM files ")

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
        self.state.tls.set_secret(internal, SECRET_CSR_LABEL, None)
        self.state.tls.set_secret(internal, SECRET_CHAIN_LABEL, None)
        self.state.tls.set_secret(internal, SECRET_KEY_LABEL, None)

        if internal:
            self.state.update_peer_ca_secrets(new_ca=None)
        else:
            self.dependent.state.update_client_ca_secrets(new_ca=None)

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

        if self.is_waiting_for_a_cert():
            logger.info("Still waiting for a certificate, delaying restart.")
            return

        try:
            self.dependent.restart_charm_services(force=True)
        except WorkloadServiceError as e:
            # TODO should we defer or just error
            logger.error("An exception occurred when starting mongod agent, error: %s.", str(e))
            return

    def delete_certificates_from_workload(self, internal: bool) -> None:
        """Deletes the certificates from the workload."""
        logger.info(
            f"Deleting {TLSType.PEER.value if internal else TLSType.CLIENT.value} TLS certificates from filesystem"
        )

        path = (
            self.workload.paths.tls_peer_files if internal else self.workload.paths.tls_client_files
        )
        for file in path:
            if self.workload.exists(file):
                self.workload.delete(file)

        if self.substrate == Substrates.VM:
            return

        if not internal:
            local_keyfile_file = self.state.paths.ext_pem_file
            local_ca_file = self.state.paths.ext_ca_file
            for file in (local_keyfile_file, local_ca_file):
                if file.exists() and file.is_file():
                    file.unlink()

    def push_tls_files_to_workload(self, internal: bool) -> None:
        """Pushes the TLS files on the workload."""
        logger.info(
            f"Pushing {TLSType.PEER.value if internal else TLSType.CLIENT.value} TLS certificates to filesystem"
        )
        ca, pem = self.get_tls_file_contents(internal=internal)

        if internal:
            if ca:
                self.workload.write(self.workload.paths.int_ca_file, ca)
            if pem:
                self.workload.write(self.workload.paths.int_pem_file, pem)
        else:
            if ca:
                self.workload.write(self.workload.paths.ext_ca_file, ca)
            if pem:
                self.workload.write(self.workload.paths.ext_pem_file, pem)

        if self.substrate == Substrates.VM:
            return

        if not internal and ca:
            self.state.paths.ext_ca_file.write_text(ca)
            self.state.paths.ext_ca_file.chmod(600)
        if not internal and pem:
            self.state.paths.ext_pem_file.write_text(pem)
            self.state.paths.ext_ca_file.chmod(600)

    def set_certificates(
        self,
        secret_chain: list[str] | None,
        certificate: str | None,
        csr: str | None,
        ca: str | None,
        private_key: str | None,
        internal: bool,
    ):
        """Sets the certificates."""
        self.state.tls.set_secret(
            internal,
            SECRET_CHAIN_LABEL,
            "\n".join(secret_chain) if secret_chain else None,
        )
        self.state.tls.set_secret(internal, SECRET_KEY_LABEL, private_key)
        self.state.tls.set_secret(internal, SECRET_CSR_LABEL, csr)
        self.state.tls.set_secret(internal, SECRET_CERT_LABEL, certificate)
        self.state.tls.set_secret(internal, SECRET_CA_LABEL, ca)
        logger.info(
            f"{TLSType.PEER.value if internal else TLSType.CLIENT.value} certificate secrets updated."
        )

    def is_certificate_available(self, internal: bool) -> bool:
        """Checks if we've received the expected certificate."""
        csr = self.get_certificate_request_attributes()
        cert, key = self.dependent.tls_events.tls_mapping[internal].get_assigned_certificate(csr)
        return bool(cert and key)

    def is_waiting_for_a_cert(self) -> bool:
        """Returns a boolean indicating whether additional certs are needed."""
        if self.state.peer_tls_relation and not self.is_certificate_available(internal=True):
            logger.debug("Waiting for peer certificate.")
            return True

        if self.state.client_tls_relation and not self.is_certificate_available(internal=False):
            logger.debug("Waiting for client certificate.")
            return True

        return False

    def get_tls_management_state(self) -> TlsManagementState:
        """Pre-checks on TLS certificates management."""
        if self.dependent.refresh_in_progress and self.initial_integration():
            return TlsManagementState.UPGRADE_IN_PROGRESS
        if self.state.is_role(MongoDBRoles.MONGOS) and self.state.config_server_name is None:
            return TlsManagementState.MONGOS_MISSING_CONFIG_SERVER
        if not self.state.db_initialised:
            if self.state.is_role(MongoDBRoles.MONGOS):
                return TlsManagementState.MONGOS_DB_NOT_INITIALIZED
            return TlsManagementState.DB_NOT_INTIALIZED
        return TlsManagementState.EMPTY

    def update_private_keys(self):
        """Updates the private keys."""
        peer_private_key = None
        client_private_key = None

        self.state.statuses.delete(
            TLSStatuses.INVALID_PEER_PRIVATE_KEY.value,
            scope="unit",
            component=self.dependent.name,
        )
        self.state.statuses.delete(
            TLSStatuses.INVALID_CLIENT_PRIVATE_KEY.value,
            scope="unit",
            component=self.dependent.name,
        )

        initial_peer_private_key = self.state.tls.peer_private_key
        initial_client_private_key = self.state.tls.client_private_key

        if tls_peer_private_key_id := self.dependent.config.tls_peer_private_key_id:
            if peer_private_key := self.update_private_key(tls_peer_private_key_id, internal=True):
                self.dependent.tls_events.peer_certificate._private_key = peer_private_key

        if tls_client_private_key_id := self.dependent.config.tls_client_private_key_id:
            if client_private_key := self.update_private_key(
                tls_client_private_key_id, internal=False
            ):
                self.dependent.tls_events.client_certificate._private_key = client_private_key

        if tls_peer_private_key_id and not peer_private_key:
            self.state.statuses.add(
                TLSStatuses.INVALID_PEER_PRIVATE_KEY.value,
                scope="unit",
                component=self.dependent.name,
            )

        if tls_client_private_key_id and not client_private_key:
            self.state.statuses.add(
                TLSStatuses.INVALID_CLIENT_PRIVATE_KEY.value,
                scope="unit",
                component=self.dependent.name,
            )

        peer_private_key_updated = peer_private_key is not None and (
            initial_peer_private_key != peer_private_key
        )
        client_private_key_updated = client_private_key is not None and (
            initial_client_private_key != client_private_key
        )

        # refresh certificates only if the value was updated.
        if peer_private_key_updated or client_private_key_updated:
            self.dependent.tls_events.refresh_certificates()

    def update_private_key(self, private_key_secret_id: str, internal: bool) -> PrivateKey | None:
        """Stores the new private key in the relation."""
        if private_key := self.read_and_validate_private_key(private_key_secret_id):
            self.state.tls.set_secret(internal, SECRET_KEY_LABEL, private_key.raw)
            return private_key

        logger.error(
            f"Invalid {'peer' if internal else 'client'} private key provided, cannot update TLS certificates."
        )
        return None

    def read_and_validate_private_key(self, private_key_secret_id: str) -> PrivateKey | None:
        """Reads the private key from the secret and validates it."""
        try:
            secret_content = self.dependent.state.get_secret_from_id(private_key_secret_id).get(
                "private-key"
            )
        except (ModelError, SecretNotFoundError) as e:
            logger.error(e)
            return None

        if secret_content is None:
            logger.error(f"Secret {private_key_secret_id} does not contain a private key.")
            return None

        try:
            _private_key = (
                secret_content
                if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", secret_content)
                else base64.b64decode(secret_content).decode("utf-8").strip()
            )
        except UnicodeDecodeError:
            logger.error("base64 decoding error, invalid key.")
            return None
        private_key = PrivateKey(raw=_private_key)
        if not private_key.is_valid():
            logger.error("Invalid private key format.")
            return None

        return private_key

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Returns the current status of the tls-manager."""
        charm_statuses = []

        if not recompute:
            return self.state.statuses.get(scope=scope, component=self.name).root

        if scope == "app":
            return []

        if tls_peer_private_key_id := self.dependent.config.tls_peer_private_key_id:
            if not self.update_private_key(tls_peer_private_key_id, internal=True):
                charm_statuses.append(TLSStatuses.INVALID_PEER_PRIVATE_KEY.value)

        if tls_client_private_key_id := self.dependent.config.tls_client_private_key_id:
            if not self.update_private_key(tls_client_private_key_id, internal=False):
                charm_statuses.append(TLSStatuses.INVALID_CLIENT_PRIVATE_KEY.value)

        return charm_statuses

    def initial_integration(self) -> bool:
        """Checks if the certificate available event runs for the first time or not."""
        if not self.workload.exists(self.workload.paths.ext_pem_file):
            return True
        if not self.workload.exists(self.workload.paths.int_pem_file):
            return True
        return False
