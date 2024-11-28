#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS Manager.

Handles MongoDB TLS Files.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import TYPE_CHECKING, TypedDict

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from single_kernel_mongo.config.literals import Scope, Substrates
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.tls_state import (
    SECRET_CA_LABEL,
    SECRET_CERT_LABEL,
    SECRET_CHAIN_LABEL,
    SECRET_CSR_LABEL,
    SECRET_KEY_LABEL,
    WAIT_CERT_UPDATE,
)
from single_kernel_mongo.utils.helpers import parse_tls_file
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class Sans(TypedDict):
    """A Typed Dict for a Sans."""

    sans_ip: list[str]
    sans_dns: list[str]


logger = logging.getLogger(__name__)


class TLSManager:
    """Manager for building necessary files for mongodb."""

    def __init__(
        self,
        charm: AbstractMongoCharm,
        workload: MongoDBWorkload,
        state: CharmState,
        substrate: Substrates,
    ) -> None:
        self.charm = charm
        self.workload = workload
        self.state = state
        self.substrate = substrate

    def generate_certificate_request(self, param: str | None, internal: bool):
        """Generate a TLS Certificate request."""
        key: bytes
        if param is None:
            key = generate_private_key()
        else:
            key = parse_tls_file(param)

        sans = self.get_new_sans()
        csr = generate_csr(
            private_key=key,
            subject=self._get_subject_name(),
            organization=self._get_subject_name(),
            sans=sans["sans_dns"],
            sans_ip=sans["sans_ip"],
        )
        self.set_tls_secret(internal, SECRET_KEY_LABEL, key.decode("utf-8"))
        self.set_tls_secret(internal, SECRET_CSR_LABEL, csr.decode("utf-8"))
        self.set_tls_secret(internal, SECRET_CERT_LABEL, None)

        label = "int" if internal else "ext"

        self.state.unit_peer_data.update({f"{label}_certs_subject": self._get_subject_name()})

    def generate_new_csr(self, internal: bool) -> tuple[bytes, bytes]:
        """Requests the renewal of a certificate.

        Returns:
            old_csr: The old certificate signing request.
            new_csr: the new_certificate signing request.
        """
        key_str = self.get_tls_secret(internal, SECRET_KEY_LABEL)
        old_csr_str = self.get_tls_secret(internal, SECRET_CSR_LABEL)
        if not key_str or not old_csr_str:
            raise Exception("Trying to renew a non existent certificate. Please fix.")

        key = key_str.encode("utf-8")
        old_csr = old_csr_str.encode("utf-8")
        sans = self.get_new_sans()
        new_csr = generate_csr(
            private_key=key,
            subject=self._get_subject_name(),
            organization=self._get_subject_name(),
            sans=sans["sans_dns"],
            sans_ip=sans["sans_ip"],
        )
        logger.debug("Requesting a certificate renewal.")

        self.set_tls_secret(internal, SECRET_CSR_LABEL, new_csr.decode("utf-8"))
        self.set_waiting_for_cert_to_update(waiting=True, internal=internal)
        return old_csr, new_csr

    def get_new_sans(self) -> Sans:
        """Create a list of DNS names for a MongoDB unit.

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
            sans_ip=[str(self.state.bind_address)],
        )

        if (
            self.state.is_role(MongoDBRoles.MONGOS)
            and self.state.app_peer_data.external_connectivity
        ):
            sans["sans_ip"].append(self.state.unit_peer_data.host)

        return sans

    def get_current_sans(self, internal: bool) -> Sans | None:
        """Gets the current SANs for the unit cert."""
        # if unit has no certificates do not proceed.
        if not self.state.tls.is_tls_enabled(internal=internal):
            return None

        pem_file = self.get_tls_secret(internal, SECRET_CERT_LABEL)
        if not pem_file:
            logger.info("No PEM file but TLS enabled.")
            raise Exception("No PEM file but TLS enabled. Please, fix.")
        try:
            cert = x509.load_pem_x509_certificate(pem_file.encode(), default_backend())
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans_ip = [str(san) for san in sans.get_values_for_type(x509.IPAddress)]
            sans_dns = [str(san) for san in sans.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            sans_ip = []
            sans_dns = []

        return Sans(sans_ip=sorted(sans_ip), sans_dns=sorted(sans_dns))

    def get_tls_files(self, internal: bool) -> tuple[str | None, str | None]:
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

        ca = self.get_tls_secret(internal, SECRET_CA_LABEL)
        chain = self.get_tls_secret(internal, SECRET_CHAIN_LABEL)
        ca_file = chain if chain else ca

        key = self.get_tls_secret(internal, SECRET_KEY_LABEL)
        cert = self.get_tls_secret(internal, SECRET_CERT_LABEL)
        pem_file = key
        if cert:
            pem_file = key + "\n" + cert if key else cert

        return ca_file, pem_file

    def disable_certificates_for_unit(self):
        """Disables the certificates on relation broken."""
        for internal in [True, False]:
            self.set_tls_secret(internal, SECRET_CA_LABEL, None)
            self.set_tls_secret(internal, SECRET_CERT_LABEL, None)
            self.set_tls_secret(internal, SECRET_CHAIN_LABEL, None)

        if self.state.is_role(MongoDBRoles.CONFIG_SERVER):
            # self.state.cluster.update_ca_secret(new_ca=None)
            # self.state.config_server.update_ca_secret(new_ca=None)
            pass

        self.charm.status_manager.to_maintenance("Disabling TLS")
        self.delete_certificates_from_workload()
        self.workload.restart()
        self.charm.status_manager.to_active(None)

    def delete_certificates_from_workload(self):
        """Deletes the certificates from the workload."""
        logger.info("Deleting TLS certificate from VM")

        for file in self.workload.paths.tls_files:
            self.workload.delete(file)

    def push_tls_files_to_workload(self) -> None:
        """Pushes the TLS files on the workload."""
        external_ca, external_pem = self.get_tls_files(internal=False)
        internal_ca, internal_pem = self.get_tls_files(internal=True)
        if external_ca is not None:
            self.workload.write(self.workload.paths.ext_ca_file, external_ca)
        if external_pem is not None:
            self.workload.write(self.workload.paths.ext_pem_file, external_pem)
        if internal_ca is not None:
            self.workload.write(self.workload.paths.int_ca_file, internal_ca)
        if internal_pem is not None:
            self.workload.write(self.workload.paths.int_pem_file, internal_pem)

    def set_certificates(
        self,
        certificate_signing_request: str,
        secret_chain: list[str] | None,
        certificate: str | None,
        ca: str | None,
    ):
        """Sets the certificates."""
        int_csr = self.get_tls_secret(internal=True, label_name=SECRET_CSR_LABEL)
        ext_csr = self.get_tls_secret(internal=False, label_name=SECRET_CSR_LABEL)
        if ext_csr and certificate_signing_request.rstrip() == ext_csr.rstrip():
            logger.debug("The external TLS certificate available.")
            internal = False
        elif int_csr and certificate_signing_request.rstrip() == int_csr.rstrip():
            logger.debug("The internal TLS certificate available.")
            internal = True
        else:
            logger.error("An unknown certificate is available -- ignoring.")
            return

        self.set_tls_secret(
            internal,
            SECRET_CHAIN_LABEL,
            "\n".join(secret_chain) if secret_chain is not None else None,
        )
        self.set_tls_secret(internal, SECRET_CERT_LABEL, certificate)
        self.set_tls_secret(internal, SECRET_CA_LABEL, ca)
        self.set_waiting_for_cert_to_update(internal=internal, waiting=False)

    def set_waiting_for_cert_to_update(self, internal: bool, waiting: bool) -> None:
        """Sets the databag."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{WAIT_CERT_UPDATE}"
        self.state.unit_peer_data.update({label_name: json.dumps(waiting)})

    def is_set_waiting_for_cert_to_update(
        self,
        internal: bool = False,
    ) -> bool:
        """Returns True if we are waiting for a cert to update."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{WAIT_CERT_UPDATE}"

        return json.loads(self.state.unit_peer_data.get(label_name) or "false")

    def is_waiting_for_both_certs(self) -> bool:
        """Returns a boolean indicating whether additional certs are needed."""
        if not self.get_tls_secret(internal=True, label_name=SECRET_CERT_LABEL):
            logger.debug("Waiting for internal certificate.")
            return True
        if not self.get_tls_secret(internal=False, label_name=SECRET_CERT_LABEL):
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

    def set_tls_secret(self, internal: bool, label_name: str, contents: str | None) -> None:
        """Sets TLS secret, based on whether or not it is related to internal connections."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{label_name}"
        if not contents:
            self.state.secrets.remove(Scope.UNIT, label_name)
            return
        self.state.secrets.set(label_name, contents, Scope.UNIT)

    def get_tls_secret(self, internal: bool, label_name: str) -> str | None:
        """Gets TLS secret, based on whether or not it is related to internal connections."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{label_name}"
        return self.state.secrets.get_for_key(Scope.UNIT, label_name)
