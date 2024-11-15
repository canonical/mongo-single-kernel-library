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

from single_kernel_mongo.config.literals import Scope, Substrates
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.lib.charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.state.tls_state import (
    SECRET_CERT_LABEL,
    SECRET_CSR_LABEL,
    SECRET_KEY_LABEL,
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
