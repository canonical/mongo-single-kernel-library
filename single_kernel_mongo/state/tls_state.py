#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS state."""

from enum import Enum

from ops import Relation
from ops.model import Unit

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.lib.charms.tls_certificates_interface.v4.tls_certificates import PrivateKey

SECRET_KEY_LABEL = "key-secret"
SECRET_CA_LABEL = "ca-secret"
SECRET_CSR_LABEL = "csr-secret"
SECRET_CERT_LABEL = "cert-secret"
SECRET_CHAIN_LABEL = "chain-secret"
INT_CERT_SECRET_KEY = "int-cert-secret"
EXT_CERT_SECRET_KEY = "ext-cert-secret"


class TlsManagementState(Enum):
    """TLS management state that can be mapped to a status."""

    EMPTY = ""
    UPGRADE_IN_PROGRESS = "Upgrade in progress."
    DB_NOT_INTIALIZED = "DB is not initialized."
    MONGOS_MISSING_CONFIG_SERVER = "mongos is not running (not integrated to config-server)."
    MONGOS_DB_NOT_INITIALIZED = "mongos DB is not initialized."


class TLSState:
    """The stored state for the TLS relation."""

    component: Unit

    def __init__(
        self, peer_relation: Relation | None, client_relation: Relation | None, secrets: SecretCache
    ):
        self.peer_relation = peer_relation
        self.client_relation = client_relation
        self.secrets = secrets

    @property
    def peer_enabled(self) -> bool:
        """Is peer TLS enabled."""
        return (
            self.peer_relation is not None
            and self.secrets.get_for_key(Scope.UNIT, INT_CERT_SECRET_KEY) is not None
        )

    @property
    def client_enabled(self) -> bool:
        """Is client TLS enabled."""
        return (
            self.client_relation is not None
            and self.secrets.get_for_key(Scope.UNIT, EXT_CERT_SECRET_KEY) is not None
        )

    def is_tls_enabled(self, internal: bool) -> bool:
        """Is TLS enabled for ::internal."""
        match internal:
            case True:
                return self.peer_enabled
            case False:
                return self.client_enabled

    def set_secret(self, internal: bool, label_name: str, contents: str | None) -> None:
        """Sets TLS secret, based on whether or not it is related to internal connections."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{label_name}"
        if not contents:
            self.secrets.remove(Scope.UNIT, label_name)
            return
        self.secrets.set(label_name, contents, Scope.UNIT)

    def get_secret(self, internal: bool, label_name: str) -> str | None:
        """Gets TLS secret, based on whether or not it is related to internal connections."""
        scope = "int" if internal else "ext"
        label_name = f"{scope}-{label_name}"
        return self.secrets.get_for_key(Scope.UNIT, label_name)

    @property
    def client_private_key(self) -> PrivateKey | None:
        """Private key for the client relation."""
        private_key_str = self.get_secret(internal=False, label_name=SECRET_KEY_LABEL)
        return PrivateKey(private_key_str) if private_key_str else None

    @property
    def peer_private_key(self) -> PrivateKey | None:
        """Private key for the peer relation."""
        private_key_str = self.get_secret(internal=True, label_name=SECRET_KEY_LABEL)
        return PrivateKey(private_key_str) if private_key_str else None
