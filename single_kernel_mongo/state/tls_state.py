#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS state."""

from ops import Relation
from ops.model import Unit

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.secrets import SecretCache

SECRET_KEY_LABEL = "key-secret"
SECRET_CA_LABEL = "ca-secret"
SECRET_CERT_LABEL = "cert-secret"
SECRET_CSR_LABEL = "csr-secret"
SECRET_CHAIN_LABEL = "chain-secret"
WAIT_CERT_UPDATE = "wait-cert-updated"
INT_CERT_SECRET_KEY = "int-cert-secret"
EXT_CERT_SECRET_KEY = "ext-cert-secret"


class TLSState:
    """The stored state for the TLS relation."""

    component: Unit

    def __init__(self, relation: Relation | None, secrets: SecretCache):
        self.relation = relation
        self.secrets = secrets

    @property
    def internal_enabled(self) -> bool:
        """Is internal TLS enabled."""
        return (
            self.relation is not None
            and self.secrets.get_for_key(Scope.UNIT, INT_CERT_SECRET_KEY) is not None
        )

    @property
    def external_enabled(self) -> bool:
        """Is external TLS enabled."""
        return (
            self.relation is not None
            and self.secrets.get_for_key(Scope.UNIT, EXT_CERT_SECRET_KEY) is not None
        )

    def is_tls_enabled(self, internal: bool) -> bool:
        """Is TLS enabled for ::internal."""
        match internal:
            case True:
                return self.internal_enabled
            case False:
                return self.external_enabled

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
