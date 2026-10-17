# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The OAuth state: each unit's identity provider CA chain."""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import Enum
from typing import TYPE_CHECKING

from cryptography import x509
from ops import Relation
from ops.model import Application

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import DataPeerData
from single_kernel_mongo.state.abstract_state import AbstractRelationState

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class OAuthStateKeys(str, Enum):
    """OAuth state keys on the oauth-peers relation."""

    # Unit secret: the certificate set this unit received over oauth-certificate-transfer.
    CHAIN = "oauth-chain"


class OAuthState(AbstractRelationState[DataPeerData]):
    """The stored state for the OAuth integration (shaped like LdapState)."""

    component: Application

    def __init__(
        self,
        charm: AbstractMongoCharm,
        relation: Relation | None,
        data_interface: DataPeerData,
        component: Application,
    ):
        super().__init__(relation, data_interface=data_interface, component=component)
        self.data_interface = data_interface
        self.secrets = SecretCache(charm=charm, relation=self.data_interface.relation_name)

    # Certificates received over oauth-certificate-transfer

    @staticmethod
    def load_certificates(certificates: Iterable[str]) -> list[x509.Certificate]:
        """Parses a certificate set; an entry may hold several PEM certificates.

        Raises:
            ValueError: If an entry holds no PEM certificate or a malformed one.
        """
        loaded: list[x509.Certificate] = []
        entries = sorted(certificates)
        for index, entry in enumerate(entries):
            try:
                loaded += x509.load_pem_x509_certificates(entry.encode())
            except ValueError as err:
                raise ValueError(f"entry {index + 1} of {len(entries)}: {err}") from err
        return loaded

    @staticmethod
    def is_ca(certificate: x509.Certificate) -> bool:
        """Whether the certificate carries the CA basic constraint."""
        try:
            return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except (x509.ExtensionNotFound, ValueError):
            return False

    # Certificates (unit secret)

    @property
    def chain(self) -> list[str] | None:
        """The identity provider CA certificates this unit received, sorted."""
        return json.loads(
            self.secrets.get_for_key(Scope.UNIT, OAuthStateKeys.CHAIN.value) or "null"
        )

    @chain.setter
    def chain(self, value: list[str] | None) -> None:
        # Update-status stores the chain again: only a change creates a secret revision.
        new_chain = sorted(value) if value else None
        if new_chain == self.chain:
            return
        if not new_chain:
            self.secrets.remove(Scope.UNIT, OAuthStateKeys.CHAIN.value)
            return
        self.secrets.set(OAuthStateKeys.CHAIN.value, json.dumps(new_chain), Scope.UNIT)

    @property
    def bundle(self) -> str | None:
        """The chain as one PEM bundle: the file content and the value shared with routers."""
        if not (chain := self.chain):
            return None
        return "\n".join(chain)

    @bundle.setter
    def bundle(self, value: str | None) -> None:
        # Routers keep the bundle shared by the config-server as a one-entry chain.
        self.chain = [value] if value else None
