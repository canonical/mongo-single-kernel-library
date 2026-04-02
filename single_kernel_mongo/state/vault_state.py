#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Vault state."""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, final
from urllib.parse import urlparse

from ops import Relation
from pydantic import ValidationError

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.lib.charms.vault_k8s.v0.vault_kv import VaultKvProviderSchema

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class VaultStateKeys(str, Enum):
    """Vault State Model."""

    VAULT_URL = "vault-url"
    CERT = "vault-cert"
    ROLE_ID = "vault-role-id"
    ROLE_SECRET_ID = "vault-role-secret-id"  # nosec: B105
    MOUNT_POINT = "vault-secret-mount-point"
    NONCE = "vault-nonce"


@final
class VaultState:
    """The stored state for Vault."""

    def __init__(self, charm: AbstractMongoCharm, vault_relation: Relation | None):
        self.vault_relation = vault_relation
        self.unit_name = charm.unit.name.replace("/", "-")
        self.secrets = SecretCache(charm=charm, relation=ExternalRequirerRelations.VAULT.value)

    @property
    def vault_enabled(self) -> bool:
        """Is the vault relation enabled."""
        return self.vault_relation is not None

    def set_from(self, provider_data: VaultKvProviderSchema) -> None:
        """Sets everything from VaultKvProviderSchema."""
        self.vault_url = provider_data.vault_url
        self.mount_point = provider_data.mount
        self.ca_certificate = provider_data.ca_certificate
        self.role_id = provider_data.credentials["role-id"]
        self.role_secret_id = provider_data.credentials["role-secret-id"]

    def get(self) -> VaultKvProviderSchema | None:
        """Gets the data model for the provider schema if we have the data."""
        try:
            return VaultKvProviderSchema.model_validate(
                {
                    "vault_url": self.vault_url,
                    "mount": self.mount_point,
                    "ca_certificate": self.ca_certificate,
                    "credentials": json.dumps(
                        {"role-id": self.role_id, "role-secret-id": self.role_secret_id}
                    ),
                }
            )
        except ValidationError:
            return None

    @property
    def ca_certificate(self) -> str | None:
        """The CA certificate."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.CERT.value)

    @ca_certificate.setter
    def ca_certificate(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.CERT.value)
            return
        self.secrets.set(VaultStateKeys.CERT.value, value, Scope.UNIT)

    @property
    def vault_url(self) -> str | None:
        """The vault url."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.VAULT_URL.value)

    @vault_url.setter
    def vault_url(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.VAULT_URL.value)
            return
        self.secrets.set(VaultStateKeys.VAULT_URL.value, value, Scope.UNIT)

    @property
    def mount_point(self) -> str | None:
        """The mount point."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.MOUNT_POINT.value)

    @mount_point.setter
    def mount_point(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.MOUNT_POINT.value)
            return
        self.secrets.set(VaultStateKeys.MOUNT_POINT.value, value, Scope.UNIT)

    @property
    def role_id(self) -> str | None:
        """The role_id point."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.ROLE_ID.value)

    @role_id.setter
    def role_id(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.ROLE_ID.value)
            return
        self.secrets.set(VaultStateKeys.ROLE_ID.value, value, Scope.UNIT)

    @property
    def role_secret_id(self) -> str | None:
        """The role_secret_id point."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.ROLE_SECRET_ID.value)

    @role_secret_id.setter
    def role_secret_id(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.ROLE_SECRET_ID.value)
            return
        self.secrets.set(VaultStateKeys.ROLE_SECRET_ID.value, value, Scope.UNIT)

    @property
    def nonce(self) -> str | None:
        """The nonce point."""
        return self.secrets.get_for_key(Scope.UNIT, VaultStateKeys.NONCE.value)

    @nonce.setter
    def nonce(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, VaultStateKeys.NONCE.value)
            return
        self.secrets.set(VaultStateKeys.NONCE.value, value, Scope.UNIT)

    @property
    def vault_url_tuple(self) -> tuple[str, str]:
        """Returns the tuple combining the servername and port."""
        vault_url = self.vault_url
        if not vault_url:
            return ("", "")
        parsed_url = urlparse(vault_url)
        return (parsed_url.hostname or "", f"{parsed_url.port or 8200}")

    @property
    def vault_secret_path(self) -> str:
        """The secret path in the vault."""
        if not self.mount_point:
            return ""
        return f"{self.mount_point}/data/{self.unit_name}"
