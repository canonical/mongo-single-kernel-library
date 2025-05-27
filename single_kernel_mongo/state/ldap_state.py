#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The Ldap state."""

from __future__ import annotations

import json
from collections.abc import Iterator
from enum import Enum
from typing import TYPE_CHECKING

from ldap3.utils.uri import parse_uri
from ops import Relation
from ops.model import Application

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.secrets import SecretCache
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import DataPeerData
from single_kernel_mongo.lib.charms.glauth_k8s.v0.ldap import LdapProviderData
from single_kernel_mongo.state.abstract_state import AbstractRelationState

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class LdapStateKeys(str, Enum):
    """LDAP State Model."""

    # From Glauth k8s through ldap relation
    BIND_DN = "bind-dn"
    BIND_PASSWORD = "bind-password"
    BASE_DN = "base-dn"
    LDAPS_URLS = "ldaps_urls"

    # From Glauth k8s through send-ca-cert relation
    CERTIFICATE = "ldap-certificate"
    CA = "ldap-ca"
    CHAIN = "ldap-chain"

    # config options
    LDAP_USER_TO_DN_MAPPING = "ldap-user-to-dn-mapping"
    LDAP_QUERY_TEMPLATE = "ldap-query-template"


class LdapState(AbstractRelationState[DataPeerData]):
    """The stored state for the Ldap relation."""

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

    def set_from(self, provider_data: LdapProviderData) -> None:
        """Sets everything from LdapProviderData."""
        self.bind_user = provider_data.bind_dn
        self.bind_password = provider_data.bind_password
        self.base_dn = provider_data.base_dn
        self.ldaps_urls = provider_data.ldaps_urls

    def clean_databag(self) -> None:
        """Removes the credentials and base DN from the databag."""
        self.bind_user = None
        self.bind_password = None
        self.base_dn = None
        self.ldaps_urls = None

    def set_certificates(
        self, certificate: str | None, ca: str | None, chain: list[str] | None
    ) -> None:
        """Removes the credentials and base DN from the databag."""
        self.certificate = certificate
        self.ca = ca
        self.chain = chain
        self.secrets.get(Scope.UNIT)

    def clean_certificates(self) -> None:
        """Removes the certificate secrets."""
        self.ca = None
        self.chain = None
        self.certificate = None

    def is_ready(self) -> bool:
        """Checks if we can restart the unit."""
        return (
            self.relation is not None
            and self.bind_user is not None
            and self.bind_password is not None
            and self.base_dn is not None
            and self.ldaps_urls is not None
            and self.certificate is not None
            and self.ca is not None
            and self.chain is not None
        )

    def ldap_ready(self) -> bool:
        """Checks if ldap relation is correctly integrated."""
        return (
            self.relation is not None
            and self.bind_user is not None
            and self.bind_password is not None
            and self.base_dn is not None
            and self.ldaps_urls is not None
        )

    def ldap_certs_ready(self) -> bool:
        """Checks if ldap relation is correctly integrated."""
        return (
            self.relation is not None
            and self.certificate is not None
            and self.ca is not None
            and self.chain is not None
        )

    @property
    def bind_user(self) -> str | None:
        """The bind user."""
        return self.secrets.get_for_key(Scope.APP, LdapStateKeys.BIND_DN.value)

    @bind_user.setter
    def bind_user(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.APP, LdapStateKeys.BIND_DN.value)
            return
        self.secrets.set(LdapStateKeys.BIND_DN.value, value, Scope.APP)

    @property
    def bind_password(self) -> str | None:
        """The bind password."""
        return self.secrets.get_for_key(Scope.APP, LdapStateKeys.BIND_PASSWORD.value)

    @bind_password.setter
    def bind_password(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.APP, LdapStateKeys.BIND_PASSWORD.value)
            return
        self.secrets.set(LdapStateKeys.BIND_PASSWORD.value, value, Scope.APP)

    @property
    def base_dn(self) -> str | None:
        """The base dn for the search."""
        return self.relation_data.get(LdapStateKeys.BASE_DN.value, "")

    @base_dn.setter
    def base_dn(self, value: str | None) -> None:
        self.update({LdapStateKeys.BASE_DN.value: value})

    @property
    def ldaps_urls(self) -> list[str] | None:
        """The ldaps urls for the search."""
        return json.loads(self.relation_data.get(LdapStateKeys.LDAPS_URLS.value, "null"))

    @ldaps_urls.setter
    def ldaps_urls(self, value: list[str] | None) -> None:
        if value is None:
            self.update({LdapStateKeys.LDAPS_URLS.value: value})
            return
        self.update({LdapStateKeys.LDAPS_URLS.value: json.dumps(sorted(value))})

    @property
    def formatted_ldap_urls(self) -> Iterator[str]:
        """LDAP urls formatted for mongodb config."""
        if not (ldaps_urls := self.ldaps_urls):
            return
        for uri in ldaps_urls:
            parsed_uri = parse_uri(uri)
            yield f"{parsed_uri['host']}:{parsed_uri['port']}"

    @property
    def certificate(self) -> str | None:
        """The certificate."""
        return self.secrets.get_for_key(Scope.UNIT, LdapStateKeys.CERTIFICATE.value)

    @certificate.setter
    def certificate(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, LdapStateKeys.CERTIFICATE.value)
            return
        self.secrets.set(LdapStateKeys.CERTIFICATE.value, value, Scope.UNIT)

    @property
    def ca(self) -> str | None:
        """The CA."""
        return self.secrets.get_for_key(Scope.UNIT, LdapStateKeys.CA.value)

    @ca.setter
    def ca(self, value: str | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, LdapStateKeys.CA.value)
            return
        self.secrets.set(LdapStateKeys.CA.value, value, Scope.UNIT)

    @property
    def chain(self) -> list[str] | None:
        """The chain."""
        return json.loads(self.secrets.get_for_key(Scope.UNIT, LdapStateKeys.CHAIN.value) or "null")

    @chain.setter
    def chain(self, value: list[str] | None) -> None:
        if not value:
            self.secrets.remove(Scope.UNIT, LdapStateKeys.CHAIN.value)
            return
        self.secrets.set(LdapStateKeys.CHAIN.value, json.dumps(value), Scope.UNIT)

    @property
    def ldap_user_to_dn_mapping(self) -> str:
        """The LDAP User To DN Mapping configuration used for user authentication."""
        return self.relation_data.get(LdapStateKeys.LDAP_USER_TO_DN_MAPPING.value, "")

    @ldap_user_to_dn_mapping.setter
    def ldap_user_to_dn_mapping(self, value: str) -> None:
        self.update({LdapStateKeys.LDAP_USER_TO_DN_MAPPING.value: value})

    @property
    def ldap_query_template(self) -> str:
        """The LDAP Query Template used for identity users authorisation."""
        return self.relation_data.get(LdapStateKeys.LDAP_QUERY_TEMPLATE.value, "")

    @ldap_query_template.setter
    def ldap_query_template(self, value: str) -> None:
        self.update({LdapStateKeys.LDAP_QUERY_TEMPLATE.value: value})
