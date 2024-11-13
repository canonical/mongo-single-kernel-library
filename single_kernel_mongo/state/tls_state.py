#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS state."""

from ops import Relation
from ops.model import Unit
from pydantic import BaseModel, Field

from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DataPeerUnitData,
)
from single_kernel_mongo.state.abstract_state import AbstractRelationState


class TLSStateModel(BaseModel):
    """The pydantic model for TLS State."""

    ext_ca_secret: str | None = Field(default=None, alias="ext-ca-secret")
    ext_cert_secret: str | None = Field(default=None, alias="ext-cert-secret")
    ext_chain_secret: str | None = Field(default=None, alias="ext-chain-secret")
    ext_csr_secret: str | None = Field(default=None, alias="ext-csr-secret")
    ext_key_secret: str | None = Field(default=None, alias="ext-key-secret")
    int_ca_secret: str | None = Field(default=None, alias="int-ca-secret")
    int_cert_secret: str | None = Field(default=None, alias="int-cert-secret")
    int_chain_secret: str | None = Field(default=None, alias="int-chain-secret")
    int_csr_secret: str | None = Field(default=None, alias="int-csr-secret")
    int_key_secret: str | None = Field(default=None, alias="int-key-secret")
    ext_wait_cert_updated: bool | None = Field(default=None, alias="ext-wait-cert-updated")
    int_wait_cert_updated: bool | None = Field(default=None, alias="int-wait-cert-updated")
    int_certs_subject: str | None = Field(default=None)
    ext_certs_subject: str | None = Field(default=None)


class TLSState(AbstractRelationState[TLSStateModel, DataPeerUnitData]):
    """The stored state for the TLS relation."""

    component: Unit

    def __init__(
        self,
        relation: Relation | None,
        data_interface: DataPeerUnitData,
        component: Unit,
    ):
        super().__init__(relation, data_interface, component, None)
        self.data_interface = data_interface
        self.relation = relation

    @property
    def internal_enabled(self) -> bool:
        """Is internal TLS enabled."""
        return self.relation_data is not None and self.relation_data.int_cert_secret is not None

    @property
    def external_enabled(self) -> bool:
        """Is external TLS enabled."""
        return self.relation_data is not None and self.relation_data.ext_cert_secret is not None

    def is_tls_enabled(self, internal: bool) -> bool:
        """Is TLS enabled for ::internal."""
        match internal:
            case True:
                return self.internal_enabled
            case False:
                return self.external_enabled
