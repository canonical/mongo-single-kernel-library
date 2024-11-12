#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""The TLS state."""

from ops import Relation
from pydantic import BaseModel


class TLSStateModel(BaseModel):
    """The pydantic model for TLS State."""


class TLSState:
    """The stored state for the TLS relation."""

    def __init__(self, relation: Relation | None):
        self.relation = relation

    @property
    def enabled(self) -> bool:
        """Is TLS enabled."""
        return False

    @property
    def relation_data(self) -> TLSStateModel | None:
        """TLS Relation Data."""
        if not self.relation or not self.relation.app:
            return None
        return TLSStateModel.model_validate(self.relation.data[self.relation.app])
