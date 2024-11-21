#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Pydantic Typed charm."""

from typing import Generic, TypeVar

from ops.charm import CharmBase
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class TypedCharmBase(CharmBase, Generic[T]):
    """Class to be used for extending config-typed charms."""

    config_type: type[T]

    @property
    def parsed_config(self) -> T:
        """Return the config parsed as a pydantic model."""
        return self.config_type.model_validate(self.model.config)
