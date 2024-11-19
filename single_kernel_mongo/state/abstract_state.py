# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The charm state for mongo charms (databags + model information)."""

from typing import Generic, TypeVar

from ops.model import Application, Relation, Unit
from pydantic import BaseModel

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    Data,
)

PModel = TypeVar("PModel", bound=BaseModel, covariant=True)
PData = TypeVar("PData", bound=Data, covariant=True)


class AbstractRelationState(Generic[PModel, PData]):
    """Relation state object."""

    atype: type[PModel]

    def __init__(
        self,
        relation: Relation | None,
        data_interface: PData,
        component: Unit | Application | None,
        substrate: Substrates | None = None,
    ):
        self.relation = relation
        self.data_interface = data_interface
        self.component = component
        self.substrate = substrate
        self._relation_data = self.data_interface.as_dict(self.relation.id) if self.relation else {}

    @property
    def relation_data(self) -> PModel:
        """Relation data as a pydantic model."""
        return self.atype.model_validate(self._relation_data)

    def __bool__(self) -> bool:
        """Boolean evaluation based on the existence of self.relation."""
        try:
            return bool(self.relation)
        except AttributeError:
            return False

    def update(self, items: dict[str, str]) -> None:
        """Writes to relation_data."""
        delete_fields = [key for key in items if not items[key]]
        update_content = {k: items[k] for k in items if k not in delete_fields}

        self._relation_data.update(update_content)

        for field in delete_fields:
            del self._relation_data[field]

    def get(self, key: str) -> str:
        """Gets a key."""
        if not self.relation:
            return ""
        return (
            self.data_interface.fetch_relation_field(relation_id=self.relation.id, field=key) or ""
        )
