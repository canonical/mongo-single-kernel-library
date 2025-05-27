# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""The charm state for mongo charms (databags + model information)."""

from typing import Generic, TypeVar

from ops.model import Application, Relation, Unit

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (  # type: ignore
    Data,
)

PData = TypeVar("PData", bound=Data, covariant=True)


class AbstractRelationState(Generic[PData]):
    """Relation state object."""

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
        self.relation_data = self.data_interface.as_dict(self.relation.id) if self.relation else {}

    def __bool__(self) -> bool:
        """Boolean evaluation based on the existence of self.relation."""
        try:
            return bool(self.relation)
        except AttributeError:
            return False

    def update(self, items: dict[str, str | None]) -> None:
        """Updates the data in the databag.

        It will add/update/delete the data in the databag according to the following scheme:
         * If the provided value is None, the key field be deleted from the databag if it exists.
         * If the field does not exist, it will be created and set to the provided value
         * If the field already existed, the value will be updated to the provided value.
        """
        delete_fields = [key for key in items if not items[key]]
        update_content = {k: items[k] for k in items if k not in delete_fields}

        self.relation_data.update(update_content)

        for field in delete_fields:
            if self.relation_data.get(field, None):
                del self.relation_data[field]

    def get(self, key: str, default: str = "") -> str:
        """Gets a key."""
        if not self.relation:
            return default
        return (
            self.data_interface.fetch_my_relation_field(relation_id=self.relation.id, field=key)
            or default
        )

    @property
    def name(self) -> str:
        """The name of this component."""
        if self.component:
            return self.component.name
        return ""
