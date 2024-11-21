# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Skeleton for the abstract charm."""

import logging
from typing import ClassVar, TypeVar

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.core.structured_config import MongoConfigModel
from single_kernel_mongo.core.typed_charm import TypedCharmBase
from single_kernel_mongo.events.lifecycle import LifecycleEventsHandler
from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator
from single_kernel_mongo.status import StatusManager

T = TypeVar("T", bound=MongoConfigModel)

logger = logging.getLogger(__name__)


class AbstractMongoCharm(TypedCharmBase[T]):
    """An abstract mongo charm."""

    config_type: type[T]
    substrate: ClassVar[Substrates]
    peer_rel_name: ClassVar[str]
    name: ClassVar[str]

    def __init__(self, *args):
        super().__init__(*args)
        self.status_manager = StatusManager(self)
        self.operator = MongoDBOperator(self)
        self.workload = self.operator.workload

        self.framework.observe(getattr(self.on, "install"), self.on_install)
        self.framework.observe(getattr(self.on, "leader_elected"), self.on_leader_elected)

        # Register the role events handler after the global ones so that they get the priority.
        self.lifecycle = LifecycleEventsHandler(self.operator, self.peer_rel_name)

    def on_install(self, _):
        """First install event handler."""
        if self.substrate == "vm":
            self.status_manager.to_maintenance("installing MongoDB")
            if not self.workload.install():
                self.status_manager.to_blocked("couldn't install MongoDB")
                return

    def on_leader_elected(self, _):
        """Set the role in the databag."""
        self.operator.state.app_peer_data.role = self.parsed_config.role
