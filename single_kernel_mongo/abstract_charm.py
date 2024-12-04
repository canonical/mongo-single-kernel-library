# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Skeleton for the abstract charm."""

import logging
from typing import ClassVar, Generic, TypeVar

from ops.charm import CharmBase

from single_kernel_mongo.config.literals import Substrates
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoConfigModel
from single_kernel_mongo.events.lifecycle import LifecycleEventsHandler
from single_kernel_mongo.status import StatusManager

T = TypeVar("T", bound=MongoConfigModel)
U = TypeVar("U", bound=OperatorProtocol)

logger = logging.getLogger(__name__)


class AbstractMongoCharm(Generic[T, U], CharmBase):
    """An abstract mongo charm.

    This class is meant to be inherited from to define an actual charm.
    Any charm inheriting from this class should specify:
     * config_type: A Pydantic Model defining the configuration options,
         inheriting from `MongoConfigModel`.
     * operator_type: An operator class which implements the OperatorProtocol protocol.
     * A substrate: One of "vm" or "k8s"
     * A peer-relation name: A RelationName element, usually `database-peers` or `router-peers`
     * A name: The name of the charm which will be used in multiple places.
    """

    config_type: type[T]
    operator_type: type[U]
    substrate: ClassVar[Substrates]
    peer_rel_name: ClassVar[str]
    name: ClassVar[str]

    def __init__(self, *args):
        # Init the Juju object Object
        super().__init__(*args)
        self.status_manager = StatusManager(self)

        # Create the operator instance (one of MongoDBOperator or MongosOperator)
        self.operator = self.operator_type(self)

        # We will use the main workload of the Charm to install the snap.
        # A workload represents a service, and the main workload represents the
        # mongod or mongos service.
        self.workload = self.operator.workload

        self.framework.observe(getattr(self.on, "install"), self.on_install)
        self.framework.observe(getattr(self.on, "leader_elected"), self.on_leader_elected)

        # Register the role events handler after the global ones so that they get the priority.
        # Those lifecycle events are bound to the operator we defined, which
        # implements the handlers for all lifecycle and peer relation events.
        self.lifecycle = LifecycleEventsHandler(self.operator, self.peer_rel_name)

    @property
    def parsed_config(self) -> T:
        """Return the config parsed as a pydantic model."""
        return self.config_type.model_validate(self.model.config)

    def on_install(self, _):
        """First install event handler."""
        if self.substrate == Substrates.VM:
            self.status_manager.to_maintenance("installing MongoDB")
            if not self.workload.install():
                self.status_manager.to_blocked("couldn't install MongoDB")
                return
            self.status_manager.to_maintenance("Installed MongoDB")

    def on_leader_elected(self, _):
        """First leader elected handler."""
        # FIXME: Check role status in databag first.

        # Sets the role in the databag.
        self.operator.state.app_peer_data.role = self.parsed_config.role
