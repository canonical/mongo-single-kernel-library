# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Skeleton for the abstract charm.

This abstract class is inherited by all actual charms that need to define the different ClassVar.
An example can be found in ../tests/unit/mongodb_test_charm/src/charm.py.


When defining a charm, the developer should go this way:
```
class MyCharm(AbstractMongoCharm[MongoDBCharmConfig, MongoDBOperator]):
    config_type = MongoDBCharmConfig
    operator_type = MongoDBOperator
    substrate = Substrates.VM
    peer_rel_name = PeerRelationNames.PEERS
    name = "mongodb-test"

```

This defines a charm that has the `MongoDBCharmConfig` configuration model,
will use the `MongoDBOperator` operator (which specifies a MongoD charm running
a DB Engine and storage), and the main peer relation name will be
`database-peers`. The name `mongodb-test` will be used for the dependency.
"""

import logging
from typing import ClassVar, Generic, TypeVar

from data_platform_helpers.advanced_statuses.handler import StatusHandler
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.protocol import ManagerStatusProtocol
from data_platform_helpers.advanced_statuses.types import Scope
from ops.charm import CharmBase

from single_kernel_mongo.config.literals import CharmKind, Substrates
from single_kernel_mongo.config.relations import PeerRelationNames
from single_kernel_mongo.config.statuses import CharmStatuses, MongoDBStatuses
from single_kernel_mongo.core.operator import OperatorProtocol
from single_kernel_mongo.core.structured_config import MongoConfigModel, MongoDBRoles
from single_kernel_mongo.events.lifecycle import LifecycleEventsHandler

T = TypeVar("T", bound=MongoConfigModel)
U = TypeVar("U", bound=OperatorProtocol)

logger = logging.getLogger(__name__)


class AbstractMongoCharm(ManagerStatusProtocol, Generic[T, U], CharmBase):
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
    peer_rel_name: ClassVar[PeerRelationNames]
    status_peer_rel_name: ClassVar[PeerRelationNames] = PeerRelationNames.STATUS_PEERS
    name: ClassVar[str]

    def __init__(self, *args):
        # Init the Juju object Object
        super(Generic, self).__init__(*args)

        # Create the operator instance (one of MongoDBOperator or MongosOperator)
        self.operator = self.operator_type(self)
        self.state = self.operator.state

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

        # Status manager stores the operator locally
        # Added after the lifecycle so that the update-status of the operator
        # runs before the one of the status handler.
        self.status_handler = StatusHandler(self, self, *self.operator.components)

    @property
    def parsed_config(self) -> T:
        """Return the config parsed as a pydantic model."""
        return self.config_type.model_validate(self.model.config)

    def on_install(self, _):
        """First install event handler."""
        if self.substrate == Substrates.VM:
            self.status_handler.set_running_status(
                CharmStatuses.INSTALLING_MONGODB.value, scope="unit"
            )
            self.workload.install()

    def on_leader_elected(self, event):
        """First leader elected handler."""
        # Sets the role in the databag: when the charm is first created, its
        # role won't exist in the databag. We save it in the databag because we
        # don't allow role changing yet.
        if (
            self.operator.name == CharmKind.MONGOD
            and self.parsed_config.role == MongoDBRoles.INVALID
        ):
            self.status_handler.set_running_status(MongoDBStatuses.INVALID_ROLE.value, scope="app")
            event.defer()
            return

        if self.operator.state.app_peer_data.role == MongoDBRoles.UNKNOWN:
            self.operator.state.app_peer_data.role = self.parsed_config.role

    def get_statuses(self, scope: Scope, recompute: bool = False) -> list[StatusObject]:
        """Returns a list of statuses."""
        return []
