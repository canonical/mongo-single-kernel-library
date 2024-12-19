#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract Operator for Mongo Related Charms.

The Charm operator defines the minimal interface that should be specified when
defining an operator. This is a Mongo manager for all mongodb related
operations, a TLS manager since all charms should be able to support TLS, a
main workload (MongoDBWorkload or MongosWorkload) and some client events.

To that, each operator can add some extra event handlers that are specific to
this operator like backups or cluster event handlers, etc.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from logging import getLogger
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from ops.charm import RelationDepartedEvent
from ops.framework import Object
from ops.model import Unit

from single_kernel_mongo.config.literals import KindEnum, Substrates
from single_kernel_mongo.config.models import CharmKind
from single_kernel_mongo.managers.config import CommonConfigManager
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.workload import WorkloadBase
    from single_kernel_mongo.events.database import DatabaseEventsHandler
    from single_kernel_mongo.events.tls import TLSEventsHandler
    from single_kernel_mongo.managers.tls import TLSManager

logger = getLogger(__name__)


class OperatorProtocol(ABC, Object):
    """Protocol for a charm operator.

    A Charm Operator must define the following elements:
     * charm: The Charm it is bound to.
     * name: The charm operator name, which is one value of the `KindEnum`
        enum. This is a class var defined in the operator.
     * tls_manager: The TLS manager for the mandatory tls events and handlers
     * state : The CharmState, object handling peer databag interactions, and model interactions.
     * mongo_manager: The manager for MongoD related interactions.
     * workload: The main workload of this Charm.
    """

    charm: AbstractMongoCharm
    name: ClassVar[KindEnum]
    substrate: Substrates
    role: CharmKind
    config_manager: CommonConfigManager
    tls_manager: TLSManager
    state: CharmState
    mongo_manager: MongoManager
    workload: WorkloadBase
    client_events: DatabaseEventsHandler
    tls_events: TLSEventsHandler

    if TYPE_CHECKING:

        def __init__(self, dependent: AbstractMongoCharm): ...

    @abstractmethod
    def on_install(self) -> None:
        """Handles the install event."""
        ...

    @abstractmethod
    def on_start(self) -> None:
        """Handles the start event."""
        ...

    @abstractmethod
    def on_secret_changed(self, secret_label: str, secret_id: str) -> None:
        """Handles the secret changed events."""

    @abstractmethod
    def on_config_changed(self) -> None:
        """Handles the config changed events."""
        ...

    @abstractmethod
    def on_storage_attached(self) -> None:
        """Handles the storage attached events."""
        ...

    @abstractmethod
    def on_storage_detaching(self) -> None:
        """Handles the storage attached events."""
        ...

    @abstractmethod
    def on_leader_elected(self) -> None:
        """Handles the leader elected events."""
        ...

    @abstractmethod
    def on_update_status(self) -> None:
        """Handle the status update events."""
        ...

    @abstractmethod
    def on_relation_joined(self) -> None:
        """Handles the relation changed events."""
        ...

    @abstractmethod
    def on_relation_changed(self) -> None:
        """Handles the relation changed events."""
        ...

    @abstractmethod
    def on_relation_departed(self, departing_unit: Unit | None) -> None:
        """Handles the relation departed events."""
        ...

    @abstractmethod
    def on_stop(self) -> None:
        """Handles the stop event."""
        ...

    @abstractmethod
    def start_charm_services(self) -> None:
        """Starts the relevant services."""
        ...

    @abstractmethod
    def stop_charm_services(self) -> None:
        """Stop the relevant services."""
        ...

    @abstractmethod
    def restart_charm_services(self) -> None:
        """Restart the relevant services with updated config."""
        ...

    @abstractmethod
    def is_relation_feasible(self, name: str) -> bool:
        """Checks if the relation is feasible in this context."""
        ...

    def check_relation_broken_or_scale_down(self, event: RelationDepartedEvent):
        """Checks relation departed event is the result of removed relation or scale down.

        Relation departed and relation broken events occur during scaling down or during relation
        removal, only relation departed events have access to metadata to determine which case.
        """
        departing_name = event.departing_unit.name if event.departing_unit else ""
        scaling_down = self.state.set_scaling_down(
            event.relation.id, departing_unit_name=departing_name
        )

        if scaling_down:
            logger.info(
                "Scaling down the application, no need to process removed relation in broken hook."
            )

    def handle_licenses(self) -> None:
        """Pull / Push licenses.

        This function runs differently according to the substrate. We do not
        store the licenses at the same location, and we do not handle the same
        licenses.
        """
        licenses = [
            "snap",
            "mongodb-exporter",
            "percona-backup-mongodb",
            "percona-server",
        ]
        prefix = Path("./src/licenses") if self.substrate == Substrates.VM else Path("./")
        # Create the directory if needed.
        if self.substrate == Substrates.VM:
            prefix.mkdir(exist_ok=True)
            file = Path("./LICENSE")
            dst = prefix / "LICENSE-charm"
            self.workload.copy_to_unit(file, dst)
        else:
            name = "LICENSE-rock"
            file = Path(f"{self.workload.paths.licenses_path}/{name}")
            dst = prefix / name
            if not dst.is_file():
                self.workload.copy_to_unit(file, dst)

        for license in licenses:
            name = f"LICENSE-{license}"
            file = Path(f"{self.workload.paths.licenses_path}/{name}")
            dst = prefix / name
            if not dst.is_file():
                self.workload.copy_to_unit(file, dst)
