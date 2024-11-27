#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract Operator for Mongo Related Charms."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from ops.charm import RelationDepartedEvent
from ops.framework import Object
from ops.model import Unit

from single_kernel_mongo.config.literals import CharmRole
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.state.charm_state import CharmState

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.core.workload import WorkloadBase
    from single_kernel_mongo.managers.tls import TLSManager


class OperatorProtocol(ABC, Object):
    """Protocol for a charm operator."""

    charm: AbstractMongoCharm
    name: ClassVar[CharmRole]
    tls_manager: TLSManager
    state: CharmState
    mongo_manager: MongoManager
    workload: WorkloadBase

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

    @abstractmethod
    def check_relation_broken_or_scale_down(self, event: RelationDepartedEvent):
        """Checks if relation is broken or scaled down."""
        ...
