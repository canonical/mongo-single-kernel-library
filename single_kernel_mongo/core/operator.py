#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract Operator for Mongo Related Charms."""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, ClassVar

from ops.framework import Object
from ops.model import Unit

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class OperatorProtocol(ABC, Object):
    """Protocol for a charm operator."""

    charm: AbstractMongoCharm
    name: ClassVar[str]

    def on_install(self) -> None:
        """Handles the install event."""
        ...

    def on_start(self) -> None:
        """Handles the start event."""
        ...

    def on_secret_changed(self, secret_label: str, secret_id: str) -> None:
        """Handles the secret changed events."""

    def on_config_changed(self) -> None:
        """Handles the config changed events."""
        ...

    def on_storage_attached(self) -> None:
        """Handles the storage attached events."""
        ...

    def on_storage_detaching(self) -> None:
        """Handles the storage attached events."""
        ...

    def on_leader_elected(self) -> None:
        """Handles the leader elected events."""
        ...

    def on_update_status(self) -> None:
        """Handle the status update events."""
        ...

    def on_relation_joined(self) -> None:
        """Handles the relation changed events."""
        ...

    def on_relation_changed(self) -> None:
        """Handles the relation changed events."""
        ...

    def on_relation_departed(self, departing_unit: Unit | None) -> None:
        """Handles the relation departed events."""
        ...

    def on_stop(self) -> None:
        """Handles the stop event."""
        ...
