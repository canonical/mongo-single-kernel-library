#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Abstract Operator for Mongo Related Charms."""

from typing import Protocol


class OperatorProtocol(Protocol):
    """Protocol for a charm operator."""

    def on_install(self) -> None:
        """Handles the install event."""
        ...

    def on_start(self) -> None:
        """Handles the start event."""
        ...

    def on_leader_elected(self) -> None:
        """Handles the leader elected event."""
        ...

    def on_relation_handler(self) -> None:
        """Handles the relation changed events."""
        ...

    def on_status_update(self) -> None:
        """Handle the status update event."""
        ...

    def on_stop(self) -> None:
        """Handles the stop event."""
