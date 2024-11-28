# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Placeholder for status handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ops.framework import Object
from ops.model import (
    ActiveStatus,
    BlockedStatus,
    ErrorStatus,
    MaintenanceStatus,
    StatusBase,
    WaitingStatus,
)

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm


class StatusManager(Object):
    """Status Manager."""

    def __init__(self, charm: AbstractMongoCharm):
        super().__init__(parent=charm, key="status")
        self.charm = charm

    def set_and_share_status(self, status: StatusBase | None):
        """Sets the unit status."""
        self.charm.unit.status = status or ActiveStatus()

    def to_blocked(self, message: str):
        """Sets status to blocked."""
        self.set_and_share_status(BlockedStatus(message))

    def to_waiting(self, message: str):
        """Sets status to waiting."""
        self.set_and_share_status(WaitingStatus(message))

    def to_active(self, message: str | None):
        """Sets status to active."""
        if message is None:
            self.set_and_share_status(ActiveStatus())
            return
        self.set_and_share_status(ActiveStatus(message))

    def to_maintenance(self, message: str):
        """Sets status to maintenance."""
        self.set_and_share_status(MaintenanceStatus(message))

    def to_error(self, message: str):
        """Sets status to error."""
        self.set_and_share_status(ErrorStatus(message))
