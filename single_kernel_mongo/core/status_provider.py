# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""A simple protocol to provide status."""

from abc import abstractmethod
from typing import Protocol

from ops.model import StatusBase


class StatusProvider(Protocol):
    """Enforces all classes inheriting from this class to provide a `get_status` method."""

    @abstractmethod
    def get_status(self) -> StatusBase | None:
        """Returns a sensitive status about the manager."""
        ...
