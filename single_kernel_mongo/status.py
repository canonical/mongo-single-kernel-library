# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Placeholder for status handling."""

from collections.abc import Callable

from ops.model import StatusBase


class StatusManager:
    """Status Manager."""

    set_and_share_status: Callable[[StatusBase | None], None]
    to_blocked: Callable[[str], None]
    to_waiting: Callable[[str], None]
    to_active: Callable[[str], None]
    to_maintenance: Callable[[str], None]
    to_error: Callable[[str], None]
