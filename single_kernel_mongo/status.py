# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Placeholder for status handling."""

from collections.abc import Callable

from ops.model import StatusBase


class StatusManager:
    """Status Manager."""

    set_and_share_status: Callable[[StatusBase], None]
