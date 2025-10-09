#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Events handler to get a primary."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ops.charm import ActionEvent
from ops.framework import Object

from single_kernel_mongo.utils.event_helpers import fail_action_with_error_log

if TYPE_CHECKING:  # pragma: nocover
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator

logger = logging.getLogger(__name__)


class PrimaryActionHandler(Object):
    "Event Handler to get a primary." ""

    def __init__(self, dependent: MongoDBOperator):
        super().__init__(parent=dependent, key=dependent.name)

        self.dependent = dependent
        self.charm = dependent.charm

        self.framework.observe(
            getattr(self.charm.on, "get_primary_action"), self.on_get_primary_action
        )

    def on_get_primary_action(self, event: ActionEvent):
        """Gets the primary of a replica set."""
        if not self.dependent.state.db_initialised:
            fail_action_with_error_log(
                logger, event, "get-primary", "Cannot get primary, DB is not initialised."
            )
        event.set_results({"replica-set-primary": self.dependent.primary_unit_name})
