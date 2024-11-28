#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Event handlers for password-related Juju Actions."""

import logging
from enum import Enum
from typing import TYPE_CHECKING

from ops.charm import ActionEvent
from ops.framework import Object
from ops.model import MaintenanceStatus

from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.utils.event_helpers import fail_action_with_error_log
from single_kernel_mongo.utils.mongodb_users import CharmUsers, OperatorUser

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm
    from single_kernel_mongo.managers.mongodb_operator import MongoDBOperator


logger = logging.getLogger(__name__)


class PasswordActionParameter(str, Enum):
    """Actions related config for MongoDB Charm."""

    PASSWORD = "password"
    USERNAME = "username"


class PasswordActionEvents(Object):
    """Event handlers for password-related Juju Actions."""

    def __init__(self, dependent: "MongoDBOperator"):
        super().__init__(dependent, key="password_events")
        self.dependent = dependent
        self.charm: AbstractMongoCharm = dependent.charm
        self.framework.observe(
            getattr(self.charm.on, "set_password_action"), self._set_password_action
        )
        self.framework.observe(
            getattr(self.charm.on, "get_password_action"),
            self._get_password_action,
        )

    def _set_password_action(self, event: ActionEvent) -> None:
        """Handler for set-password action.

        Set the password for a specific user, if no passwords are passed, generate them.
        """
        action = "set-password"
        if not self.model.unit.is_leader():
            fail_action_with_error_log(
                logger, event, action, "Password rotation must be called on leader unit"
            )
            return
        if self.dependent.state.upgrade_in_progress:
            fail_action_with_error_log(
                logger,
                event,
                action,
                "Cannot set passwords while an upgrade is in progress.",
            )
            return
        if self.dependent.state.is_role(MongoDBRoles.SHARD):
            fail_action_with_error_log(
                logger,
                event,
                action,
                "Cannot set password on shard, please set password on config-server.",
            )
            return
        if isinstance(self.dependent.backup_manager.get_status(), MaintenanceStatus):
            fail_action_with_error_log(
                logger,
                event,
                action,
                "Cannot change password while a backup/restore is in progress.",
            )
            return
        username = event.params.get(PasswordActionParameter.USERNAME, OperatorUser.username)
        password = event.params.get(PasswordActionParameter.PASSWORD)
        if username not in CharmUsers:
            fail_action_with_error_log(
                logger,
                event,
                action,
                f"The action can be run only for users used by the charm: {', '.join(CharmUsers)} not {username}",
            )
            return
        try:
            passwd, secret_id = self.dependent.on_set_password_action(username, password)
        except SetPasswordError as e:
            fail_action_with_error_log(logger, event, action, str(e))
            return

        event.set_results({PasswordActionParameter.PASSWORD: passwd, "secret-id": secret_id})
        return

    def _get_password_action(self, event: ActionEvent) -> None:
        action = "get-password"
        username = event.params.get(PasswordActionParameter.USERNAME, OperatorUser.username)
        # breakpoint()
        if username not in CharmUsers:
            fail_action_with_error_log(
                logger,
                event,
                action,
                f"The action can be run only for users used by the charm: {', '.join(CharmUsers)} not {username}",
            )
            return

        if not username:
            return
        password = self.dependent.on_get_password_action(username)
        event.set_results({PasswordActionParameter.PASSWORD: password})