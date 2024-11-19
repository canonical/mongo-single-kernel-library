#!/usr/bin/python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Operator for MongoDB Related Charms."""

import logging
from typing import TYPE_CHECKING

from pymongo.errors import PyMongoError

from single_kernel_mongo.config.literals import MAX_PASSWORD_LENGTH, Scope, Substrates
from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.managers.backups import BackupManager
from single_kernel_mongo.managers.config import MongoDBConfigManager
from single_kernel_mongo.managers.mongo import MongoManager
from single_kernel_mongo.managers.tls import TLSManager
from single_kernel_mongo.state.charm_state import CharmState
from single_kernel_mongo.utils.mongo_connection import MongoConnection, NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    OperatorUser,
    get_user_from_username,
)
from single_kernel_mongo.workload.mongodb_workload import MongoDBWorkload

if TYPE_CHECKING:
    from single_kernel_mongo.abstract_charm import AbstractMongoCharm

from ops.framework import Object

logger = logging.getLogger(__name__)


class MongoDBOperator(Object):
    """Operator for MongoDB Related Charms."""

    backup: BackupManager
    tls: TLSManager
    charm: AbstractMongoCharm
    state: CharmState
    mongo: MongoManager
    config_manager: MongoDBConfigManager
    substrate: Substrates
    workload: MongoDBWorkload

    def handle_set_password_action(
        self, username: str, password: str | None = None
    ) -> tuple[str, str]:
        """Sets the password."""
        user = get_user_from_username(username)
        new_password = password or self.workload.generate_password()
        if len(new_password) > MAX_PASSWORD_LENGTH:
            raise SetPasswordError(
                f"Password cannot be longer than {MAX_PASSWORD_LENGTH} characters."
            )

        secret_id = self.set_password(user, new_password)
        # Rotate password.
        if username in (OperatorUser.username, BackupUser.username):
            pass

        return new_password, secret_id

    def set_password(self, user: MongoDBUser, password: str) -> str:
        """Sets the password for a given username and return the secret id.

        Raises:
            SetPasswordError
        """
        with MongoConnection(self.state.mongo_config) as mongo:
            try:
                mongo.set_user_password(user.username, password)
            except NotReadyError:
                raise SetPasswordError(
                    "Failed changing the password: Not all members healthy or finished initial sync."
                )
            except PyMongoError as e:
                raise SetPasswordError(f"Failed changing the password: {e}")

        return self.state.secrets.set(
            user.password_key_name,
            password,
            Scope.UNIT,
        ).label

    def get_password(self, username: str) -> str:
        """Gets the password for the relevant username."""
        user = get_user_from_username(username)
        return self.state.secrets.get_for_key(Scope.APP, user.password_key_name) or ""
