# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops.testing import Harness
from pymongo.errors import OperationFailure, PyMongoError

from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    BackupUser,
    MonitorUser,
    OperatorUser,
)

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm


def test_set_user_password(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    harness.charm.operator.mongo_manager.set_user_password(OperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(OperatorUser) == "deadbeef"


def test_set_user_not_ready(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=NotReadyError,
    )
    old_password = harness.charm.operator.state.get_user_password(OperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(OperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(OperatorUser) == old_password


def test_set_user_pymongo_error(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=PyMongoError,
    )
    old_password = harness.charm.operator.state.get_user_password(OperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(OperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(OperatorUser) == old_password


@patch_network_get(private_address="1.1.1.1")
def test_initialise_replica_set_operation_failure(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset",
        side_effect=OperationFailure(error="woooops", code=11),
    )
    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.initialise_replica_set()


@pytest.mark.parametrize(("user"), (MonitorUser, BackupUser))
@patch_network_get(private_address="1.1.1.1")
def test_initialise_user(harness: Harness[MongoTestCharm], mocker, user):
    harness.set_leader(True)
    mock_create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role",
    )
    mock_create_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
    )

    getattr(harness.charm.operator.mongo_manager, "initialise_user")(user)
    config = getattr(harness.charm.operator.state, f"{user.username}_config")

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=user.privileges)
    mock_create_user.assert_called_with(config.username, config.password, config.supported_roles)

    assert harness.charm.operator.state.app_peer_data.is_user_created(user.username)


@patch_network_get(private_address="1.1.1.1")
def test_initialise_operator_user(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mock_create_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
    )

    getattr(harness.charm.operator.mongo_manager, "initialise_operator_user")()
    config = getattr(harness.charm.operator.state, "operator_config")

    mock_create_user.assert_called_with(config.username, config.password, roles=OPERATOR_ROLE)

    assert harness.charm.operator.state.app_peer_data.is_user_created(OperatorUser.username)
