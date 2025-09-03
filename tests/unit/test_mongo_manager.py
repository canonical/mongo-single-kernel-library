# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops.testing import Harness
from pymongo.errors import OperationFailure, PyMongoError

from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    CharmedBackupUser,
    CharmedMonitorUser,
    CharmedOperatorUser,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate


def test_set_user_password(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == "deadbeef"


def test_set_user_not_ready(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=NotReadyError,
    )
    old_password = harness.charm.operator.state.get_user_password(CharmedOperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == old_password


def test_set_user_pymongo_error(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=PyMongoError,
    )
    old_password = harness.charm.operator.state.get_user_password(CharmedOperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == old_password


def test_initialise_replica_set_operation_failure(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset",
        side_effect=OperationFailure(error="woooops", code=11),
    )
    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.initialise_replica_set()


@pytest.mark.parametrize(("user"), (CharmedMonitorUser, CharmedBackupUser))
def test_initialise_user(harness: Harness[MongoTestCharm], mocker, user):
    harness.set_leader(True)
    mock_create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role",
    )
    mock_create_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
    )

    getattr(harness.charm.operator.mongo_manager, "initialise_user")(user)
    config = getattr(
        harness.charm.operator.state, f"{user.username.replace('charmed_', '')}_config"
    )

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=user.privileges)
    mock_create_user.assert_called_with(config.username, config.password, config.supported_roles)

    assert harness.charm.operator.state.app_peer_data.is_user_created(user.username)


def test_initialise_charmed_operator_user(
    harness: Harness[MongoTestCharm], mocker, substrate: Substrate
):
    harness.set_leader(True)
    if substrate == "lxd":
        mock_create_user = mocker.patch(
            "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command"
        )
    else:
        mock_create_user = mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command"
        )

    getattr(harness.charm.operator.mongo_manager, "initialise_charmed_operator_user")()
    config = getattr(harness.charm.operator.state, "operator_config")
    cmd = [
        "--quiet",
        "--eval",
        '"db.createUser({'
        f"  user: 'charmed_operator',"
        "  pwd: passwordPrompt(),"
        f"  roles: {OPERATOR_ROLE},"
        "  mechanisms: ['SCRAM-SHA-256'],"
        "  passwordDigestor: 'server',"
        '})"',
    ]

    mock_create_user.assert_called_with("mongodb://localhost/admin", cmd, input=config.password)

    assert harness.charm.operator.state.app_peer_data.is_user_created(CharmedOperatorUser.username)
