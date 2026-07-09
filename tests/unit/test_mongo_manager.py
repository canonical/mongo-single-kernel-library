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
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
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


@pytest.mark.parametrize(("user"), (CharmedStatsUser, CharmedBackupUser))
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
        harness.charm.operator.state, f"{user.username.replace('charmed-', '')}_config"
    )

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=user.privileges)
    mock_create_user.assert_called_with(
        config.username,
        config.password,
        config.supported_roles,
        auth_restrictions=[
            {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
            {"clientSource": ["10.0.0.0/24"], "serverAddress": ["10.0.0.0/24"]},
        ],
    )

    assert harness.charm.operator.state.app_peer_data.is_user_created(user.username)


def test_reconcile_local_auth_restrictions(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    state = harness.charm.operator.state
    for user in (CharmedStatsUser, CharmedBackupUser, CharmedLogRotateUser):
        state.app_peer_data.set_user_created(user.username)

    mock_update = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.update_user_auth_restrictions",
    )

    harness.charm.operator.mongo_manager.update_users_local_auth_restrictions()

    assert mock_update.call_count == 3
    for call in mock_update.call_args_list:
        config = call.args[0]
        assert config.auth_restrictions == [
            {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
            {"clientSource": ["10.0.0.0/24"], "serverAddress": ["10.0.0.0/24"]},
        ]


def test_update_cluster_ip_source_allowlist(harness: Harness[MongoTestCharm], mocker):
    mock_connection = mocker.patch("single_kernel_mongo.managers.mongo.MongoConnection")
    mock_update = mock_connection.return_value.__enter__.return_value.set_cluster_ip_source_allowlist

    harness.charm.operator.mongo_manager.update_cluster_ip_source_allowlist(["10.0.0.0/24"])

    config = mock_connection.call_args.args[0]
    assert config.username == CharmedOperatorUser.username
    assert config == harness.charm.operator.state.mongo_config
    assert mock_connection.call_args.kwargs == {}
    mock_update.assert_called_once_with(["10.0.0.0/24"])


def test_initialise_operator_user(harness: Harness[MongoTestCharm], mocker, substrate: Substrate):
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
        f"  user: 'charmed-operator',"
        "  pwd: passwordPrompt(),"
        f"  roles: {OPERATOR_ROLE},"
        "  mechanisms: ['SCRAM-SHA-256'],"
        "  passwordDigestor: 'server',"
        '})"',
    ]

    mock_create_user.assert_called_with("mongodb://localhost/admin", cmd, input=config.password)

    assert harness.charm.operator.state.app_peer_data.is_user_created(CharmedOperatorUser.username)
