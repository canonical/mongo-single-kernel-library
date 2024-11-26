# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest
from ops.model import ActiveStatus, MaintenanceStatus
from ops.testing import ActionFailed, Harness

from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MonitorUser,
    OperatorUser,
)

from .mongodb_test_charm.src.charm import MongoTestCharm


def test_get_password_action_fail(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(False)
    with pytest.raises(ActionFailed):
        harness.run_action("set-password")

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD.value
    with pytest.raises(ActionFailed):
        harness.run_action("set-password")

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value

    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
        return_value=MaintenanceStatus(""),
    )
    with pytest.raises(ActionFailed):
        harness.run_action("set-password")

    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
        return_value=ActiveStatus(""),
    )
    with pytest.raises(ActionFailed):
        harness.run_action("set-password", {"username": "notfound"})


@pytest.mark.parametrize(
    ("user", "password"),
    ((MonitorUser, None), (OperatorUser, "deadbeef"), (BackupUser, "cafe")),
)
def test_get_password_action_succeed(harness: Harness[MongoTestCharm], mocker, user, password):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
        return_value=ActiveStatus(""),
    )
    mock_exporter_connect = mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect"
    )
    mock_pbm_connect = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.connect"
    )
    mock_mongo_manager = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.set_user_password"
    )

    output = harness.run_action(
        "set-password", params={"username": user.username, "password": password}
    )
    output_password = output.results["password"]
    if password:
        assert output_password == password
    else:
        assert len(output_password) == 32

    if user == BackupUser:
        mock_pbm_connect.assert_called()
    if user == MonitorUser:
        mock_exporter_connect.assert_called()
    mock_mongo_manager.assert_called_with(user, output_password)


def test_set_password_action_fail_too_long(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
        return_value=ActiveStatus(""),
    )
    with pytest.raises(ActionFailed):
        harness.run_action("set-password", {"password": 40 * "a"})
