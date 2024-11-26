# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops import MaintenanceStatus
from ops.model import BlockedStatus, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import ShardingMigrationError, WorkloadExecError
from single_kernel_mongo.utils.mongodb_users import BackupUser, MonitorUser, OperatorUser

from .mongodb_test_charm.src.charm import MongoTestCharm


def test_install_blocks_snap_install_failure(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=False)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == BlockedStatus("couldn't install MongoDB")


def test_install_snap_install_success(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=True)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == MaintenanceStatus("installing MongoDB")


def test_snap_start_failure_leads_to_blocked_status(harness, mocker, mock_fs_interactions):
    open_ports_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.open_ports"
    )
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    harness.set_leader(True)
    harness.charm.on.start.emit()
    open_ports_mock.assert_not_called()
    assert harness.charm.unit.status == BlockedStatus("couldn't start MongoDB")


def test_on_start_mongod_not_ready_defer(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=False),
    )
    patched_mongo_initialise = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    assert harness.charm.unit.status == WaitingStatus("waiting for MongoDB to start")
    patched_mongo_initialise.assert_not_called()


def test_start_unable_to_open_tcp_moves_to_blocked(harness, mocker, mock_fs_interactions):
    # This also tests that we call the hook on the workload.
    def mock_exec(command, *_, **__):
        if command[0] == "open-port":
            raise WorkloadExecError("open-port", 1, None, None)

    harness.charm.workload.exec = mock_exec
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    harness.set_leader(True)
    harness.charm.on.start.emit()
    assert harness.charm.unit.status == BlockedStatus("failed to open TCP port for MongoDB")


def test_start_success(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    patched_mongo_initialise_replica_set = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_replica_set"
    )
    patched_mongo_initialise_user = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.initialise_users"
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.on.start.emit()
    patched_mongo_initialise_replica_set.assert_called()
    patched_mongo_initialise_user.assert_called()

    assert harness.charm.operator.state.db_initialised


def test_on_config_changed(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    with pytest.raises(ShardingMigrationError):
        harness.update_config({"role": "shard"})


def test_on_leader_elected(harness):
    state = harness.charm.operator.state
    assert state.app_peer_data.keyfile == ""
    assert state.get_user_password(MonitorUser) == ""
    assert state.get_user_password(OperatorUser) == ""
    assert state.get_user_password(BackupUser) == ""
    harness.set_leader(True)
    assert len(state.app_peer_data.keyfile) == 1024
    assert len(state.get_user_password(MonitorUser)) == 32
    assert len(state.get_user_password(OperatorUser)) == 32
    assert len(state.get_user_password(BackupUser)) == 32


def test_on_leader_elected_dont_rotate_if_present(harness):
    state = harness.charm.operator.state
    harness.set_leader(True)
    operator_password = state.get_user_password(OperatorUser)
    harness.charm.on.leader_elected.emit()
    assert state.get_user_password(OperatorUser) == operator_password


def test_on_secret_changed(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    mocked = mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect"
    )
    harness.set_leader(True)
    password = "deadbeef"
    secret_label = "test-mongodb.app"
    secret = harness.charm.operator.state.secrets.get(scope=Scope.APP)
    # breakpoint()
    content = secret.get_content()
    content["monitor-password"] = password
    secret.set_content(content)

    harness.charm.operator.on_secret_changed(secret_label, secret.get_info().id)

    mocked.assert_called()
    assert (
        password in harness.charm.operator.mongodb_exporter_config_manager.build_parameters()[0][0]
    )
