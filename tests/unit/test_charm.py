# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops import MaintenanceStatus
from ops.model import BlockedStatus, WaitingStatus
from ops.testing import ActionFailed, Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    ShardingMigrationError,
    WorkloadExecError,
    WorkloadServiceError,
)
from single_kernel_mongo.utils.mongodb_users import BackupUser, MonitorUser, OperatorUser

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm

PEER_ADDR = {"private-address": "127.4.5.6"}


def test_install_blocks_snap_install_failure(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=False)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == BlockedStatus("couldn't install MongoDB")


def test_install_snap_install_success(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=True)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == MaintenanceStatus("Installed MongoDB")


def test_charm_install_success_calls_set_env(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.snap_present", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.write", return_value=True)
    mock_connect = mocker.patch(
        "single_kernel_mongo.managers.config.LogRotateConfigManager.connect"
    )

    mock_set_env = mocker.patch(
        "single_kernel_mongo.managers.config.CommonConfigManager.set_environment"
    )

    harness.charm.on.install.emit()

    mock_connect.assert_called()
    assert mock_set_env.call_count == 5


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


def test_start_fail_mongodb_exporter(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect",
        side_effect=WorkloadServiceError,
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    harness.charm.on.start.emit()

    assert harness.charm.unit.status == BlockedStatus("couldn't start mongodb exporter")


def test_start_fail_pbm_agent(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock(return_value=True),
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.connect",
        side_effect=WorkloadServiceError,
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    harness.charm.on.start.emit()

    assert harness.charm.unit.status == BlockedStatus("couldn't start pbm-agent")


def test_on_config_changed(harness):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    with pytest.raises(ShardingMigrationError):
        harness.update_config({"role": "shard"})


def test_on_config_changed_upgrade_in_progress(harness, mocker):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocked_defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress", return_value=True
    )
    harness.update_config({"role": "shard"})

    mocked_defer.assert_called()


def test_on_leader_elected(harness):
    state = harness.charm.operator.state
    assert state.get_keyfile() is None
    assert state.get_user_password(MonitorUser) == ""
    assert state.get_user_password(OperatorUser) == ""
    assert state.get_user_password(BackupUser) == ""
    harness.set_leader(True)
    assert len(state.get_keyfile()) == 1024
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
    secret_label = "database-peers.test-mongodb.app"
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


def test_on_secret_changed_unknown(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mock_get = mocker.patch("single_kernel_mongo.core.secrets.SecretCache.get")

    harness.charm.operator.on_secret_changed("unknown", "kdfjqlmdfjldq")
    mock_get.assert_not_called()


def test_pbm_connect_no_password(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.backup_manager.connect()

    mock_active.assert_not_called()


def test_pbm_connect_no_db_initialised(harness: Harness[MongoTestCharm], mocker):
    mock_active = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.active")
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.backup_manager.connect()

    mock_active.assert_not_called()


def test_pbm_connect_same_env(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active", return_value=True
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")

    uri = harness.charm.operator.state.backup_config.uri
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.get_environment", return_value=uri
    )
    harness.charm.operator.backup_manager.connect()
    mock_start.assert_not_called()


def test_pbm_connect_not_active(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active", return_value=False
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")
    mock_stop = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.stop")
    mock_set_env = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.set_environment"
    )

    harness.charm.operator.backup_manager.connect()
    mock_start.assert_called()
    mock_stop.assert_called()
    mock_set_env.assert_called()


def test_pbm_connect_active_other_password(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.workload.backup_workload.PBMWorkload.active", return_value=True
    )
    mock_start = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.start")
    mock_stop = mocker.patch("single_kernel_mongo.workload.backup_workload.PBMWorkload.stop")
    mock_set_env = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.set_environment"
    )
    mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.get_environment",
        return_value="deadbeef",
    )

    harness.charm.operator.backup_manager.connect()
    mock_start.assert_called()
    mock_stop.assert_called()
    mock_set_env.assert_called()


def test_relation_joined_non_leader_does_nothing(harness: Harness[MongoTestCharm], mocker):
    rel = harness.charm.operator.state.peer_relation
    mock_on_relation_changed = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.on_relation_changed"
    )
    spied = mocker.spy(harness.charm.operator, "on_relation_joined")

    harness.set_leader(False)
    harness.add_relation_unit(rel.id, "test-mongodb/1")

    spied.assert_called()
    mock_on_relation_changed.assert_not_called()


def test_relation_joined_upgrade_in_progress_defers(harness: Harness[MongoTestCharm], mocker):
    rel = harness.charm.operator.state.peer_relation
    mock_on_relation_changed = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.on_relation_changed"
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress", return_value=True
    )
    spied = mocker.spy(harness.charm.operator, "on_relation_joined")
    harness.set_leader(True)
    harness.add_relation_unit(rel.id, "test-mongodb/1")

    spied.assert_called()
    mock_on_relation_changed.assert_not_called()


@patch_network_get(private_address="1.1.1.1")
def test_mongodb_relation_joined_all_replicas_not_ready(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mock_conn = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
    )
    mock_conn.return_value = False
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_members",
        return_value={"1.1.1.1"},
    )
    mocked_add_replset_member = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_replset_member"
    )
    mocker.patch("single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.connect")

    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "test-mongodb/1")
    harness.update_relation_data(rel.id, "test-mongodb/1", PEER_ADDR)

    assert isinstance(harness.charm.unit.status, WaitingStatus)
    mocked_add_replset_member.assert_not_called()


@patch_network_get(private_address="1.1.1.1")
def test_on_relation_departed_not_leader(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    spied = mocker.spy(harness.charm.operator, "on_relation_departed")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    update_host_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_hosts"
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "test-mongodb/1")

    harness.set_leader(False)
    harness.remove_relation_unit(rel.id, "test-mongodb/1")

    spied.assert_called()
    update_host_mock.assert_not_called()


@patch_network_get(private_address="1.1.1.1")
def test_on_relation_departed_eader(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    spied = mocker.spy(harness.charm.operator, "on_relation_departed")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    update_host_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.update_hosts"
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "test-mongodb/1")

    harness.remove_relation_unit(rel.id, "test-mongodb/1")

    spied.assert_called()
    update_host_mock.assert_called()


@patch_network_get(private_address="1.1.1.1")
def test_primary_db_not_initialised(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False

    with pytest.raises(ActionFailed):
        harness.run_action("get-primary")


@patch_network_get(private_address="1.1.1.1")
def test_primary(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.primary",
        new_callable=mocker.PropertyMock,
        return_value="1.1.1.1",
    )
    output = harness.run_action("get-primary")
    assert output.results["replica-set-primary"] == "test-mongodb/0"


@patch_network_get(private_address="1.1.1.1")
def test_primary_other_unit(harness: Harness[MongoTestCharm], mocker):
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.is_ready",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.MongoDBExporterConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.config.BackupConfigManager.connect")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.process_added_units")
    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.update_app_relation_data")
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.primary",
        new_callable=mocker.PropertyMock,
        return_value=PEER_ADDR["private-address"],
    )
    rel = harness.charm.operator.state.peer_relation
    harness.add_relation_unit(rel.id, "test-mongodb/1")
    harness.update_relation_data(rel.id, "test-mongodb/1", PEER_ADDR)
    output = harness.run_action("get-primary")
    assert output.results["replica-set-primary"] == "test-mongodb/1"
