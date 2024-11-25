# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from ops.model import BlockedStatus, WaitingStatus

from single_kernel_mongo.exceptions import WorkloadExecError


def test_install_blocks_snap_install_failure(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=False)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == BlockedStatus("couldn't install MongoDB")


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
