# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from pathlib import Path

import pytest
import yaml
from ops.model import BlockedStatus, WaitingStatus
from ops.testing import Harness
from pymongo.errors import ConfigurationError, ConnectionFailure, OperationFailure

from single_kernel_mongo.exceptions import WorkloadExecError

from .mongodb_test_charm.src.charm import MongoTestCharm

PYMONGO_EXCEPTIONS = [
    ConnectionFailure("error message"),
    ConfigurationError("error message"),
    OperationFailure("error message"),
]

CONFIG = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/config.yaml").read_text()))
ACTIONS = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/actions.yaml").read_text()))
METADATA = str(yaml.safe_load(Path("./tests/unit/mongodb_test_charm/metadata.yaml").read_text()))


def setup_sercrets(harness: Harness):
    harness.set_leader(True)
    harness.charm.operator.on_leader_elected()
    harness.set_leader(False)


@pytest.fixture
def mock_fs_interactions(mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.write")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.copy_to_unit")
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.exec")
    mocker.patch("pathlib.Path.mkdir")


@pytest.fixture
def harness() -> Harness:
    harness = Harness(MongoTestCharm, meta=METADATA, actions=ACTIONS, config=CONFIG)
    harness.add_relation("database-peers", "database-peers")
    harness.begin()
    with harness.hooks_disabled():
        harness.add_storage(storage_name="mongodb", count=1, attach=True)
    return harness


def test_install_blocks_snap_install_failure(harness, mocker):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.install", return_value=False)
    harness.charm.on.install.emit()
    assert harness.charm.unit.status == BlockedStatus("couldn't install MongoDB")


def test_snap_start_failure_leads_to_blocked_status(harness, mocker, mock_fs_interactions):
    open_ports_mock = mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.open_ports"
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    open_ports_mock.assert_not_called()
    assert harness.charm.unit.status == BlockedStatus("couldn't start MongoDB")


def test_on_start_mongod_not_ready_defer(harness, mocker, mock_fs_interactions):
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
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
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.start", return_value=True)
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.open_ports",
        side_effect=WorkloadExecError("open-port", 1, None, None),
    )
    harness.set_leader(True)
    harness.charm.on.start.emit()
    assert harness.charm.unit.status == BlockedStatus("failed to open TCP port for MongoDB")
