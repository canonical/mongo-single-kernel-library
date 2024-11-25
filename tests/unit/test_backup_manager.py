# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from ops import ActiveStatus, MaintenanceStatus
from ops.model import BlockedStatus, Relation, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.events.backups import INVALID_S3_INTEGRATION_STATUS
from single_kernel_mongo.exceptions import (
    BackupError,
    InvalidArgumentForActionError,
    InvalidPBMStatusError,
    ListBackupError,
    ResyncError,
    WorkloadExecError,
)

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm


def test_valid_s3_integration(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    relation: Relation = harness.charm.operator.state.s3_relation

    harness.charm.on[ExternalRequirerRelations.S3_CREDENTIALS.value].relation_joined.emit(
        relation=relation
    )
    assert harness.charm.unit.status != BlockedStatus(INVALID_S3_INTEGRATION_STATUS)


def test_invalid_s3_integration(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD.value
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    relation: Relation = harness.charm.operator.state.s3_relation

    harness.charm.on[ExternalRequirerRelations.S3_CREDENTIALS.value].relation_joined.emit(
        relation=relation
    )
    assert harness.charm.unit.status == BlockedStatus(INVALID_S3_INTEGRATION_STATUS)


def test_environment_is_valid(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    assert harness.charm.operator.backup_manager.environment["PBM_MONGODB_URI"] != ""


def test_get_status_fail(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager

    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=False)
    status = backup_manager.get_status()
    assert status == WaitingStatus("waiting for pbm to start")

    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    status = backup_manager.get_status()
    assert status is None


@pytest.mark.parametrize(
    ("pbm_status", "expected"),
    (
        ("status code: 403", "s3 credentials are incorrect."),
        ("status code: 404", "s3 configurations are incompatible."),
        ("status code: 301", "s3 configurations are incompatible."),
        ("Unknown message", "PBM error"),
        (
            '{"cluster": [{"nodes":[{"host": "mongodb/1.1.1.1:27018", "errors": "status code: 403"}], "rs": "test-mongodb"}]}',
            "s3 credentials are incorrect.",
        ),
    ),
)
@patch_network_get(private_address="1.1.1.1")
def test_get_status_pbm_error(harness: Harness[MongoTestCharm], mocker, pbm_status, expected):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )

    mock.return_value = pbm_status
    status = backup_manager.get_status()
    assert status == BlockedStatus(expected)


def test_get_status_success(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )
    mock.return_value = '{"running":{"type":"resync","opID":"64f5cc22a73b330c3880e3b2"}}'
    status = backup_manager.get_status()
    assert status == WaitingStatus("waiting to sync s3 configurations.")

    mock.return_value = '{"running":{"type":"backup","name":"2024-11-25"}}'
    status = backup_manager.get_status()
    assert status == MaintenanceStatus("backup started/running, backup id: '2024-11-25'")

    mock.return_value = '{"running":{"type":"restore","name":"2024-11-25"}}'
    status = backup_manager.get_status()
    assert status == MaintenanceStatus("restore started/running, backup id: '2024-11-25'")

    mock.return_value = "{}"
    status = backup_manager.get_status()
    assert status == ActiveStatus("")


def test_create_backup_success(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        return_value="Starting backup '2024-11-25T15:05:40Z'",
    )

    backup_id = backup_manager.create_backup_action()

    assert backup_id == "2024-11-25T15:05:40Z"


def test_create_backup_fail_resync(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="Resync", stderr=None),
    )

    with pytest.raises(ResyncError):
        backup_manager.create_backup_action()


def test_create_backup_fail_other(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="deadbeef", stderr=None),
    )

    with pytest.raises(BackupError) as e:
        backup_manager.create_backup_action()

    assert e.match(r"deadbeef")


def test_list_backup_action_success(harness: Harness[MongoTestCharm], mocker):
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )
    with open("tests/unit/data/list_backups.json") as fd:
        pbm_status = fd.read()
    mock.return_value = pbm_status

    backup_formatted = backup_manager.list_backup_action()

    expected_list = [("", "", "")]
    expected_list = [
        ("2024-11-25T-15:15:05Z", "logical", "in progress"),
        ("2024-11-25T-15:20:05Z", "backup", "finished"),
        ("2024-11-25T-15:25:05Z", "restore", "finished"),
        ("2024-11-25T-15:30:05Z", "restore", "failed: not found"),
        ("2024-11-25T-15:35:05Z", "backup", "in progress"),
    ]
    assert backup_formatted == backup_manager._format_backup_list(expected_list)


def test_list_backup_action_error(harness: Harness[MongoTestCharm], mocker) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="status", return_code=1, stdout=None, stderr=None),
    )
    with pytest.raises(ListBackupError):
        backup_manager.list_backup_action()


def test_restore_backup_success(harness: Harness[MongoTestCharm], mocker) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock_call = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command")

    backup_manager.restore_backup("deadbeef", "test-mongodb=test-mongodb")

    mock_call.assert_called_with(
        "restore",
        ["deadbeef", "--replset-remapping", "test-mongodb=test-mongodb"],
        environment=backup_manager.environment,
    )


def test_get_backup_error_status(harness: Harness[MongoTestCharm], mocker) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )
    with open("tests/unit/data/list_backups.json") as fd:
        pbm_status = fd.read()

    mock.return_value = pbm_status

    error = backup_manager.get_backup_error_status("2024-11-25T-15:30:05Z")
    assert error == "not found"


@pytest.mark.parametrize(
    ("pbm_status", "pattern"),
    (
        (MaintenanceStatus(""), "Please wait for current.*"),
        (WaitingStatus(""), "Sync-ing configurations needs more time.*"),
        (BlockedStatus("error"), "error"),
    ),
)
def test_can_restore_fail_status(
    harness: Harness[MongoTestCharm], mocker, pbm_status, pattern
) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
    )

    mock.return_value = pbm_status
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.can_restore("backup", "remapping_pattern")
    assert e.match(pattern)


@pytest.mark.parametrize(
    ("backup_id", "remap_pattern", "pattern"),
    (("", "", "Missing backup-id.*"), ("2024", "", ".*'remap-pattern'.*")),
)
def test_can_restore_fail_params(
    harness: Harness[MongoTestCharm], mocker, backup_id, remap_pattern, pattern
) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status", return_value=ActiveStatus()
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager._needs_provided_remap_arguments",
        return_value=True,
    )
    with pytest.raises(InvalidArgumentForActionError) as e:
        backup_manager.can_restore(backup_id, remap_pattern)

    assert e.match(pattern)


@pytest.mark.parametrize(
    ("pbm_status", "pattern"),
    (
        (MaintenanceStatus(""), "Can only create one backup.*"),
        (WaitingStatus(""), "Sync-ing configurations needs more time.*"),
        (BlockedStatus("error"), "error"),
    ),
)
def test_can_backup_fail(harness: Harness[MongoTestCharm], mocker, pbm_status, pattern) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
    )

    mock.return_value = pbm_status
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.can_backup()
    assert e.match(pattern)


@pytest.mark.parametrize(
    ("pbm_status", "pattern"),
    (
        (WaitingStatus(""), "Sync-ing configurations needs more time.*"),
        (BlockedStatus("error"), "error"),
    ),
)
def test_can_list_backup_fail(
    harness: Harness[MongoTestCharm], mocker, pbm_status, pattern
) -> None:
    backup_manager = harness.charm.operator.backup_manager
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION.value
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.get_status",
    )

    mock.return_value = pbm_status
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.can_list_backup()
    assert e.match(pattern)
