# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops import ActiveStatus, MaintenanceStatus
from ops.model import BlockedStatus, Relation
from ops.testing import ActionFailed, Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.config.relations import ExternalRequirerRelations
from single_kernel_mongo.config.statuses import BackupStatuses, MongoDBStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    BackupError,
    InvalidArgumentForActionError,
    InvalidPBMStatusError,
    ListBackupError,
    ResyncError,
    WorkloadExecError,
)
from single_kernel_mongo.managers.backups import BackupManager
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate


@pytest.fixture
def backup_manager(harness: Harness[MongoTestCharm]) -> BackupManager:
    return harness.charm.operator.backup_manager


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.REPLICATION.value,
        MongoDBRoles.CONFIG_SERVER.value,
    ],
)
def test_valid_s3_integration(harness: Harness[MongoTestCharm], role: MongoDBRoles):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    relation: Relation = harness.charm.operator.state.s3_relation

    harness.charm.on[ExternalRequirerRelations.S3_CREDENTIALS.value].relation_joined.emit(
        relation=relation
    )
    assert harness.charm.unit.status != MongoDBStatuses.INVALID_S3_REL.value


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.UNKNOWN.value,
        MongoDBRoles.SHARD.value,
        MongoDBRoles.MONGOS.value,
    ],
)
def test_invalid_s3_integration(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, role: MongoDBRoles
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    relation: Relation = harness.charm.operator.state.s3_relation

    harness.charm.on[ExternalRequirerRelations.S3_CREDENTIALS.value].relation_joined.emit(
        relation=relation
    )
    statuses = backup_manager.state.statuses.get(
        scope=Scope.UNIT, component=backup_manager.name
    ).root

    assert MongoDBStatuses.INVALID_S3_REL.value in statuses


def test_backup_without_rel(harness):
    """Verifies no backups are attempted without s3 relation."""
    with pytest.raises(ActionFailed):
        harness.run_action("create-backup")


def test_list_backup_without_rel(harness):
    """Verifies that we can't list backups without s3 relation."""
    with pytest.raises(ActionFailed):
        harness.run_action("list-backups")


def test_s3_credentials_no_db(harness: Harness[MongoTestCharm], mocker):
    """Verifies that when there is no DB that setting credentials is deferred."""
    harness.charm.operator.state.db_initialised = False
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    defer = mocker.patch("ops.framework.EventBase.defer")
    mocker.patch(
        "single_kernel_mongo.events.backups.S3Requirer.get_s3_connection_info",
        return_value={"access-key": "noneya", "secret-key": "business"},
    )

    relation_id = harness.add_relation("s3-credentials", "s3-integrator")
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    harness.update_relation_data(
        relation_id,
        "s3-integrator/0",
        {"bucket": "hat"},
    )
    defer.assert_called()


def test_credentials_changed_backup_running(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.events.backups.S3Requirer.get_s3_connection_info",
        return_value={"access-key": "noneya", "secret-key": "business"},
    )
    defer = mocker.patch("ops.framework.EventBase.defer")
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )

    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=BackupState.BACKUP_RUNNING,
    )
    harness.update_relation_data(relation_id, "s3-integrator/0", {"bucket": "hat"})
    defer.assert_called()


def test_environment_is_valid(harness: Harness[MongoTestCharm]):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    assert harness.charm.operator.backup_manager.environment["PBM_MONGODB_URI"] != ""


def test_get_status_fail(harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True

    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status is None

    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.validate_s3_config",
        return_value=True,
    )

    harness.add_relation(ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator")

    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=False)

    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == BackupStatuses.WAITING_FOR_PBM_START.value


@pytest.mark.parametrize(
    ("pbm_status", "expected"),
    (
        ("status code: 403", "Incorrect S3 credentials."),
        ("status code: 404", "Incompatible S3 config options."),
        ("status code: 301", "Incompatible S3 config options."),
        ("Unknown message", "Unknown PBM error, check logs."),
        (
            '{"cluster": [{"nodes":[{"host": "%s/%s:27017", "errors": "status code: 403"}], "rs": "%s"}]}',
            "Incorrect S3 credentials.",
        ),
    ),
)
def test_get_status_pbm_error(
    harness: Harness[MongoTestCharm],
    substrate: Substrate,
    backup_manager: BackupManager,
    mongodb_name: str,
    mocker,
    pbm_status: str,
    expected: str,
    mongodb_hostname: str,
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.validate_s3_config",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.create_bucket",
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    # Handle the case where we match on the app name
    host = f"{mongodb_hostname}:27017"
    if "cluster" in pbm_status:
        pbm_status = pbm_status % (mongodb_name, host, mongodb_name)

    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )

    mock.return_value = pbm_status
    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert as_status(status) == BlockedStatus(expected)


def test_get_status_success(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch("single_kernel_mongo.managers.backups.BackupManager.validate_s3_config")
    mocker.patch("single_kernel_mongo.managers.backups.BackupManager.create_bucket")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )
    mock.return_value = '{"running":{"type":"resync","opID":"64f5cc22a73b330c3880e3b2"}}'
    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == BackupStatuses.PBM_WAITING_TO_SYNC.value

    mock.return_value = '{"running":{"type":"backup","name":"2024-11-25"}}'
    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert as_status(status) == MaintenanceStatus("Backup started/running, backup id: '2024-11-25'")

    mock.return_value = '{"running":{"type":"restore","name":"2024-11-25"}}'
    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert as_status(status) == MaintenanceStatus(
        "Restore started/running, backup id: '2024-11-25'"
    )

    mock.return_value = "{}"
    statuses = backup_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert as_status(status) == ActiveStatus("")


def test_create_backup_success(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        return_value="Starting backup '2024-11-25T15:05:40Z'",
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command",
        return_value="Starting backup '2024-11-25T15:05:40Z'",
    )

    backup_id = backup_manager.create_backup_action()

    assert backup_id == "2024-11-25T15:05:40Z"


def test_create_backup_fail_resync(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="Resync", stderr=None),
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="Resync", stderr=None),
    )

    with pytest.raises(ResyncError):
        backup_manager.create_backup_action()


def test_create_backup_fail_other(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="deadbeef", stderr=None),
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="backup", return_code=1, stdout="deadbeef", stderr=None),
    )

    with pytest.raises(BackupError) as e:
        backup_manager.create_backup_action()

    assert e.match(r"deadbeef")


def test_list_backup_action_success(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
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

    expected_list = [
        ("2024-11-25T-15:15:05Z", "logical", "in progress"),
        ("2024-11-25T-15:20:05Z", "backup", "finished"),
        ("2024-11-25T-15:25:05Z", "restore", "finished"),
        ("2024-11-25T-15:30:05Z", "restore", "failed: not found"),
        ("2024-11-25T-15:35:05Z", "backup", "in progress"),
    ]
    assert backup_formatted == backup_manager._format_backup_list(expected_list)


def test_list_backup_action_success_no_backups(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.pbm_status",
        new_callable=mocker.PropertyMock,
    )
    with open("tests/unit/data/list_backups_nothing.json") as fd:
        pbm_status = fd.read()
    mock.return_value = pbm_status

    backup_formatted = backup_manager.list_backup_action()

    expected_list: list[tuple[str, str, str]] = []
    assert backup_formatted == backup_manager._format_backup_list(expected_list)


def test_list_backup_action_error(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="status", return_code=1, stdout=None, stderr=None),
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command",
        side_effect=WorkloadExecError(cmd="status", return_code=1, stdout=None, stderr=None),
    )
    with pytest.raises(ListBackupError):
        backup_manager.list_backup_action()


def test_restore_backup_success(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, substrate: Substrate, mocker
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    if substrate == "lxd":
        mock_call = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command")
    else:
        mock_call = mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command"
        )

    backup_manager.restore_backup("deadbeef", "mongodb=mongodb")

    mock_call.assert_called_with(
        "restore",
        ["deadbeef", "--replset-remapping", "mongodb=mongodb"],
        environment=backup_manager.environment,
    )


def test_get_backup_error_status(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
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
    ("pbm_state", "pattern"),
    (
        (BackupState.BACKUP_RUNNING, "Please wait for current.*"),
        (BackupState.WAITING_TO_SYNC, "Sync-ing configurations needs more time.*"),
        (BackupState.UNKNOWN_ERROR, "error"),
    ),
)
def test_can_restore_fail_status(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker, pbm_state, pattern
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.active", return_value=True
    )
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
    )

    mock.return_value = pbm_state
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.assert_can_restore("backup", "remapping_pattern")
    assert e.match(pattern)


@pytest.mark.parametrize(
    ("backup_id", "remap_pattern", "pattern"),
    (("", "", "Missing backup-id.*"), ("2024", "", ".*'remap-pattern'.*")),
)
def test_can_restore_fail_params(
    harness: Harness[MongoTestCharm],
    backup_manager: BackupManager,
    mocker,
    backup_id,
    remap_pattern,
    pattern,
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=[BackupState.ACTIVE],
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager._needs_provided_remap_arguments",
        return_value=True,
    )
    with pytest.raises(InvalidArgumentForActionError) as e:
        backup_manager.assert_can_restore(backup_id, remap_pattern)

    assert e.match(pattern)


@pytest.mark.parametrize(
    ("pbm_status", "pattern"),
    (
        (BackupState.BACKUP_RUNNING, "Can only create one backup.*"),
        (BackupState.WAITING_TO_SYNC, "Sync-ing configurations needs more time.*"),
        (BackupState.UNKNOWN_ERROR, "error"),
    ),
)
def test_can_backup_fail(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker, pbm_status, pattern
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
    )

    mock.return_value = pbm_status
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.assert_can_backup()
    assert e.match(pattern)


@pytest.mark.parametrize(
    ("pbm_status", "pattern"),
    (
        (BackupState.WAITING_TO_SYNC, "Sync-ing configurations needs more time.*"),
        (BackupState.UNKNOWN_ERROR, "error"),
    ),
)
def test_can_list_backup_fail(
    harness: Harness[MongoTestCharm], backup_manager: BackupManager, mocker, pbm_status, pattern
) -> None:
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.active", return_value=True)
    relation_id = harness.add_relation(
        ExternalRequirerRelations.S3_CREDENTIALS.value, "s3-integrator"
    )
    harness.add_relation_unit(relation_id, "s3-integrator/0")
    mock = mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
    )

    mock.return_value = pbm_status
    with pytest.raises(InvalidPBMStatusError) as e:
        backup_manager.assert_can_list_backup()
    assert e.match(pattern)
