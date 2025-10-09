# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from charm_refresh import PrecheckFailed
from ops.testing import Harness
from pymongo.errors import OperationFailure, PyMongoError, ServerSelectionTimeoutError

from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.core.abstract_upgrades_v3 import MongoDBRefresh
from single_kernel_mongo.exceptions import FailedToMovePrimaryError
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm


def test_on_config_changed_during_ugprade_fails(harness: Harness[MongoTestCharm], mocker):
    defer = mocker.patch("ops.framework.EventBase.defer")
    harness.charm.operator.refresh.in_progress = True
    mocker.patch("single_kernel_mongo.state.charm_state.CharmState.is_role", return_value=False)

    harness.charm.on.config_changed.emit()

    defer.assert_called()


@pytest.mark.parametrize(("handler",), (("relation_joined",), ("relation_changed",)))
def test_on_relation_handler(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, handler: str
):
    """Verifies that peer relation events are blocked on upgrade."""
    defer = mocker.patch("ops.framework.EventBase.defer")
    harness.charm.operator.refresh.in_progress = True
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True

    relation = harness.charm.model.get_relation("database-peers")

    getattr(harness.charm.on[relation.name], handler).emit(relation)

    defer.assert_called()


@pytest.mark.parametrize(
    ("old_version", "new_version", "expected"),
    (
        ("6.0.0", "7.0.0", False),
        ("6.0.0", "6.0.1", True),
        ("6.1.0", "7.0.0", False),
        ("7.0.0", "6.0.1", False),
        ("invalid", "6.0.0", False),
        ("6.0.0", "invalid", False),
    ),
)
def test_is_workload_compatible(old_version, new_version, expected: bool) -> None:
    assert (
        MongoDBRefresh.is_workload_compatible(
            old_workload_version=old_version, new_workload_version=new_version
        )
        == expected
    )


@pytest.mark.parametrize(
    ("backup_state", "pre_check_result"),
    (
        (BackupState.BACKUP_RUNNING, "Backup in progress."),
        (BackupState.RESTORE_RUNNING, "Restore in progress."),
    ),
)
def test_pre_refresh_check_after_1_unit_refreshed_fails(
    harness, mocker, backup_state, pre_check_result
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.__init__",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=backup_state,
    )
    refresh = MongoDBRefresh.__new__(MongoDBRefresh)
    refresh.charm = harness.charm
    refresh.dependent = harness.charm.operator
    refresh.state = harness.charm.state

    with pytest.raises(PrecheckFailed) as e:
        refresh.run_pre_refresh_checks_after_1_unit_refreshed()

    assert str(e.value) == pre_check_result


def test_pre_refresh_check_after_1_unit_refreshed_success(harness, mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.__init__",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=BackupState.ACTIVE,
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.wait_for_cluster_healthy"
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.move_primary_to_last_upgrade_unit"
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.is_cluster_able_to_read_write"
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.is_feature_compatibility_version"
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.are_pre_upgrade_operations_config_server_successful"
    )
    refresh = MongoDBRefresh.__new__(MongoDBRefresh)
    refresh.charm = harness.charm
    refresh.dependent = harness.charm.operator
    refresh.state = harness.charm.state

    refresh.run_pre_refresh_checks_after_1_unit_refreshed()


@pytest.mark.parametrize(
    ("checks", "pre_check_result"),
    (
        (
            {
                "mongod_ready": True,
                "are_nodes_healthy": False,
                "cluster_able_to_read_write": True,
            },
            "Cluster is not healthy",
        ),
        (
            {
                "mongod_ready": True,
                "are_nodes_healthy": True,
                "cluster_able_to_read_write": False,
            },
            "Cluster is not able to read/write to replicas",
        ),
    ),
)
def test_pre_refresh_check_before_any_unit_refreshed_boolean_fail(
    harness, mocker, checks, pre_check_result
):
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.__init__",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=BackupState.ACTIVE,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=checks["mongod_ready"],
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.are_nodes_healthy",
        return_value=checks["are_nodes_healthy"],
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.is_cluster_able_to_read_write",
        return_value=checks["cluster_able_to_read_write"],
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.move_primary_to_last_upgrade_unit",
        return_value=None,
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    refresh = MongoDBRefresh.__new__(MongoDBRefresh)
    refresh.charm = harness.charm
    refresh.dependent = harness.charm.operator
    refresh.state = harness.charm.state

    with pytest.raises(PrecheckFailed) as e:
        refresh.run_pre_refresh_checks_after_1_unit_refreshed()

    assert str(e.value) == pre_check_result


@pytest.mark.parametrize(
    ("checks", "pre_check_result"),
    (
        (
            {"are_nodes_healthy": PyMongoError, "move_primary_to_last_upgrade_unit": [None]},
            "Cluster is not healthy",
        ),
        (
            {
                "are_nodes_healthy": OperationFailure(error=""),
                "move_primary_to_last_upgrade_unit": [None],
            },
            "Cluster is not healthy",
        ),
        (
            {
                "are_nodes_healthy": ServerSelectionTimeoutError,
                "move_primary_to_last_upgrade_unit": [None],
            },
            "Cluster is not healthy",
        ),
        (
            {
                "are_nodes_healthy": [True],
                "move_primary_to_last_upgrade_unit": FailedToMovePrimaryError,
            },
            "Primary switchover failed",
        ),
    ),
)
def test_pre_refresh_check_before_any_unit_refreshed_raises(
    harness, mocker, checks, pre_check_result
):
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.__init__",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=BackupState.ACTIVE,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.is_cluster_able_to_read_write",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.are_nodes_healthy",
        side_effect=checks["are_nodes_healthy"],
    )
    mocker.patch(
        "single_kernel_mongo.core.abstract_upgrades_v3.MongoDBRefresh.move_primary_to_last_upgrade_unit",
        side_effect=checks["move_primary_to_last_upgrade_unit"],
    )
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    refresh = MongoDBRefresh.__new__(MongoDBRefresh)
    refresh.charm = harness.charm
    refresh.dependent = harness.charm.operator
    refresh.state = harness.charm.state

    with pytest.raises(PrecheckFailed) as e:
        refresh.run_pre_refresh_checks_after_1_unit_refreshed()

    assert str(e.value) == pre_check_result
