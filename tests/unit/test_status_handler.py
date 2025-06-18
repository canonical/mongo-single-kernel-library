# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops import MaintenanceStatus
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import Harness
from pymongo.errors import AutoReconnect, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import (
    ConfigServerStatuses,
    MongoDBStatuses,
    MongodStatuses,
    MongosStatuses,
    ShardStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm


@pytest.mark.parametrize(
    ("replset_status", "expected_status"),
    (
        ({}, WaitingStatus("Member being added...")),
        ({"10.0.0.10": "PRIMARY"}, ActiveStatus("Primary.")),
        ({"10.0.0.10": "SECONDARY"}, ActiveStatus("")),
        ({"10.0.0.10": "STARTUP"}, WaitingStatus("Member is syncing...")),
        ({"10.0.0.10": "STARTUP2"}, WaitingStatus("Member is syncing...")),
        ({"10.0.0.10": "ROLLBACK"}, WaitingStatus("Member is syncing...")),
        ({"10.0.0.10": "RECOVERING"}, WaitingStatus("Member is syncing...")),
        ({"10.0.0.10": "REMOVED"}, WaitingStatus("Member is removing...")),
        ({"10.0.0.10": "ERROR"}, BlockedStatus("ERROR")),
    ),
)
def test_mongo_get_status_no_error(
    harness: Harness[MongoTestCharm], mocker, replset_status, expected_status
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_status",
        return_value=replset_status,
    )

    statuses = harness.charm.operator.mongo_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert as_status(status) == expected_status


@pytest.mark.parametrize(
    ("error", "expected_status"),
    (
        (
            ServerSelectionTimeoutError,
            MongodStatuses.WAITING_ELECTION.value,
        ),
        (AutoReconnect, MongodStatuses.WAITING_RECONNECT.value),
    ),
)
def test_mongo_get_status_with_error(
    harness: Harness[MongoTestCharm], mocker, error, expected_status
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_status",
        side_effect=error,
    )

    statuses = harness.charm.operator.mongo_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == expected_status


def test_config_server_get_status_invalid_integration(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.SHARDING_ON_REPLICA.value


def test_config_server_get_status_invalid_role(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert status is None


def test_config_server_get_status_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert status is None


def test_config_server_get_status_client_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.DATABASE.value, "client")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_DB_REL_ON_SHARD.value


def test_config_server_get_status_internal_mongos_not_running(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=False,
    )

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value={"shard"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=[],
    )

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert status == ConfigServerStatuses.MONGOS_NOT_RUNNING.value


def test_config_server_get_status_password_not_synced(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=False,
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value={"shard"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=[],
    )

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert status == ConfigServerStatuses.SYNCING_PASSWORDS.value


def test_config_server_get_status_shard_draining(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value={"shard", "shard0"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert as_status(status) == MaintenanceStatus("Draining shard shard0")


def test_config_server_get_status_unreachable_shards(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value={"shard"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=["shard0"],
    )
    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert as_status(status) == BlockedStatus("Shards: shard0 are unreachable.")


def test_config_server_all_active(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        return_value={"shard"},
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=[],
    )

    statuses = harness.charm.operator.config_server_manager.get_statuses(
        scope=Scope.UNIT, recompute=True
    )
    status = next(iter(statuses), None)

    assert status == ConfigServerStatuses.ACTIVE_IDLE.value


def test_shard_get_status_invalid_role(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status is None


def test_shard_get_status_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status is None


def test_shard_get_status_charm_is_replication(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.SHARDING_ON_REPLICA.value


def test_shard_get_status_charm_client_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.DATABASE.value, "client")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_DB_REL_ON_SHARD.value


def test_shard_get_status_charm_missing_relation_not_drained(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.charm.operator.state.unit_peer_data.drained = False

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.MISSING_CONF_SERVER_REL.value


def test_shard_get_status_charm_missing_relation_drained(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.charm.operator.state.unit_peer_data.drained = True

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.SHARD_DRAINED.value


def test_shard_get_status_cluster_password_not_synced(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_shard_added_to_cluster",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager._is_shard_aware",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=False,
    )

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.SYNCING_PASSWORDS.value


def test_shard_get_status_tls_status(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    status_one = ShardStatuses.REQUIRES_TLS.value
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.get_tls_status",
        return_value=status_one,
    )

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == status_one


def test_shard_get_status_shard_not_added_to_cluster(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_shard_added_to_cluster",
        return_value=False,
    )

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.ADDING_TO_CLUSTER.value


def test_shard_get_status_shard_not_aware(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_shard_added_to_cluster",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager._is_shard_aware",
        return_value=False,
    )

    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.SHARD_NOT_AWARE.value


def test_shard_get_status_all_ok(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_shard_added_to_cluster",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager._is_shard_aware",
        return_value=True,
    )
    statuses = harness.charm.operator.shard_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == ShardStatuses.ACTIVE_IDLE.value


def test_mongos_get_status_no_relation(mongos_harness: Harness[MongosTestCharm], mocker):
    mongos_operator = mongos_harness.charm.operator

    expected_status = MongosStatuses.MISSING_CONF_SERVER_REL.value

    mocker.patch(
        "single_kernel_mongo.workload.VMMongosWorkload.workload_present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )

    statuses = mongos_operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == expected_status


def test_mongos_get_status_tls_status(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator
    mocker.patch(
        "single_kernel_mongo.workload.VMMongosWorkload.workload_present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )
    expected_status = MongosStatuses.REQUIRES_TLS.value
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_statuses",
        return_value=expected_status,
    )

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")

    statuses = mongos_operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == expected_status


def test_mongos_get_status_wait_to_connect(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = MongosStatuses.CONNECTING_TO_CONFIG_SERVER.value
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_statuses",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.workload_present",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.active",
        return_value=False,
    )

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")

    statuses = mongos_operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == expected_status


def test_mongos_get_statuses_needs_waiting_to_connect(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = MongosStatuses.CONNECTING_TO_CONFIG_SERVER.value

    mocker.patch(
        "single_kernel_mongo.workload.VMMongosWorkload.workload_present",
        new_callable=mocker.PropertyMock,
        return_value=True,
    )

    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_statuses",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.active",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")
    statuses = mongos_operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)
    assert status == expected_status
