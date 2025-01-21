# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from dataclasses import asdict

import pytest
from ops import MaintenanceStatus
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import Harness
from pymongo.errors import AutoReconnect, ServerSelectionTimeoutError

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.status import Statuses

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm
from .mongos_test_charm.src.charm import MongosTestCharm


@patch_network_get(private_address="1.1.1.1")
@pytest.mark.parametrize(
    ("replset_status", "expected_status"),
    (
        ({}, WaitingStatus("Member being added.")),
        ({"1.1.1.1": "PRIMARY"}, ActiveStatus("Primary")),
        ({"1.1.1.1": "SECONDARY"}, ActiveStatus("")),
        ({"1.1.1.1": "STARTUP"}, WaitingStatus("Member is syncing...")),
        ({"1.1.1.1": "STARTUP2"}, WaitingStatus("Member is syncing...")),
        ({"1.1.1.1": "ROLLBACK"}, WaitingStatus("Member is syncing...")),
        ({"1.1.1.1": "RECOVERING"}, WaitingStatus("Member is syncing...")),
        ({"1.1.1.1": "REMOVED"}, WaitingStatus("Member is removing...")),
        ({"1.1.1.1": "ERROR"}, BlockedStatus("ERROR")),
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

    status = harness.charm.operator.mongo_manager.get_status()

    assert status == expected_status


@patch_network_get(private_address="1.1.1.1")
@pytest.mark.parametrize(
    ("error", "expected_status"),
    (
        (ServerSelectionTimeoutError, WaitingStatus("Waiting for primary re-election.")),
        (AutoReconnect, WaitingStatus("Waiting to reconnect to unit...")),
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

    status = harness.charm.operator.mongo_manager.get_status()

    assert status == expected_status


def test_config_server_get_status_invalid_integration(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    assert harness.charm.operator.config_server_manager.get_status() == BlockedStatus(
        "sharding interface cannot be used by replicas"
    )


def test_config_server_get_status_invalid_role(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    assert harness.charm.operator.config_server_manager.get_status() is None


def test_config_server_get_status_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    assert harness.charm.operator.config_server_manager.get_status() is None


def test_config_server_get_status_client_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.DATABASE.value, "client")

    assert harness.charm.operator.config_server_manager.get_status() == BlockedStatus(
        "Sharding roles do not support database interface."
    )


def test_config_server_get_status_internal_mongos_not_running(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=False)

    assert harness.charm.operator.config_server_manager.get_status() == BlockedStatus(
        "Internal mongos is not running."
    )


def test_config_server_get_status_password_not_synced(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)

    assert harness.charm.operator.config_server_manager.get_status() == WaitingStatus(
        "Waiting to sync passwords across the cluster"
    )


def test_config_server_get_status_shard_draining(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.get_draining_shards",
        return_value=["shard0"],
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )

    assert harness.charm.operator.config_server_manager.get_status() == MaintenanceStatus(
        "Draining shard shard0"
    )


def test_config_server_get_status_unreachable_shards(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.get_draining_shards",
        return_value=[],
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=["shard0"],
    )

    assert harness.charm.operator.config_server_manager.get_status() == BlockedStatus(
        "shards shard0 are unreachable."
    )


def test_config_server_all_active(harness: Harness[MongoTestCharm], mocker, mock_fs_interactions):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.get_draining_shards",
        return_value=[],
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ConfigServerManager.get_unreachable_shards",
        return_value=[],
    )

    assert harness.charm.operator.config_server_manager.get_status() == ActiveStatus()


def test_shard_get_status_invalid_role(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    assert harness.charm.operator.shard_manager.get_status() is None


def test_shard_get_status_db_not_initialised(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    assert harness.charm.operator.shard_manager.get_status() is None


def test_shard_get_status_charm_is_replication(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    assert harness.charm.operator.shard_manager.get_status() == BlockedStatus(
        "Sharding interface cannot be used by replicas"
    )


def test_shard_get_status_charm_client_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.DATABASE.value, "client")

    assert harness.charm.operator.shard_manager.get_status() == BlockedStatus(
        "Sharding roles do not support database interface."
    )


def test_shard_get_status_charm_missing_relation_not_drained(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.charm.operator.state.unit_peer_data.drained = False

    assert harness.charm.operator.shard_manager.get_status() == BlockedStatus(
        "Missing relation to config-server."
    )


def test_shard_get_status_charm_missing_relation_drained(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.charm.operator.state.unit_peer_data.drained = True

    assert harness.charm.operator.shard_manager.get_status() == ActiveStatus(
        "Shard drained from cluster, ready for removal"
    )


def test_shard_get_status_cluster_password_not_synced(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=False,
    )

    assert harness.charm.operator.shard_manager.get_status() == WaitingStatus(
        "Waiting to sync passwords across the cluster"
    )


def test_shard_get_status_tls_status(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    status = BlockedStatus("Shard requires TLS to be enabled.")
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.get_tls_status",
        return_value=status,
    )

    assert harness.charm.operator.shard_manager.get_status() == status


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

    assert harness.charm.operator.shard_manager.get_status() == MaintenanceStatus(
        "Adding shard to config-server"
    )


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

    assert harness.charm.operator.shard_manager.get_status() == BlockedStatus(
        "Shard is not yet shard aware"
    )


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

    assert harness.charm.operator.shard_manager.get_status() == ActiveStatus()


@pytest.mark.parametrize(
    ("mongo_status", "shard_status", "config_server_status", "pbm_status", "expected_key"),
    (
        (BlockedStatus("error"), ActiveStatus(), ActiveStatus, ActiveStatus(), "mongodb"),
        (ActiveStatus("Primary"), None, None, None, "mongodb"),
        (ActiveStatus("Primary"), BlockedStatus("error"), None, None, "shard"),
        (ActiveStatus("Primary"), None, BlockedStatus("error"), None, "config_server"),
        (ActiveStatus("Primary"), ActiveStatus(), BlockedStatus("error"), None, "config_server"),
        (ActiveStatus("Primary"), ActiveStatus(), None, BlockedStatus("error"), "pbm"),
        (ActiveStatus("Primary"), ActiveStatus(), ActiveStatus(), BlockedStatus("error"), "pbm"),
    ),
)
def test_status_handler_prioritize_status(
    harness: Harness[MongoTestCharm],
    mocker,
    mongo_status,
    shard_status,
    config_server_status,
    pbm_status,
    expected_key,
):
    status_handler = harness.charm.status_manager

    status = Statuses(
        mongodb=mongo_status,
        shard=shard_status,
        config_server=config_server_status,
        pbm=pbm_status,
    )

    assert status_handler.prioritize_statuses(status) == asdict(status)[expected_key]  # type: ignore[literal-required]


def test_mongos_get_status_no_relation(
    mongos_harness: Harness[MongosTestCharm],
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = BlockedStatus("Missing relation to config-server.")
    assert mongos_operator.get_sanity_check_status() == expected_status

    mongos_harness.charm.status_manager.process_and_share_statuses()

    assert mongos_operator.charm.unit.status == expected_status


def test_mongos_get_status_tls_status(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = BlockedStatus("mongos requires TLS to be enabled.")
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_statuses",
        return_value=expected_status,
    )

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")

    assert mongos_operator.get_sanity_check_status() == expected_status

    mongos_harness.charm.status_manager.process_and_share_statuses()

    assert mongos_operator.charm.unit.status == expected_status


def test_mongos_get_status_mongos_not_running(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = WaitingStatus("Waiting for mongos to start.")
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_statuses",
        return_value=None,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.active",
        return_value=False,
    )

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "config-server")

    assert mongos_operator.get_sanity_check_status() == expected_status
    mongos_harness.charm.status_manager.process_and_share_statuses()

    assert mongos_operator.charm.unit.status == expected_status


def test_mongos_get_status_all_good(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
):
    mongos_operator = mongos_harness.charm.operator

    expected_status = ActiveStatus()
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

    assert mongos_operator.get_sanity_check_status() is None
    mongos_harness.charm.status_manager.process_and_share_statuses()

    assert mongos_operator.charm.unit.status == expected_status
