# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops import MaintenanceStatus
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness
from pymongo.errors import AutoReconnect, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import (
    ConfigServerStatuses,
    MongoDBStatuses,
    MongodStatuses,
    MongosStatuses,
    PasswordManagementStatuses,
    ShardStatuses,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm


@pytest.mark.skip_if_substrate("microk8s")
@pytest.mark.parametrize(
    ("replset_status", "expected_status"),
    (
        ({}, MaintenanceStatus("Adding member...")),
        ({"10.0.0.1": "PRIMARY"}, ActiveStatus("Primary.")),
        ({"10.0.0.1": "SECONDARY"}, ActiveStatus("")),
        ({"10.0.0.1": "STARTUP"}, MaintenanceStatus("Syncing member...")),
        ({"10.0.0.1": "STARTUP2"}, MaintenanceStatus("Syncing member...")),
        ({"10.0.0.1": "ROLLBACK"}, MaintenanceStatus("Syncing member...")),
        ({"10.0.0.1": "RECOVERING"}, MaintenanceStatus("Syncing member...")),
        ({"10.0.0.1": "REMOVED"}, MaintenanceStatus("Removing member...")),
        ({"10.0.0.1": "ERROR"}, BlockedStatus("ERROR")),
    ),
)
def test_mongo_get_status_no_error_lxd(
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


@pytest.mark.skip_if_substrate("lxd")
@pytest.mark.parametrize(
    ("replset_status", "expected_status"),
    (
        ({}, MaintenanceStatus("Adding member...")),
        ({"mongodb-k8s-0.mongodb-k8s-endpoints": "PRIMARY"}, ActiveStatus("Primary.")),
        ({"mongodb-k8s-0.mongodb-k8s-endpoints": "SECONDARY"}, ActiveStatus("")),
        (
            {"mongodb-k8s-0.mongodb-k8s-endpoints": "STARTUP"},
            MaintenanceStatus("Syncing member..."),
        ),
        (
            {"mongodb-k8s-0.mongodb-k8s-endpoints": "STARTUP2"},
            MaintenanceStatus("Syncing member..."),
        ),
        (
            {"mongodb-k8s-0.mongodb-k8s-endpoints": "ROLLBACK"},
            MaintenanceStatus("Syncing member..."),
        ),
        (
            {"mongodb-k8s-0.mongodb-k8s-endpoints": "RECOVERING"},
            MaintenanceStatus("Syncing member..."),
        ),
        (
            {"mongodb-k8s-0.mongodb-k8s-endpoints": "REMOVED"},
            MaintenanceStatus("Removing member..."),
        ),
        ({"mongodb-k8s-0.mongodb-k8s-endpoints": "ERROR"}, BlockedStatus("ERROR")),
    ),
)
def test_mongo_get_status_no_error_microk8s(
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


def test_mongo_get_status_not_ready(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=False,
    )

    statuses = harness.charm.operator.mongo_manager.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongodStatuses.NOT_READY.value


@pytest.mark.parametrize(
    ("error", "expected_status"),
    (
        (
            ServerSelectionTimeoutError,
            MongodStatuses.WAITING_ELECTION.value,
        ),
        (AutoReconnect, MongodStatuses.WAITING_RECONNECTION.value),
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


@pytest.mark.parametrize(
    "role",
    [
        MongoDBRoles.SHARD,
        MongoDBRoles.REPLICATION,
    ],
)
def test_sharding_components_get_status_invalid_cluster_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions, role: MongoDBRoles
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = role

    harness.add_relation(RelationNames.CLUSTER.value, "mongos")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_MONGOS_REL.value


def test_replica_set_get_status_invalid_config_server_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_SHARDING_REL.value


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

    assert status == MongoDBStatuses.INVALID_DB_REL.value


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

    assert as_status(status) == MaintenanceStatus("Draining shard shard0...")


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

    assert as_status(status) == BlockedStatus("Shards: shard0 is unreachable.")


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


@pytest.mark.parametrize(("role"), ((MongoDBRoles.CONFIG_SERVER), (MongoDBRoles.REPLICATION)))
def test_get_statuses_system_users_no_secret_found(harness: Harness[MongoTestCharm], role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": "secret:12345",
            }
        )

    statuses = harness.charm.operator.get_statuses(scope=Scope.APP, recompute=True)
    status = next(iter(statuses), None)

    assert status == PasswordManagementStatuses.SECRET_NOT_FOUND.value


@pytest.mark.parametrize(("role"), ((MongoDBRoles.CONFIG_SERVER), (MongoDBRoles.REPLICATION)))
def test_get_statuses_system_users_invalid_content(
    harness: Harness[MongoTestCharm], mongodb_name, role
):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    system_users = {"invalid": "123"}
    secret_id = harness.add_model_secret(mongodb_name, system_users)
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    statuses = harness.charm.operator.get_statuses(scope=Scope.APP, recompute=True)
    status = next(iter(statuses), None)

    assert status == PasswordManagementStatuses.INVALID_SYSTEM_USERS.value


@pytest.mark.parametrize(("role"), ((MongoDBRoles.CONFIG_SERVER), (MongoDBRoles.REPLICATION)))
def test_get_statuses_system_users_invalid_secret_uri(harness: Harness[MongoTestCharm], role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": "1234",
            }
        )

    statuses = harness.charm.operator.get_statuses(scope=Scope.APP, recompute=True)
    status = next(iter(statuses), None)

    assert status == PasswordManagementStatuses.INVALID_SYSTEM_USERS.value


@pytest.mark.parametrize(("role"), ((MongoDBRoles.CONFIG_SERVER), (MongoDBRoles.REPLICATION)))
def test_get_statuses_valid_system_users(harness: Harness[MongoTestCharm], mongodb_name, role):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = role
    system_users = {"charmed-operator": "123"}
    secret_id = harness.add_model_secret(mongodb_name, system_users)
    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{role.value}",
                "system-users": f"{secret_id}",
            }
        )

    statuses = harness.charm.operator.get_statuses(scope=Scope.APP, recompute=True)
    assert len(statuses) == 0


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


def test_replica_set_get_status_invalid_sharding_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_SHARDING_REL.value


def test_shard_get_status_shard_with_system_users_config(
    harness: Harness[MongoTestCharm],
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    with harness.hooks_disabled():
        harness.update_config(
            {
                "role": f"{MongoDBRoles.SHARD.value}",
                "system-users": "some-secret",
            }
        )
    statuses = harness.charm.operator.get_statuses(scope=Scope.APP, recompute=True)
    status = next(iter(statuses), None)

    assert status == PasswordManagementStatuses.PASSWORD_ON_SHARD.value


def test_shard_get_status_charm_client_relation(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD

    harness.add_relation(RelationNames.DATABASE.value, "client")

    statuses = harness.charm.operator.get_statuses(scope=Scope.UNIT, recompute=True)
    status = next(iter(statuses), None)

    assert status == MongoDBStatuses.INVALID_DB_REL.value


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

    status_one = ShardStatuses.MISSING_PEER_TLS_REL.value
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.cluster_password_synced",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.tls_statuses",
        return_value=[status_one],
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
    expected_status = MongosStatuses.MISSING_PEER_TLS_REL.value
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.tls_statuses",
        return_value=[expected_status],
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
        "single_kernel_mongo.managers.cluster.ClusterRequirer.tls_statuses",
        return_value=[],
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
        "single_kernel_mongo.managers.cluster.ClusterRequirer.tls_statuses",
        return_value=[],
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
