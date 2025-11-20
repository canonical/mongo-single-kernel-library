# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import MaintenanceStatus, Relation
from ops.testing import Harness
from pymongo.errors import OperationFailure, ServerSelectionTimeoutError

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.models import BackupState
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    RelationNames,
)
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForCertificatesError,
    WaitingForSecretsError,
)
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import BackupUser, OperatorUser
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate

############################
# Config Server Side tests #
############################


def test_config_server_database_requested(
    harness: Harness[MongoTestCharm], mock_fs_interactions, mongodb_hostname: str
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    data = manager.data_interface.as_dict(rel_id)

    assert len(data.get("key-file", "")) == 1024
    assert data.get("database") == "unused"
    assert data.get("username") == "unused"
    assert data.get("password") == "unused"
    assert data.get("operator-password") is not None
    assert data.get("backup-password") is not None
    assert data.get("host") == f'["{mongodb_hostname}"]'


def test_config_server_database_requested_failed_db_not_initialised(
    harness: Harness[MongoTestCharm], mock_fs_interactions
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = False

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    relation: Relation = harness.charm.model.get_relation(RelationNames.CONFIG_SERVER.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.prepare_sharding_config(relation)

    assert err.value.args[0] == "db is not initialised."


def test_config_server_database_requested_failed_role_invalid(
    harness: Harness[MongoTestCharm], mock_fs_interactions
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    relation: Relation = harness.charm.model.get_relation(RelationNames.CONFIG_SERVER.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.prepare_sharding_config(relation)

    assert err.value.args[0] == "is only executed by config-server"


def test_config_server_database_requested_failed_not_leader(
    harness: Harness[MongoTestCharm], mock_fs_interactions
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    relation: Relation = harness.charm.model.get_relation(RelationNames.CONFIG_SERVER.value, rel_id)  # type: ignore[assignment]

    harness.set_leader(False)

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.prepare_sharding_config(relation)

    assert err.value.args == ()


def test_config_server_database_requested_failed_wrong_pbm_status(
    harness: Harness[MongoTestCharm], mocker, mock_fs_interactions
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.managers.backups.BackupManager.backup_state",
        return_value=BackupState.BACKUP_RUNNING,
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    relation: Relation = harness.charm.model.get_relation(RelationNames.CONFIG_SERVER.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.prepare_sharding_config(relation)

    assert err.value.args[0] == "Cannot add/remove shards while a backup/restore is in progress."


def test_config_server_update_credentials(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    manager.update_credentials("operator-password", "deadbeef")

    assert manager.data_interface.as_dict(rel_id).get("operator-password") == "deadbeef"


def test_config_server_update_ca_secret(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    manager.state.update_ca_secrets("newca")

    assert manager.data_interface.as_dict(rel_id).get("int-ca-secret") == "newca"


def test_config_server_add_shard(harness: Harness[MongoTestCharm], mocker, substrate: Substrate):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocked_add_shard = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.add_shard",
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
    harness.add_relation_unit(rel_id, "shard0/0")

    relation: Relation = harness.charm.model.get_relation(RelationNames.CONFIG_SERVER.value, rel_id)  # type: ignore[assignment]

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )
    harness.update_relation_data(rel_id, "shard0/0", {"private-address": "2.2.2.2"})

    manager.add_shard(relation)

    if substrate == "lxd":
        mocked_add_shard.assert_called_with("shard0", ["2.2.2.2"])
    else:
        mocked_add_shard.assert_called_with("shard0", ["shard0-0.shard0-endpoints"])


def test_config_server_cluster_password_synced_success(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_status",
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
    harness.add_relation_unit(rel_id, "shard0/0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    assert manager.cluster_password_synced()


@pytest.mark.parametrize(
    ("error"),
    (
        (OperationFailure("", 13)),
        (OperationFailure("", 18)),
        (ServerSelectionTimeoutError),
    ),
)
def test_config_server_cluster_password_synced_failure(
    harness: Harness[MongoTestCharm], mocker, error
):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        side_effect=error,
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_status",
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
    harness.add_relation_unit(rel_id, "shard0/0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    assert not manager.cluster_password_synced()


def test_config_server_cluster_password_synced_raises(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_shard_members",
        side_effect=OperationFailure("", 27),
    )
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.get_replset_status",
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
    harness.add_relation_unit(rel_id, "shard0/0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    with pytest.raises(OperationFailure) as err:
        manager.cluster_password_synced()

    assert err.value.code == 27


def test_config_server_get_unreachable_shards(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.config_server_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=False,
    )

    rel_id = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard0")
    rel_id_bis = harness.add_relation(RelationNames.CONFIG_SERVER.value, "shard1")
    harness.add_relation_unit(rel_id, "shard0/0")
    harness.add_relation_unit(rel_id_bis, "shard1/0")

    harness.update_relation_data(
        rel_id, "shard0", {"requested-secrets": '["unused"]', "database": "unused"}
    )
    harness.update_relation_data(
        rel_id_bis, "shard1", {"requested-secrets": '["unused"]', "database": "unused"}
    )

    assert set(manager.get_unreachable_shards()) == {"shard0", "shard1"}


####################
# Shard Side tests #
####################


def test_shard_manager_prepare_to_add_shard(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True

    harness.add_relation(RelationNames.SHARDING.value, "config-server")

    assert not manager.state.unit_peer_data.drained

    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.shard_manager.name
    )

    assert as_status(statuses[0]) == MaintenanceStatus("Adding shard to config-server...")


def test_shard_manager_synchronise_cluster_invalid_role(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")
    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.synchronise_cluster_secrets(relation)

    assert err.value.args[0] == "is only executed by shards"


def test_shard_manager_synchronise_cluster_secrets_success(
    harness: Harness[MongoTestCharm], mocker
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True
    mocked_update_member_auth = mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.update_member_auth"
    )
    mocked_sync = mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.sync_cluster_passwords"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )

    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")

    harness.update_relation_data(
        rel_id,
        "config-server",
        {
            "key-file": "deadbeef",
            "operator-password": "test-operator",
            "backup-password": "test-backup",
            "username": "unused",
            "password": "unused",
        },
    )

    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    manager.synchronise_cluster_secrets(relation)

    mocked_update_member_auth.assert_called_with("deadbeef", None)
    mocked_sync.assert_called_with("test-operator", "test-backup")

    assert manager.data_requirer.as_dict(rel_id).get("auth-updated", "false") == "true"


def test_shard_manager_synchronise_cluster_secrets_no_keyfile(
    harness: Harness[MongoTestCharm], mocker
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")

    harness.update_relation_data(
        rel_id,
        "config-server",
        {
            "operator-password": "test-operator",
            "backup-password": "test-backup",
            "username": "unused",
            "password": "unused",
        },
    )

    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(WaitingForSecretsError):
        manager.synchronise_cluster_secrets(relation)


def test_shard_manager_synchronise_cluster_secrets_no_ca_cert_waiting_for_both_certs(
    harness: Harness[MongoTestCharm], mocker
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True

    # Simulate missing certs
    mocker.patch(
        "single_kernel_mongo.managers.sharding.ShardManager.update_member_auth",
        side_effect=WaitingForCertificatesError,
    )

    rel_id = harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")
    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")

    harness.update_relation_data(
        rel_id,
        "config-server",
        {
            "key-file": "feeddead",
            "int-ca-secret": "deadbeef",
            "operator-password": "test-operator",
            "backup-password": "test-backup",
            "username": "unused",
            "password": "unused",
        },
    )

    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(WaitingForCertificatesError):
        manager.synchronise_cluster_secrets(relation)


def test_shard_manager_synchronise_cluster_secrets_mongod_not_ready(
    harness: Harness[MongoTestCharm], mocker
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True

    mocker.patch("single_kernel_mongo.managers.sharding.ShardManager.update_member_auth")
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=False,
    )

    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")

    harness.update_relation_data(
        rel_id,
        "config-server",
        {
            "key-file": "feeddead",
            "operator-password": "test-operator",
            "backup-password": "test-backup",
            "username": "unused",
            "password": "unused",
        },
    )

    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(NotReadyError):
        manager.synchronise_cluster_secrets(relation)


def test_shard_manager_sync_cluster_passwords(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader(True)

    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.primary",
        return_value=mongodb_hostname,
    )

    mock_set_user_password = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
    )
    patch_config_and_restart = mocker.patch(
        "single_kernel_mongo.managers.config.BackupConfigManager.configure_and_restart",
    )

    manager.sync_cluster_passwords("test-operator", "test-backup")

    mock_set_user_password.assert_any_call("operator", "test-operator")
    mock_set_user_password.assert_any_call("backup", "test-backup")
    patch_config_and_restart.assert_called()

    assert manager.state.get_user_password(OperatorUser) == "test-operator"
    assert manager.state.get_user_password(BackupUser) == "test-backup"


def test_shard_manager_remove_invalid_relation(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname
):
    manager = harness.charm.operator.shard_manager

    harness.set_leader()
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    harness.charm.operator.state.db_initialised = True

    rel_id = harness.add_relation(RelationNames.SHARDING.value, "config-server")

    relation: Relation = harness.charm.model.get_relation(RelationNames.SHARDING.value, rel_id)  # type: ignore[assignment]

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks(relation, is_leaving=True)

    assert err.value.args[0] == "Config-server never set up, no need to process broken event."
