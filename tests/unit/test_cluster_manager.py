# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import pytest
from ops.model import ActiveStatus, BlockedStatus, Relation, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import ExternalRequirerRelations, RelationNames
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
)
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL

from .helpers import patch_network_get
from .mongodb_test_charm.src.charm import MongoTestCharm
from .mongos_test_charm.src.charm import MongosTestCharm

#################
# Mongo DB Side #
#################


def test_assert_pass_hook_checks_fail_db_not_initialised(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == "DB is not initialised"


def test_assert_pass_hook_checks_fail_invalid_mongos_integration(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == "ClusterProvider is only executed by a config-server"
    assert isinstance(harness.charm.unit.status, BlockedStatus)


def test_assert_pass_hook_checks_fail_not_leader(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")

    harness.set_leader(False)

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == "Not leader"


def test_assert_pass_hook_checks_fail_upgrade_in_progress(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=True),
    )

    harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert "during an upgrade" in err.value.args[0]


@patch_network_get(private_address="1.1.1.1")
def test_share_secret_to_mongos(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )

    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")
    harness.add_relation_unit(rel_id, "test-mongos/0")
    harness.update_relation_data(rel_id, "test-mongos", {"database": "test_mongos"})

    mocked_reconcile.assert_called()
    data = manager.data_interface.as_dict(rel_id)

    assert len(data.get("key-file", "")) == 1024
    assert data.get("config-server-db") == f"{harness.charm.app.name}/1.1.1.1:27017"


@patch_network_get(private_address="1.1.1.1")
def test_cleanup_users(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )

    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")
    relation: Relation = harness.model.get_relation(RelationNames.CLUSTER.value, rel_id)  # type: ignore[assignment]
    harness.add_relation_unit(rel_id, "test-mongos/0")
    harness.update_relation_data(rel_id, "test-mongos", {"database": "test_mongos"})

    harness.charm.operator.state.unit_peer_data.update({f"relation_{rel_id}_departed": "false"})

    manager.cleanup_users(relation)

    mocked_reconcile.assert_called_with(relation, relation_departing=True)


###############
# Mongos Side #
###############


@pytest.mark.parametrize(
    (
        "mongo_has_tls",
        "config_server_has_tls",
        "is_ca_compatible",
        "upgrade_in_progress",
        "expected_error",
    ),
    (
        (
            False,
            True,
            True,
            True,
            "Config-Server uses TLS but mongos does not. Please synchronise encryption method.",
        ),
        (
            True,
            False,
            True,
            True,
            "Mongos uses TLS but config-server does not. Please synchronise encryption method.",
        ),
        (
            False,
            False,
            False,
            True,
            "mongos is integrated to a different CA than the config server. Please use the same CA for all cluster components.",
        ),
        (
            False,
            False,
            True,
            True,
            "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state.",
        ),
    ),
)
def test_cluster_requirer_assert_pass_hook_checks_fail(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
    mongo_has_tls,
    is_ca_compatible,
    upgrade_in_progress,
    config_server_has_tls,
    expected_error,
):
    manager = mongos_harness.charm.operator.cluster_manager

    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS

    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.tls_status",
        return_value=(mongo_has_tls, config_server_has_tls),
    )
    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.is_ca_compatible",
        return_value=is_ca_compatible,
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=upgrade_in_progress),
    )

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == expected_error


def test_cluster_requirer_set_relation_created_status(
    mongos_harness: Harness[MongosTestCharm],
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")

    assert isinstance(mongos_harness.charm.unit.status, WaitingStatus)
    assert mongos_harness.charm.unit.status.message == "Connecting to config-server"


def test_cluster_requirer_share_credentials_to_clients(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=True),
    )

    # No credentials
    with pytest.raises(WaitingForSecretsError):
        manager.share_credentials_to_clients(None, None)

    # Upgrade in progress
    with pytest.raises(DeferrableFailedHookChecksError):
        manager.share_credentials_to_clients("operator", "password")

    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=False),
    )

    manager.share_credentials_to_clients("operator", "password")

    assert manager.state.secrets.get_for_key(Scope.APP, "username") == "operator"
    assert manager.state.secrets.get_for_key(Scope.APP, "password") == "password"


@patch_network_get(private_address="1.1.1.1")
def test_cluster_requirer_update_mongos_and_restart(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    operator = mongos_harness.charm.operator
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )

    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")
    rel_id_proxy = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "test-application")

    mongos_harness.add_relation_unit(rel_id_cluster, "test-mongodb/0")
    mongos_harness.add_relation_unit(rel_id_proxy, "test-application/0")

    manager.share_credentials_to_clients("operator", "password")

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {"key-file": "deadbeef", "config-server-db": "test-mongodb/2.2.2.2:27017"},
    )

    assert isinstance(mongos_harness.charm.unit.status, ActiveStatus)
    assert manager.state.db_initialised

    for relation in operator.state.client_relations:
        data = relation.data[mongos_harness.charm.app]
        assert data["username"] == "operator"
        assert data["password"] == "password"
        assert data["database"] == "mongos-database"
        assert (
            data["endpoints"]
            == "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"
        )
        assert (
            data["uris"]
            == "mongodb://operator:password@%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock:27018/mongos-database?authSource=admin"
        )


@patch_network_get(private_address="1.1.1.1")
@pytest.mark.parametrize(
    ("databag"), (({"key-file": "deadbeef"}), ({"config-server-db": "deadbeef"}), ({}))
)
def test_cluster_requirer_update_mongos_and_restart_fail_missing_data(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker, databag: dict[str, str]
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        databag,
    )
    with pytest.raises(WaitingForSecretsError) as err:
        manager.update_mongos_and_restart()

    assert err.value.args[0] == "Waiting for keyfile or config server db uri"


@patch_network_get(private_address="1.1.1.1")
def test_cluster_requirer_update_mongos_and_restart_mongos_not_running(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=False)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")
    mongos_harness.add_relation_unit(rel_id_cluster, "test-mongodb/0")
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {"key-file": "deadbeef", "config-server-db": "test-mongodb/2.2.2.2:27017"},
    )

    # Check that we raise a deferrable error because mongos is not running after restart
    with pytest.raises(DeferrableError):
        manager.update_mongos_and_restart()

    # Check that we have the correct status
    assert mongos_harness.charm.unit.status == WaitingStatus("Waiting for mongos to start")


@patch_network_get(private_address="1.1.1.1")
def test_cluster_requirer_remove_users_and_cleanup_mongo(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")
    relation_cluster: Relation = mongos_harness.model.get_relation(
        RelationNames.CLUSTER.value, rel_id_cluster
    )  # type: ignore[assignment]
    mongos_harness.add_relation_unit(rel_id_cluster, "test-mongodb/0")

    manager.share_credentials_to_clients("operator", "password")

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {"key-file": "deadbeef", "config-server-db": "test-mongodb/2.2.2.2:27017"},
    )

    mongos_harness.charm.operator.state.unit_peer_data.update(
        {f"relation_{rel_id_cluster}_departed": "false"}
    )

    manager.remove_users_and_cleanup_mongo(relation_cluster)

    assert manager.state.secrets.get_for_key(Scope.APP, "username") is None
    assert manager.state.secrets.get_for_key(Scope.APP, "password") is None


@pytest.mark.parametrize(
    ("cluster_ca_secret", "mongos_ca_secret", "expected_compatibility"),
    (
        (None, None, True),
        (None, "deadbeef", True),
        ("deadbeef", None, True),
        ("deadbeef", "deadbeef", True),
        ("deadbeef", "feeddead", False),
    ),
)
def test_cluster_requirer_is_ca_compatible(
    mongos_harness: Harness[MongosTestCharm],
    mock_fs_interactions,
    mocker,
    cluster_ca_secret: str | None,
    mongos_ca_secret: str | None,
    expected_compatibility: bool,
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")

    # Create the TLS relation
    mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    # Ensure some credentials are present
    manager.share_credentials_to_clients("operator", "password")

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "test-mongodb/2.2.2.2:27017",
            "int-ca-secret": cluster_ca_secret or "",
        },
    )

    # Local certificate
    manager.state.tls.set_secret(
        internal=True, label_name=SECRET_CA_LABEL, contents=mongos_ca_secret
    )

    # Actual check
    assert manager.is_ca_compatible() == expected_compatibility


@pytest.mark.parametrize(
    ("mongos_has_tls", "cluster_ca_secret", "expected_statuses"),
    (
        (True, None, (True, False)),
        (False, None, (False, False)),
        (True, "deadbeef", (True, True)),
        (False, "deadbeef", (False, True)),
    ),
)
def test_cluster_requirer_tls_status(
    mongos_harness: Harness[MongosTestCharm],
    mock_fs_interactions,
    mocker,
    cluster_ca_secret: str | None,
    mongos_has_tls: bool,
    expected_statuses: tuple[bool, bool],
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")

    # Create the TLS relation if it should have one
    if mongos_has_tls:
        mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    # Ensure some credentials are present
    manager.share_credentials_to_clients("operator", "password")

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "test-mongodb/2.2.2.2:27017",
            "int-ca-secret": cluster_ca_secret or "",
        },
    )

    # Actual check
    assert manager.tls_status() == expected_statuses


@pytest.mark.parametrize(
    ("mongos_ca_secret", "cluster_ca_secret", "expected_status"),
    (
        (None, "deadbeef", BlockedStatus("mongos requires TLS to be enabled.")),
        ("deadbeef", None, BlockedStatus("mongos has TLS enabled but config-server does not.")),
        (None, None, None),
        ("deadbeef", "deadbeef", None),
        ("feeddead", "deadbeef", BlockedStatus("mongos CA and Config-Server CA don't match.")),
    ),
)
def test_cluster_requirer_get_tls_statuses(
    mongos_harness: Harness[MongosTestCharm],
    mock_fs_interactions,
    mocker,
    mongos_ca_secret: str | None,
    cluster_ca_secret: str | None,
    expected_status: BlockedStatus | None,
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.mongod_ready", return_value=True)
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "test-mongodb")

    # Create the TLS relation if it should have one
    if mongos_ca_secret:
        mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")
        # Local certificate
        manager.state.tls.set_secret(
            internal=True, label_name=SECRET_CA_LABEL, contents=mongos_ca_secret
        )

    # Ensure some credentials are present
    manager.share_credentials_to_clients("operator", "password")

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "test-mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "test-mongodb/2.2.2.2:27017",
            "int-ca-secret": cluster_ca_secret or "",
        },
    )

    # Actual check
    assert manager.get_tls_statuses() == expected_status
