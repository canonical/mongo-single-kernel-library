# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from pathlib import Path

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import BlockedStatus, Relation, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    RelationNames,
)
from single_kernel_mongo.config.statuses import MongosStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
)
from single_kernel_mongo.state.tls_state import SECRET_CA_LABEL
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate

#################
# Mongo DB Side #
#################


def test_assert_pass_hook_checks_fail_db_not_initialised(
    harness: Harness[MongoTestCharm],
):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = False
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == "DB is not initialised"


def test_assert_pass_hook_checks_fail_invalid_mongos_integration(
    harness: Harness[MongoTestCharm],
):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION

    harness.add_relation(RelationNames.CLUSTER.value, "mongos")

    with pytest.raises(NonDeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert err.value.args[0] == "ClusterProvider is only executed by a config-server"

    statuses = harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=harness.charm.operator.name
    )
    assert any(status.status == "blocked" for status in statuses)


def test_assert_pass_hook_checks_fail_not_leader(harness: Harness[MongoTestCharm]):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    harness.add_relation(RelationNames.CLUSTER.value, "mongos")

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

    harness.add_relation(RelationNames.CLUSTER.value, "mongos")

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks()

    assert "during an upgrade" in err.value.args[0]


def test_share_secret_to_mongos(harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )

    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "mongos")
    harness.add_relation_unit(rel_id, "mongos/0")
    harness.update_relation_data(rel_id, "mongos", {"database": "test_mongos"})

    mocked_reconcile.assert_called()
    data = manager.data_interface.as_dict(rel_id)

    assert len(data.get("key-file", "")) == 1024

    assert data.get("config-server-db") == f"{harness.charm.app.name}/{mongodb_hostname}:27017"


def test_share_secret_to_mongos_also_shares_ldap_config(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str
):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.restart_charm_services"
    )

    valid_mapping = [
        {
            "match": "([^@]+)@([^@\\.]+)\\.example\\.com",
            "substitution": "CN={0},CN=Users,DC={1},DC=example,DC=com",
        }
    ]

    harness.update_config(
        {
            "role": MongoDBRoles.CONFIG_SERVER.value,
            "ldap-user-to-dn-mapping": json.dumps(valid_mapping),
        }
    )

    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "test-mongos")
    harness.add_relation_unit(rel_id, "test-mongos/0")
    harness.update_relation_data(rel_id, "test-mongos", {"database": "test_mongos"})

    mocked_reconcile.assert_called()
    data = manager.data_interface.as_dict(rel_id)

    assert len(data.get("key-file", "")) == 1024
    assert data.get("config-server-db") == f"{harness.charm.app.name}/{mongodb_hostname}:27017"
    assert data.get("ldap-user-to-dn-mapping") == json.dumps(valid_mapping)


@pytest.mark.skip_if_substrate("microk8s")
def test_cleanup_users(harness: Harness[MongoTestCharm], mocker):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )

    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "mongos")
    relation: Relation = harness.model.get_relation(RelationNames.CLUSTER.value, rel_id)  # type: ignore[assignment]
    harness.add_relation_unit(rel_id, "mongos/0")
    harness.update_relation_data(rel_id, "mongos", {"database": "test_mongos"})

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
        "is_waiting_to_request_certs",
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
            True,
            True,
            "Mongos was waiting for config-server to enable TLS. Wait for TLS to be enabled until starting mongos.",
        ),
        (
            False,
            False,
            False,
            True,
            "Processing client applications is not supported during an upgrade. The charm may be in a broken, unrecoverable state.",
        ),
    ),
)
def test_cluster_requirer_assert_pass_hook_checks_fail(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
    mongo_has_tls,
    is_waiting_to_request_certs,
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
        "single_kernel_mongo.managers.cluster.ClusterRequirer.is_waiting_to_request_certs",
        return_value=is_waiting_to_request_certs,
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

    mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    statuses = mongos_harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=mongos_harness.charm.operator.name
    )

    assert statuses[0].status == "waiting"
    assert statuses[0].message == "Connecting to config-server..."


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
        manager.share_credentials_to_clients("charmed_operator", "password")

    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.upgrade_in_progress",
        new_callable=mocker.PropertyMock(return_value=False),
    )

    manager.share_credentials_to_clients("charmed_operator", "password")

    assert manager.state.secrets.get_for_key(Scope.APP, "username") == "charmed_operator"
    assert manager.state.secrets.get_for_key(Scope.APP, "password") == "password"


def test_cluster_requirer_update_mongos_and_restart(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker, substrate: Substrate
):
    manager = mongos_harness.charm.operator.cluster_manager
    operator = mongos_harness.charm.operator
    mongos_harness.set_leader(True)

    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id_proxy = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "test-application")

    mongos_harness.add_relation_unit(rel_id_cluster, "mongodb/0")
    mongos_harness.add_relation_unit(rel_id_proxy, "test-application/0")

    mongos_harness.update_relation_data(rel_id_proxy, "test-application", {"database": "test-db"})

    manager.share_credentials_to_clients("charmed_operator", "password")

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch("single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs")

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {"key-file": "deadbeef", "config-server-db": "mongodb/2.2.2.2:27017"},
    )

    statuses = mongos_harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=mongos_harness.charm.operator.name
    )
    assert statuses[0].status == "active"
    assert manager.state.db_initialised

    for relation in operator.state.client_relations:
        data = relation.data[mongos_harness.charm.app]
        if substrate == "lxd":
            assert data["username"] == "charmed_operator"
            assert data["password"] == "password"
            assert (
                data["endpoints"]
                == "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"
            )
            assert (
                data["uris"]
                == "mongodb://charmed_operator:password@%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock/test-db?authSource=admin"
            )
        else:
            # on k8s, the router generates the password and user ids.
            assert data["username"] == f"relation-{relation.id}"
            assert len(data["password"]) == 32
            assert data["endpoints"] == "mongos-k8s-0.mongos-k8s-endpoints"
        assert data["database"] == "test-db"


@pytest.mark.parametrize(
    ("databag"), (({"key-file": "deadbeef"}), ({"config-server-db": "deadbeef"}), ({}))
)
def test_cluster_requirer_update_mongos_and_restart_fail_missing_data(
    mongos_harness: Harness[MongosTestCharm],
    mock_fs_interactions,
    mocker,
    databag: dict[str, str],
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        databag,
    )
    with pytest.raises(WaitingForSecretsError) as err:
        manager.update_mongos_and_restart()

    assert err.value.args[0] == "Waiting for keyfile or config server db uri"


def test_cluster_requirer_update_mongos_and_restart_mongos_not_running(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=False,
    )

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(rel_id_cluster, "mongodb/0")
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {"key-file": "deadbeef", "config-server-db": "mongodb/2.2.2.2:27017"},
    )

    # Check that we raise a deferrable error because mongos is not running after restart
    with pytest.raises(DeferrableError):
        manager.update_mongos_and_restart()

    # Check that we have the correct status
    statuses = mongos_harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=mongos_harness.charm.operator.name
    )
    assert as_status(statuses[0]) == WaitingStatus("Waiting to start mongos...")


def test_cluster_requirer_remove_users_and_cleanup_mongo(
    mongos_harness: Harness[MongosTestCharm], mock_fs_interactions, mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    relation_cluster: Relation = mongos_harness.model.get_relation(
        RelationNames.CLUSTER.value, rel_id_cluster
    )  # type: ignore[assignment]
    mongos_harness.add_relation_unit(rel_id_cluster, "mongodb/0")

    manager.share_credentials_to_clients("charmed_operator", "password")

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_user")

    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {"key-file": "deadbeef", "config-server-db": "mongodb/2.2.2.2:27017"},
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

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    # Create the TLS relation
    mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed_operator", "password")

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "mongodb/2.2.2.2:27017",
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

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.get_env",
        return_value={"MONGOS_ARGS": "unused"},
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    # Create the TLS relation if it should have one
    if mongos_has_tls:
        mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed_operator", "password")

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "mongodb/2.2.2.2:27017",
            "int-ca-secret": cluster_ca_secret or "",
        },
    )

    # Actual check
    assert manager.tls_status() == expected_statuses


@pytest.mark.parametrize(
    ("mongos_ca_secret", "cluster_ca_secret", "expected_status"),
    (
        (None, "deadbeef", MongosStatuses.REQUIRES_TLS.value),
        (
            "deadbeef",
            None,
            MongosStatuses.REQUIRES_NO_TLS.value,
        ),
        (None, None, None),
        ("deadbeef", "deadbeef", None),
        (
            "feeddead",
            "deadbeef",
            MongosStatuses.CA_MISMATCH.value,
        ),
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

    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.mongod_ready",
        return_value=True,
    )
    mocker.patch("single_kernel_mongo.managers.config.CommonConfigManager.set_environment")

    # Create the cluster relation
    rel_id_cluster = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    # Create the TLS relation if it should have one
    if mongos_ca_secret:
        mongos_harness.add_relation(ExternalRequirerRelations.TLS.value, "self-signed-certificates")
        # Local certificate
        manager.state.tls.set_secret(
            internal=True, label_name=SECRET_CA_LABEL, contents=mongos_ca_secret
        )

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed_operator", "password")

    data = Path("tests/unit/data/mongos.conf").read_text().splitlines()

    mocker.patch(
        "single_kernel_mongo.core.vm_workload.VMWorkload.read",
        return_value=data,
    )
    mocker.patch(
        "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.read",
        return_value=data,
    )

    # Write the information + optional certificate
    mongos_harness.update_relation_data(
        rel_id_cluster,
        "mongodb",
        {
            "key-file": "deadbeef",
            "config-server-db": "mongodb/2.2.2.2:27017",
            "int-ca-secret": cluster_ca_secret or "",
        },
    )

    # Actual check
    assert manager.get_tls_statuses() == expected_status
