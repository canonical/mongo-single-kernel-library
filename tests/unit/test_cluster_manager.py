# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from pathlib import Path

import pytest
from data_platform_helpers.advanced_statuses.models import StatusObject
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import Relation, WaitingStatus
from ops.testing import Harness

from single_kernel_mongo.config.literals import Scope
from single_kernel_mongo.config.models import MongosTLSState
from single_kernel_mongo.config.relations import (
    ExternalRequirerRelations,
    RelationNames,
)
from single_kernel_mongo.config.statuses import MongosStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import (
    ClusterTLSError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
    RelationStatus,
)
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from single_kernel_mongo.state.tls_state import (
    SECRET_CA_LABEL,
    SECRET_CERT_LABEL,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate
from tests.unit.helpers import CLUSTER_NAME, MODEL_NAME

GROUP_DN = "ou=superheroes,ou=users,dc=glauth,dc=com"

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

    harness.charm.operator.refresh.in_progress = True

    harness.add_relation(RelationNames.CLUSTER.value, "mongos")

    with pytest.raises(DeferrableFailedHookChecksError) as err:
        manager.assert_pass_hook_checks(initial_event=True)

    assert "during an upgrade" in err.value.args[0]


def test_share_secret_to_mongos(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str, substrate: Substrate
):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.unit_peer_data.cluster_address = mongodb_hostname

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
    if substrate == Substrate.lxd:
        assert len(data.get("cluster-id")) == 8
    else:
        assert data.get("cluster-id") is None


def test_share_secret_to_mongos_also_shares_ldap_config(
    harness: Harness[MongoTestCharm], mocker, mongodb_hostname: str
):
    manager = harness.charm.operator.cluster_manager

    harness.set_leader(True)
    harness.charm.operator.state.db_initialised = True
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.unit_peer_data.cluster_address = mongodb_hostname

    mocked_reconcile = mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager.reconcile_mongo_users_and_dbs"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongodb_operator.MongoDBOperator.async_restart_charm_services"
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


@pytest.mark.skip_if_substrate(Substrate.k8s)
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
    harness.charm.operator.state.app_peer_data.requested_entity_names = {str(rel_id): GROUP_DN}

    manager.cleanup_users(relation)

    mocked_reconcile.assert_called_with(relation, relation_departing=True)
    assert harness.charm.operator.state.app_peer_data.requested_entity_names == {}


###############
# Mongos Side #
###############


@pytest.mark.parametrize(
    (
        "peer_tls_status",
        "client_tls_status",
        "is_waiting_for_a_cert",
        "expected_error",
    ),
    (
        (
            MongosTLSState.VALID,
            MongosTLSState.missing(internal=True),
            True,
            "Invalid TLS integration, check logs.",
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.VALID,
            True,
            "Invalid TLS integration, check logs.",
        ),
        (
            MongosTLSState.VALID,
            MongosTLSState.invalid(internal=True),
            True,
            "Invalid TLS integration, check logs.",
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.VALID,
            True,
            "Invalid TLS integration, check logs.",
        ),
        (
            MongosTLSState.VALID,
            MongosTLSState.VALID,
            True,
            "Mongos was waiting for config-server to enable TLS. Wait for TLS to be enabled until starting mongos.",
        ),
    ),
)
def test_cluster_requirer_assert_pass_hook_checks_fail(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
    peer_tls_status: MongosTLSState,
    client_tls_status: MongosTLSState,
    is_waiting_for_a_cert: bool,
    expected_error: Exception,
):
    manager = mongos_harness.charm.operator.cluster_manager

    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.role = MongoDBRoles.MONGOS

    mocker.patch(
        "single_kernel_mongo.state.cluster_state.ClusterState.has_received_credentials",
        return_value=True,
    )

    mocker.patch(
        "single_kernel_mongo.managers.cluster.ClusterRequirer.get_tls_state",
        side_effect=(peer_tls_status, client_tls_status),
    )
    mocker.patch(
        "single_kernel_mongo.managers.tls.TLSManager.is_waiting_for_a_cert",
        return_value=is_waiting_for_a_cert,
    )

    with pytest.raises(ClusterTLSError) as err:
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
    mongos_harness.charm.operator.refresh.in_progress = True

    # No credentials
    with pytest.raises(WaitingForSecretsError):
        manager.share_credentials_to_clients(None, None)

    # Upgrade in progress
    with pytest.raises(DeferrableFailedHookChecksError):
        manager.share_credentials_to_clients("charmed-operator", "password")

    mongos_harness.charm.operator.refresh.in_progress = False

    manager.share_credentials_to_clients("charmed-operator", "password")

    assert manager.state.secrets.get_for_key(Scope.APP, "username") == "charmed-operator"
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
        {
            "key-file": "deadbeef",
            "config-server-db": "mongodb/2.2.2.2:27017",
            "username": "charmed-operator",
            "password": "password",  # nosec: B105
            "cluster-id": "cluster",
        },
    )

    manager.update_mongos_and_restart()
    statuses = mongos_harness.charm.operator.state.statuses.get(
        scope="unit", component=mongos_harness.charm.operator.name
    )
    assert statuses[0].status == "active"
    assert manager.state.db_initialised

    for relation in operator.state.client_relations:
        data = relation.data[mongos_harness.charm.app]
        if substrate == Substrate.lxd:
            assert data["username"] == "charmed-operator"
            assert data["password"] == "password"
            assert (
                data["endpoints"]
                == "%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock"
            )
            assert (
                data["uris"]
                == "mongodb://charmed-operator:password@%2Fvar%2Fsnap%2Fcharmed-mongodb%2Fcommon%2Fvar%2Fmongodb-27018.sock/test-db?authMechanism=SCRAM-SHA-256&authSource=admin"
            )
            assert mongos_harness.charm.operator.state.get_cluster_id() == "cluster"
        else:
            # on k8s, the router generates the password and user ids.
            assert data["username"] == f"relation-{relation.id}"
            assert len(data["password"]) == 32
            assert (
                data["endpoints"]
                == f"mongos-k8s-0.mongos-k8s-endpoints.{MODEL_NAME}.svc.{CLUSTER_NAME}"
            )
            assert mongos_harness.charm.operator.state.get_cluster_id() is None
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
        databag | {"username": "unused", "password": "unused"},
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
        {
            "key-file": "deadbeef",
            "config-server-db": "mongodb/2.2.2.2:27017",
            "username": "unused",
            "password": "unused",
        },
    )

    # Check that we raise a deferrable error because mongos is not running after restart
    with pytest.raises(WorkloadServiceError):
        manager.update_mongos_and_restart()

    # Check that we have the correct status
    statuses = mongos_harness.charm.operator.state.statuses.get(
        scope=Scope.UNIT, component=mongos_harness.charm.operator.name
    )
    assert as_status(statuses[0]) == WaitingStatus("Waiting for mongos to start...")


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

    manager.share_credentials_to_clients("charmed-operator", "password")

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
    mongos_harness.add_relation(
        ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
    )
    mongos_harness.add_relation(
        ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
    )

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed-operator", "password")

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
    assert manager.is_peer_ca_compatible() == expected_compatibility


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
        mongos_harness.add_relation(
            ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
        )
        mongos_harness.add_relation(
            ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
        )
        mocker.patch(
            "single_kernel_mongo.state.tls_state.TLSState.peer_enabled",
            new_callable=mocker.PropertyMock(return_value=True),
        )
        mocker.patch(
            "single_kernel_mongo.state.tls_state.TLSState.client_enabled",
            new_callable=mocker.PropertyMock(return_value=True),
        )

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed-operator", "password")

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
    assert manager.mongos_and_config_server_peer_tls_status() == expected_statuses


@pytest.mark.parametrize(
    (
        "mongos_peer_ca_secret",
        "cluster_peer_ca_secret",
        "mongos_client_ca_secret",
        "cluster_client_ca_secret",
        "expected_status",
    ),
    (
        (None, "deadbeef", None, None, [MongosStatuses.MISSING_PEER_TLS_REL.value]),
        ("deadbeef", None, None, None, [MongosStatuses.INVALID_PEER_TLS_REL.value]),
        (None, None, None, None, []),
        ("deadbeef", "deadbeef", None, None, []),
        ("deadbeef", "deadbeef", "deadbeef", "deadbeef", []),
        ("feeddead", "deadbeef", None, None, [MongosStatuses.PEER_CA_MISMATCH.value]),
        (None, None, None, "deadbeef", [MongosStatuses.MISSING_CLIENT_TLS_REL.value]),
        (None, None, "deadbeef", None, [MongosStatuses.INVALID_CLIENT_TLS_REL.value]),
        ("deadbeef", "deadbeef", "deadbeef", None, [MongosStatuses.INVALID_CLIENT_TLS_REL.value]),
        (None, None, "deadbeef", "deadbeef", []),
        (None, None, "feeddead", "deadbeef", [MongosStatuses.CLIENT_CA_MISMATCH.value]),
        (
            None,
            "deadbeef",
            None,
            "deadbeef",
            [
                MongosStatuses.MISSING_PEER_TLS_REL.value,
                MongosStatuses.MISSING_CLIENT_TLS_REL.value,
            ],
        ),
    ),
)
def test_cluster_requirer_get_tls_statuses(
    mongos_harness: Harness[MongosTestCharm],
    mock_fs_interactions,
    mocker,
    mongos_peer_ca_secret: str | None,
    cluster_peer_ca_secret: str | None,
    mongos_client_ca_secret: str | None,
    cluster_client_ca_secret: str | None,
    expected_status: list[StatusObject],
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
    if mongos_peer_ca_secret:
        mongos_harness.add_relation(
            ExternalRequirerRelations.PEER_TLS.value, "self-signed-certificates"
        )
        # Local CA certificate
        manager.state.tls.set_secret(
            internal=True, label_name=SECRET_CA_LABEL, contents=mongos_peer_ca_secret
        )
        # Local cert
        manager.state.tls.set_secret(
            internal=True, label_name=SECRET_CERT_LABEL, contents="useless"
        )
    if mongos_client_ca_secret:
        mongos_harness.add_relation(
            ExternalRequirerRelations.CLIENT_TLS.value, "self-signed-certificates"
        )
        manager.state.tls.set_secret(
            internal=False, label_name=SECRET_CA_LABEL, contents=mongos_client_ca_secret
        )
        # Local cert
        manager.state.tls.set_secret(
            internal=False, label_name=SECRET_CERT_LABEL, contents="useless"
        )

    # Ensure some credentials are present
    manager.share_credentials_to_clients("charmed-operator", "password")

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
            "int-ca-secret": cluster_peer_ca_secret or "",
            "ext-ca-secret": cluster_client_ca_secret or "",
        },
    )

    # Actual check
    assert manager.tls_statuses() == expected_status


@pytest.mark.parametrize(
    ("internal_tls_state", "external_tls_state", "expected"),
    (
        (
            MongosTLSState.VALID,
            MongosTLSState.missing(internal=True),
            True,
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.VALID,
            True,
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.missing(internal=True),
            True,
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.missing(internal=True),
            True,
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.invalid(internal=True),
            True,
        ),
        (
            MongosTLSState.VALID,
            MongosTLSState.VALID,
            False,
        ),
    ),
)
def test_tls_mongos_state_any_missing(
    internal_tls_state: MongosTLSState, external_tls_state: MongosTLSState, expected: bool
):
    ### Checks all the possible states for mongos tls state validation.
    assert MongosTLSState.any_missing(internal_tls_state | external_tls_state) == expected


@pytest.mark.parametrize(
    ("internal_tls_state", "external_tls_state", "expected"),
    (
        (
            MongosTLSState.VALID,
            MongosTLSState.invalid(internal=True),
            True,
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.VALID,
            True,
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.invalid(internal=True),
            True,
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.missing(internal=True),
            True,
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.invalid(internal=True),
            True,
        ),
        (
            MongosTLSState.VALID,
            MongosTLSState.VALID,
            False,
        ),
    ),
)
def test_tls_mongos_state_any_invalid(
    internal_tls_state: MongosTLSState, external_tls_state: MongosTLSState, expected: bool
):
    ### Checks all the possible states for mongos tls state validation.
    assert MongosTLSState.any_invalid(internal_tls_state | external_tls_state) == expected


@pytest.mark.parametrize(
    ("internal_tls_state", "external_tls_state", "expected"),
    (
        (
            MongosTLSState.VALID,
            MongosTLSState.incompatible(internal=True),
            True,
        ),
        (
            MongosTLSState.incompatible(internal=False),
            MongosTLSState.VALID,
            True,
        ),
        (
            MongosTLSState.incompatible(internal=False),
            MongosTLSState.incompatible(internal=True),
            True,
        ),
        (
            MongosTLSState.incompatible(internal=False),
            MongosTLSState.missing(internal=True),
            True,
        ),
        (
            MongosTLSState.missing(internal=False),
            MongosTLSState.incompatible(internal=True),
            True,
        ),
        (
            MongosTLSState.invalid(internal=False),
            MongosTLSState.invalid(internal=True),
            False,
        ),
        (
            MongosTLSState.VALID,
            MongosTLSState.VALID,
            False,
        ),
    ),
)
def test_tls_mongos_state_any_incompatible(
    internal_tls_state: MongosTLSState, external_tls_state: MongosTLSState, expected: bool
):
    ### Checks all the possible states for mongos tls state validation.
    assert MongosTLSState.any_incompatible(internal_tls_state | external_tls_state) == expected


def _app_statuses(mongos_harness):
    return mongos_harness.charm.operator.state.statuses.get(
        scope="app", component=mongos_harness.charm.operator.name
    ).root


def _vm_mongos_with_entity_client(mongos_harness):
    """A VM mongos leader that forwarded a GROUP request from `client-app`."""
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(cluster_id, "mongodb/0")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )
    return cluster_id, rel_id


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_mongos_mirrors_cluster_status_to_client(mongos_harness):
    cluster_id, rel_id = _vm_mongos_with_entity_client(mongos_harness)
    status = RelationStatus(code=5002, message="MongoDB refused createRole: x", resolution="r")

    mongos_harness.update_relation_data(
        cluster_id, "mongodb", {"status": json.dumps([status.__dict__])}
    )

    client_statuses = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )
    assert client_statuses == [status.__dict__]
    app_statuses = mongos_harness.charm.operator.state.statuses.get(
        scope="app", component=mongos_harness.charm.operator.name
    ).root
    assert any(f"(relation {rel_id})" in s.message for s in app_statuses)

    mongos_harness.update_relation_data(cluster_id, "mongodb", {"status": "[]"})

    assert (
        json.loads(
            mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
        )
        == []
    )
    app_statuses = mongos_harness.charm.operator.state.statuses.get(
        scope="app", component=mongos_harness.charm.operator.name
    ).root
    assert not any(f"(relation {rel_id})" in s.message for s in app_statuses)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_router_creates_and_removes_group_role(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    manager = mongos_harness.charm.operator.cluster_manager
    manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists", return_value=False
    )
    create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role"
    )
    drop_role = mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_role")
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_user")
    mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")

    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )

    assert create_role.call_args.args[0] == f"relation-{rel_id}"
    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert "username" not in data
    assert data["entity-name"] == f"relation-{rel_id}"

    cluster = mongos_harness.model.get_relation(RelationNames.CLUSTER.value)
    manager.remove_users_for_k8s_routers(cluster)

    drop_role.assert_called_once_with(f"relation-{rel_id}")


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_router_restart_creates_pending_group_role(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    manager = mongos_harness.charm.operator.cluster_manager
    manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists", return_value=False
    )
    create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role"
    )
    mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    # The request arrived while the router could not reach the cluster.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(
            rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
        )

    manager.update_users_for_k8s_routers()

    create_role.assert_called_once()
    assert create_role.call_args.args[0] == f"relation-{rel_id}"
    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert data["entity-name"] == f"relation-{rel_id}"
    assert "username" not in data


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_router_reintegration_recreates_named_group_role(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    manager = mongos_harness.charm.operator.cluster_manager
    manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists", return_value=False
    )
    create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role"
    )
    drop_role = mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_role")
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_user")
    mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": secret_id},
    )
    assert create_role.call_args.args[0] == GROUP_DN
    # The requester's library removes its helper secret once the role exists.
    mongos_harness.revoke_secret(secret_id, mongos_harness.charm.app.name)
    cluster = mongos_harness.model.get_relation(RelationNames.CLUSTER.value)

    manager.remove_users_for_k8s_routers(cluster)
    drop_role.assert_called_once_with(GROUP_DN)
    # Re-integration with a config-server: the router start reconciles client relations.
    manager.update_users_for_k8s_routers()

    assert create_role.call_count == 2
    assert create_role.call_args.args[0] == GROUP_DN
    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert data["entity-name"] == GROUP_DN
    assert "status" not in data
    assert not [
        s
        for s in mongos_harness.charm.operator.state.statuses.get(
            scope="app", component=mongos_harness.charm.operator.name
        ).root
        if s.status == "blocked"
    ]
    assert mongos_harness.charm.operator.state.app_peer_data.managed_entities == {
        str(rel_id): GROUP_DN
    }


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_mongos_mirrors_cluster_status_only_onto_the_entity_client(mongos_harness):
    cluster_id, rel_id = _vm_mongos_with_entity_client(mongos_harness)
    plain_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "plain-app")
    mongos_harness.add_relation_unit(plain_id, "plain-app/0")
    mongos_harness.update_relation_data(plain_id, "plain-app", {"database": "plaindb"})
    # A client that has not even sent `database` yet: raising a status there would fail.
    early_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "early-app")
    mongos_harness.add_relation_unit(early_id, "early-app/0")
    status = RelationStatus(code=5002, message="MongoDB refused createRole: x", resolution="r")

    mongos_harness.update_relation_data(
        cluster_id, "mongodb", {"status": json.dumps([status.__dict__])}
    )

    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert json.loads(data["status"]) == [status.__dict__]
    for other_id in (plain_id, early_id):
        assert "status" not in mongos_harness.get_relation_data(
            other_id, mongos_harness.charm.app.name
        )
    blocked = [s.message for s in _app_statuses(mongos_harness) if s.status == "blocked"]
    assert blocked == [f"{status.message} (relation {rel_id})"]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_mongos_mirrors_nothing_without_a_forwarded_request(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    # Seeded without hooks: the request was never forwarded to this config-server.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(
            rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
        )
    status = RelationStatus(code=5002, message="MongoDB refused createRole: x", resolution="r")

    mongos_harness.update_relation_data(
        cluster_id, "mongodb", {"status": json.dumps([status.__dict__])}
    )

    assert "status" not in mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert not [s for s in _app_statuses(mongos_harness) if s.status == "blocked"]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_mongos_mirrors_nothing_onto_a_client_without_entity_type(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "plain-app")
    mongos_harness.add_relation_unit(rel_id, "plain-app/0")
    mongos_harness.update_relation_data(rel_id, "plain-app", {"database": "plaindb"})
    # A stale record pointing at a relation that carries no entity request.
    mongos_harness.charm.operator.state.app_peer_data.client_entity_fields = {
        ClusterStateKeys.CLIENT_ENTITY_TYPE.value: "GROUP",
        ClusterStateKeys.CLIENT_ENTITY_RELATION.value: str(rel_id),
    }
    status = RelationStatus(code=5002, message="MongoDB refused createRole: x", resolution="r")

    mongos_harness.update_relation_data(
        cluster_id, "mongodb", {"status": json.dumps([status.__dict__])}
    )

    assert "status" not in mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert not [s for s in _app_statuses(mongos_harness) if s.status == "blocked"]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_cluster_broken_clears_mirrored_entity_statuses(mongos_harness, mocker):
    cluster_id, rel_id = _vm_mongos_with_entity_client(mongos_harness)
    status = RelationStatus(code=5002, message="MongoDB refused createRole: x", resolution="r")
    mongos_harness.update_relation_data(
        cluster_id, "mongodb", {"status": json.dumps([status.__dict__])}
    )
    assert json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    ) == [status.__dict__]
    unrelated = RelationStatus(code=1001, message="not an entity status", resolution="wait")
    DatabaseProviderData(mongos_harness.model, RelationNames.MONGOS_PROXY.value).raise_status(
        rel_id, unrelated
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )
    mocker.patch("single_kernel_mongo.managers.mongos_operator.MongosOperator.stop_charm_services")

    mongos_harness.remove_relation(cluster_id)

    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert json.loads(data["status"]) == [unrelated.__dict__]
    assert not [s for s in _app_statuses(mongos_harness) if s.status == "blocked"]
    recomputed = mongos_harness.charm.operator.get_statuses(scope="app", recompute=True)
    assert not [s for s in recomputed if f"(relation {rel_id})" in s.message]
    # Re-integrating forwards the request again, for the new config-server to judge.
    new_cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    new_cluster_data = mongos_harness.get_relation_data(
        new_cluster_id, mongos_harness.charm.app.name
    )
    assert new_cluster_data[ClusterStateKeys.CLIENT_ENTITY_RELATION.value] == str(rel_id)
