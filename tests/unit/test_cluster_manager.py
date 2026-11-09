# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from pathlib import Path
from unittest.mock import Mock

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
    DeferrableError,
    DeferrableFailedHookChecksError,
    NonDeferrableFailedHookChecksError,
    WaitingForSecretsError,
    WorkloadServiceError,
)
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from single_kernel_mongo.state.tls_state import (
    SECRET_CA_LABEL,
    SECRET_CERT_LABEL,
)
from single_kernel_mongo.utils.mongodb_users import roles_for_database
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate
from tests.unit.helpers import CLUSTER_NAME, CONNECTION, GROUP_DN, MODEL_NAME

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

    manager.cleanup_users(relation)

    mocked_reconcile.assert_called_with(relation, relation_departing=True)


# The request of a client of a VM mongos, as the mongos forwards it on the cluster relation,
# its name aside: `_mongos_relation` shares it in a secret of the mongos.
FORWARDED_REQUEST = {
    "database": "superdb",
    ClusterStateKeys.ENTITY_TYPE.value: "GROUP",
    ClusterStateKeys.EXTRA_GROUP_ROLES.value: "default",
    ClusterStateKeys.ENTITY_PERMISSIONS.value: json.dumps(
        [{"resource_name": "superdb.posts", "resource_type": "collection", "privileges": ["find"]}]
    ),
}


ENTITY_REQUEST_KEYS = (
    ClusterStateKeys.ENTITY_TYPE.value,
    ClusterStateKeys.EXTRA_GROUP_ROLES.value,
    ClusterStateKeys.ENTITY_PERMISSIONS.value,
    ClusterStateKeys.REQUESTED_ENTITY_SECRET.value,
)


def _config_server_setup(harness: Harness[MongoTestCharm], mocker) -> Mock:
    """Initialised config-server leader with the MongoDB user and role calls patched.

    Returns:
        The mock recording the user and role calls, in order.
    """
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.CONFIG_SERVER
    harness.charm.operator.state.db_initialised = True
    mocker.patch(f"{CONNECTION}.user_exists", return_value=False)
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager._compute_auth_restrictions",
        return_value=[],
    )
    calls = Mock()
    calls.get_role.return_value = None
    for method in ("create_user", "drop_user", "get_role", "create_role", "drop_role"):
        mocker.patch(f"{CONNECTION}.{method}", getattr(calls, method))
    return calls


def _name_secret(harness: Harness[MongoTestCharm], name: str) -> str:
    """Adds a mongos-owned `requested-entity-secret` granted to the config-server."""
    secret_id = harness.add_model_secret("mongos", {"entity-name": name})
    harness.grant_secret(secret_id, harness.charm.app.name)
    return secret_id


def _mongos_relation(
    harness: Harness[MongoTestCharm], data: dict[str, str], name: str | None = None
) -> int:
    """Adds a cluster relation whose mongos publishes `data`, and the entity `name` if given."""
    rel_id = harness.add_relation(RelationNames.CLUSTER.value, "mongos")
    harness.add_relation_unit(rel_id, "mongos/0")
    if name is not None:
        data = data | {ClusterStateKeys.REQUESTED_ENTITY_SECRET.value: _name_secret(harness, name)}
    harness.update_relation_data(rel_id, "mongos", data)
    return rel_id


def _entity_name(harness: Harness[MongoTestCharm], rel_id: int) -> str | None:
    """The entity name the config-server published, read without a cached secret."""
    data_interface = DatabaseProviderData(harness.model, RelationNames.CLUSTER.value)
    return data_interface.fetch_my_relation_field(rel_id, "entity-name")


def test_config_server_creates_role_for_forwarded_request(harness: Harness[MongoTestCharm], mocker):
    calls = _config_server_setup(harness, mocker)

    rel_id = _mongos_relation(harness, FORWARDED_REQUEST, GROUP_DN)

    calls.create_role.assert_called_once_with(
        GROUP_DN,
        [{"resource": {"db": "superdb", "collection": "posts"}, "actions": ["find"]}],
        [{"role": "readWrite", "db": "superdb"}, {"role": "enableSharding", "db": "superdb"}],
    )
    names = [name for name, _, _ in calls.mock_calls]
    assert names.index("create_user") < names.index("create_role")
    assert calls.create_user.call_args.args[0] == f"relation-{rel_id}"
    assert _entity_name(harness, rel_id) == GROUP_DN
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}


def test_config_server_drops_role_when_cluster_relation_breaks(
    harness: Harness[MongoTestCharm], mocker, substrate: Substrate
):
    calls = _config_server_setup(harness, mocker)
    if substrate == Substrate.lxd:
        rel_id = _mongos_relation(harness, FORWARDED_REQUEST, GROUP_DN)
        assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    else:
        # A mongos-k8s router creates its own roles: it forwards nothing.
        rel_id = _mongos_relation(harness, {"database": "superdb"})
        assert harness.charm.operator.state.entity_relations == set()
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )
    mocker.patch(f"{CONNECTION}.user_exists", return_value=True)

    harness.remove_relation(rel_id)

    if substrate == Substrate.lxd:
        calls.drop_role.assert_called_once_with(GROUP_DN)
        # Together with the router user.
        calls.drop_user.assert_called_once_with(f"relation-{rel_id}")
    else:
        calls.drop_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_config_server_drops_role_once_mongos_units_are_gone(
    harness: Harness[MongoTestCharm], mocker, monkeypatch
):
    calls = _config_server_setup(harness, mocker)
    # The mongos asks for the entity name as a secret, like the cluster requirer does.
    monkeypatch.setenv("JUJU_VERSION", "3.6.0")
    rel_id = _mongos_relation(
        harness, FORWARDED_REQUEST | {"requested-secrets": json.dumps(["entity-name"])}, GROUP_DN
    )
    assert _entity_name(harness, rel_id) == GROUP_DN
    assert "secret-entity" in harness.get_relation_data(rel_id, harness.charm.app.name)

    # The subordinate mongos units vanish with its client relation, its request stays.
    harness.remove_relation_unit(rel_id, "mongos/0")
    calls.drop_role.assert_not_called()

    # Honoured at the next update-status.
    harness.charm.operator.reconcile_entities()

    calls.drop_role.assert_called_once_with(GROUP_DN)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    assert _entity_name(harness, rel_id) is None
    assert "secret-entity" not in harness.get_relation_data(rel_id, harness.charm.app.name)

    # A relation-changed deferred while the units were there does not re-create it.
    relation = harness.model.get_relation(RelationNames.CLUSTER.value, rel_id)
    with pytest.raises(DeferrableError):
        harness.charm.operator.cluster_manager.share_secret_to_mongos(relation)
    calls.create_role.assert_called_once()


def test_config_server_renames_role(harness: Harness[MongoTestCharm], mocker, monkeypatch):
    calls = _config_server_setup(harness, mocker)
    monkeypatch.setenv("JUJU_VERSION", "3.6.0")
    rel_id = _mongos_relation(
        harness, FORWARDED_REQUEST | {"requested-secrets": json.dumps(["entity-name"])}, GROUP_DN
    )

    # A new client asks for another name before the withdrawal of the previous one was seen.
    harness.update_relation_data(
        rel_id,
        "mongos",
        {ClusterStateKeys.REQUESTED_ENTITY_SECRET.value: _name_secret(harness, "ou=villains")},
    )

    calls.drop_role.assert_called_once_with(GROUP_DN)
    assert calls.create_role.call_count == 2
    assert calls.create_role.call_args.args[0] == "ou=villains"
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: "ou=villains"}
    assert _entity_name(harness, rel_id) == "ou=villains"


def test_config_server_replaces_role_forwarded_with_another_definition(
    harness: Harness[MongoTestCharm], mocker
):
    calls = _config_server_setup(harness, mocker)
    rel_id = _mongos_relation(harness, FORWARDED_REQUEST, GROUP_DN)
    _, privileges, roles = calls.create_role.call_args.args
    # The existing role as `rolesInfo` reads it, then gone once dropped.
    calls.get_role.side_effect = [{"privileges": privileges, "roles": roles}, None]

    # A replacement client asks for the same name with other roles before the units rule ran.
    # The library refuses a changed value, so the mongos clears its request first.
    harness.update_relation_data(rel_id, "mongos", dict.fromkeys(ENTITY_REQUEST_KEYS, ""))
    calls.drop_role.assert_not_called()
    harness.update_relation_data(
        rel_id,
        "mongos",
        FORWARDED_REQUEST
        | {
            ClusterStateKeys.EXTRA_GROUP_ROLES.value: "monitor",
            ClusterStateKeys.REQUESTED_ENTITY_SECRET.value: _name_secret(harness, GROUP_DN),
        },
    )

    calls.drop_role.assert_called_once_with(GROUP_DN)
    assert calls.create_role.call_count == 2
    assert calls.create_role.call_args.args == (
        GROUP_DN,
        privileges,
        roles_for_database("superdb", {"monitor"}),
    )
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}


def test_library_refuses_a_changed_forwarded_extra_group_roles(
    harness: Harness[MongoTestCharm], mocker
):
    _config_server_setup(harness, mocker)
    rel_id = _mongos_relation(harness, FORWARDED_REQUEST, GROUP_DN)

    # Why the mongos clears its request before it writes other roles.
    with pytest.raises(ValueError, match="Cannot change extra-group-roles"):
        harness.update_relation_data(
            rel_id, "mongos", {ClusterStateKeys.EXTRA_GROUP_ROLES.value: "monitor"}
        )


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


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_router_cleanup_drops_entity_roles_and_keeps_entity_name(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    manager = mongos_harness.charm.operator.cluster_manager
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(cluster_id, "mongodb/0")
    manager.share_credentials_to_clients(f"relation-{cluster_id}", "password")
    mocker.patch(f"{CONNECTION}.get_role", return_value=None)
    create_role = mocker.patch(f"{CONNECTION}.create_role")
    drop_role = mocker.patch(f"{CONNECTION}.drop_role")
    drop_user = mocker.patch(f"{CONNECTION}.drop_user")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": secret_id},
    )
    create_role.assert_called_once()
    # The requester stops sharing its secret once the entity name is published.
    mongos_harness.revoke_secret(secret_id, mongos_harness.charm.app.name)
    cluster: Relation = mongos_harness.model.get_relation(RelationNames.CLUSTER.value, cluster_id)  # type: ignore[assignment]

    manager.remove_users_for_k8s_routers(cluster)

    drop_role.assert_called_once_with(GROUP_DN)
    drop_user.assert_called_once_with(f"relation-{cluster_id}")  # the router user
    assert mongos_harness.charm.operator.state.app_peer_data.managed_entities == {}
    data_interface = DatabaseProviderData(mongos_harness.model, RelationNames.MONGOS_PROXY.value)
    assert data_interface.fetch_my_relation_field(rel_id, "entity-name") == GROUP_DN

    # Integrated again: the router start re-creates the role under the published name.
    manager.update_users_for_k8s_routers()

    assert create_role.call_count == 2
    assert create_role.call_args.args[0] == GROUP_DN
    assert mongos_harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}


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
