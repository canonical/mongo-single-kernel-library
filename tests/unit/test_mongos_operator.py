# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import PosixPath

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.testing import Harness

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import MongodStatuses, MongosStatuses
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate
from tests.unit.helpers import CONNECTION, GROUP_DN


def test_start(
    mongos_harness: Harness[MongosTestCharm],
    mocker,
    mock_refresh,
    mock_fs_interactions,
    substrate: Substrate,
):
    if substrate == Substrate.lxd:
        mocked_copy = mocker.patch("single_kernel_mongo.core.vm_workload.VMWorkload.copy_to_unit")
    else:
        mocked_copy = mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.copy_to_unit"
        )

    mocker.patch("single_kernel_mongo.core.operator.OperatorProtocol.setup_systemd_overrides")

    mongos_harness.charm.on.start.emit()
    mongos_harness.evaluate_status()
    assert mongos_harness.charm.unit.status == as_status(
        MongosStatuses.MISSING_CONF_SERVER_REL.value
    )

    if substrate == Substrate.lxd:
        mocked_copy.assert_has_calls(
            [
                mocker.call(
                    PosixPath("LICENSE"),
                    PosixPath("src/licenses/LICENSE-charm"),
                ),
                mocker.call(
                    PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-snap"),
                    PosixPath("src/licenses/LICENSE-snap"),
                ),
                mocker.call(
                    PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-mongodb-exporter"),
                    PosixPath("src/licenses/LICENSE-mongodb-exporter"),
                ),
                mocker.call(
                    PosixPath(
                        "/snap/charmed-mongodb/current/licenses/LICENSE-percona-backup-mongodb"
                    ),
                    PosixPath("src/licenses/LICENSE-percona-backup-mongodb"),
                ),
                mocker.call(
                    PosixPath("/snap/charmed-mongodb/current/licenses/LICENSE-percona-server"),
                    PosixPath("src/licenses/LICENSE-percona-server"),
                ),
            ]
        )
    else:
        mocked_copy.assert_has_calls(
            [
                mocker.call(
                    PosixPath("/licenses/LICENSE-rock"),
                    PosixPath("LICENSE-rock"),
                ),
                mocker.call(
                    PosixPath("/licenses/LICENSE-snap"),
                    PosixPath("LICENSE-snap"),
                ),
                mocker.call(
                    PosixPath("/licenses/LICENSE-mongodb-exporter"),
                    PosixPath("LICENSE-mongodb-exporter"),
                ),
                mocker.call(
                    PosixPath("/licenses/LICENSE-percona-backup-mongodb"),
                    PosixPath("LICENSE-percona-backup-mongodb"),
                ),
                mocker.call(
                    PosixPath("/licenses/LICENSE-percona-server"),
                    PosixPath("LICENSE-percona-server"),
                ),
            ]
        )


def test_share_connection_info_fail_db_not_initialised(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = False

    mocked_share = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator._share_configuration"
    )

    mongos_harness.charm.operator.share_connection_info()

    mocked_share.assert_not_called()


def test_share_connection_info_fail_not_leader(mongos_harness: Harness[MongosTestCharm], mocker):
    mongos_harness.set_leader(False)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True

    mocked_share = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator._share_configuration"
    )

    mongos_harness.charm.operator.share_connection_info()

    mocked_share.assert_not_called()


@pytest.mark.parametrize(
    ("databag", "expected_db", "expected_extra_user_roles", "expected_connectivity"),
    (
        (
            {
                "database": "test",
                "extra-user-roles": "default,admin",
                "external-node-connectivity": "false",
            },
            "test",
            {"default", "admin"},
            False,
        ),
        (
            {
                "database": "test",
                "external-node-connectivity": "false",
            },
            "test",
            {"default"},
            False,
        ),
        (
            {
                "database": "test",
                "external-node-connectivity": "true",
            },
            "test",
            {"default"},
            True,
        ),
    ),
)
def test_proxy_information_to_client_and_handler_connectivity(
    mongos_harness: Harness[MongosTestCharm],
    substrate: Substrate,
    mocker,
    databag,
    expected_db,
    expected_extra_user_roles,
    expected_connectivity,
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    mock_open_port = mocker.patch("ops.model.Unit.open_port")

    manager = mongos_harness.charm.operator.cluster_manager
    manager.share_credentials_to_clients("charmed-operator", "password")

    if substrate == Substrate.k8s:
        mocker.patch(
            "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists",
            return_value=False,
        )
        mocker.patch(
            "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
        )

    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        databag,
    )

    if substrate == Substrate.lxd:
        assert mongos_harness.charm.operator.state.app_peer_data.database == expected_db
        assert (
            mongos_harness.charm.operator.state.app_peer_data.extra_user_roles
            == expected_extra_user_roles
        )
        assert (
            mongos_harness.charm.operator.state.app_peer_data.external_connectivity
            == expected_connectivity
        )

        if expected_connectivity:
            mock_open_port.assert_called()
    else:
        data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
        assert data["database"] == expected_db
        assert len(data["password"]) == 32
        assert data["username"] == f"relation-{rel_id}"


PERMISSIONS = json.dumps(
    [{"resource_name": "superdb.posts", "resource_type": "collection", "privileges": ["find"]}]
)
# Raw strings: the VM mongos forwards them as they are, a parsed value would lose the space.
GROUP_REQUEST = {
    "database": "superdb",
    "entity-type": "GROUP",
    "extra-group-roles": "monitor, admin",
    "entity-permissions": PERMISSIONS,
}
CLIENT_ENTITY_KEYS = (
    ClusterStateKeys.CLIENT_ENTITY_TYPE.value,
    ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value,
    ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value,
    ClusterStateKeys.CLIENT_ENTITY_NAME.value,
)


def _mongos_leader(mongos_harness: Harness[MongosTestCharm]) -> int:
    """An initialised mongos leader integrated with its config-server.

    Returns:
        The id of the cluster relation.
    """
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(cluster_id, "mongodb/0")
    return cluster_id


def _client_relation(
    mongos_harness: Harness[MongosTestCharm],
    data: dict[str, str],
    name: str | None = None,
    app: str = "client-app",
) -> int:
    """Adds a `mongos_proxy` relation whose requester publishes `data`.

    With `name`, the requester also shares a `requested-entity-secret` carrying it.
    """
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, app)
    mongos_harness.add_relation_unit(rel_id, f"{app}/0")
    if name is not None:
        secret_id = mongos_harness.add_model_secret(app, {"entity-name": name})
        mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
        data = data | {"requested-entity-secret": secret_id}
    mongos_harness.update_relation_data(rel_id, app, data)
    return rel_id


def _published(mongos_harness: Harness[MongosTestCharm], rel_id: int, field: str) -> str | None:
    data_interface = DatabaseProviderData(mongos_harness.model, RelationNames.MONGOS_PROXY.value)
    return data_interface.fetch_my_relation_field(rel_id, field)


def _app_statuses(mongos_harness: Harness[MongosTestCharm]) -> list:
    """The app statuses the status handler shows for the mongos operator."""
    return mongos_harness.charm.operator.get_statuses(scope="app")


def _cluster_data(mongos_harness: Harness[MongosTestCharm], cluster_id: int) -> dict[str, str]:
    """The data this mongos wrote on the cluster relation."""
    return dict(mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name))


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_writes_client_keys(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _mongos_leader(mongos_harness)

    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)

    data = _cluster_data(mongos_harness, cluster_id)
    assert data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    assert data[ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value] == "monitor, admin"
    assert data[ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value] == PERMISSIONS
    assert data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == GROUP_DN
    assert data["database"] == "superdb"
    # The library's own names would turn the router user request into an entity request.
    for library_key in ("entity-type", "extra-group-roles", "entity-permissions"):
        assert library_key not in data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_unreadable_secret_forwards_nothing(
    mongos_harness: Harness[MongosTestCharm], caplog
):
    cluster_id = _mongos_leader(mongos_harness)

    rel_id = _client_relation(
        mongos_harness, GROUP_REQUEST | {"requested-entity-secret": "secret:nope"}
    )

    data = _cluster_data(mongos_harness, cluster_id)
    assert not [key for key in CLIENT_ENTITY_KEYS if key in data]
    assert data["database"] == "superdb"
    assert f"Cannot forward the entity request of relation {rel_id}" in caplog.text


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_invalid_request_forwards_nothing(
    mongos_harness: Harness[MongosTestCharm], caplog
):
    cluster_id = _mongos_leader(mongos_harness)

    rel_id = _client_relation(mongos_harness, GROUP_REQUEST | {"entity-type": "USER"})

    data = _cluster_data(mongos_harness, cluster_id)
    assert not [key for key in data if key.startswith("client-")]
    # The mongos reports why, the config-server never sees the request.
    assert f"Cannot forward the entity request of relation {rel_id}" in caplog.text
    assert "entity-type 'USER' is not supported" in caplog.text
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(mongos_harness)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_invalid_forwarded_request_status_cleared_once_valid(
    mongos_harness: Harness[MongosTestCharm],
):
    _mongos_leader(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST | {"entity-type": "USER"})
    operator = mongos_harness.charm.operator
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(mongos_harness)
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in operator.get_statuses(
        scope="app", recompute=True
    )

    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(rel_id, "client-app", {"entity-type": "GROUP"})
    mongos_harness.charm.on.update_status.emit()

    assert MongodStatuses.INVALID_ENTITY_REQUEST.value not in _app_statuses(mongos_harness)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_rewrites_changed_fields(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _mongos_leader(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": "ou=villains"})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    new_permissions = PERMISSIONS.replace("find", "insert")

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"requested-entity-secret": secret_id, "entity-permissions": new_permissions},
    )

    # Not answered yet: the name is copied whenever it changes, like the other fields.
    data = _cluster_data(mongos_harness, cluster_id)
    assert data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == "ou=villains"
    assert data[ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value] == new_permissions

    # A field the request no longer carries is not kept.
    mongos_harness.update_relation_data(rel_id, "client-app", {"extra-group-roles": ""})
    data = _cluster_data(mongos_harness, cluster_id)
    assert ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value not in data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_invalid_request_clears_forwarded_request(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _mongos_leader(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": "charmed-operator"})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)

    mongos_harness.update_relation_data(
        rel_id, "client-app", {"requested-entity-secret": secret_id}
    )

    assert not [
        key for key in CLIENT_ENTITY_KEYS if key in _cluster_data(mongos_harness, cluster_id)
    ]
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(mongos_harness)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_user_client_after_entity_client_clears_forwarded_request(
    mongos_harness: Harness[MongosTestCharm],
):
    cluster_id = _mongos_leader(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    # The remote data may be unreadable in relation-broken: a removal changes nothing, the
    # config-server ends the request once the mongos units are gone.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(
            rel_id, "client-app", dict.fromkeys([*GROUP_REQUEST, "requested-entity-secret"], "")
        )
    mongos_harness.remove_relation(rel_id)
    assert all(key in _cluster_data(mongos_harness, cluster_id) for key in CLIENT_ENTITY_KEYS)

    _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")

    assert not [
        key for key in CLIENT_ENTITY_KEYS if key in _cluster_data(mongos_harness, cluster_id)
    ]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_user_client_keeps_request_of_another_relation(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _mongos_leader(mongos_harness)
    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)

    _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")

    assert all(key in _cluster_data(mongos_harness, cluster_id) for key in CLIENT_ENTITY_KEYS)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_invalid_change_of_answered_request_keeps_forwarded_request(
    mongos_harness: Harness[MongosTestCharm],
):
    cluster_id = _mongos_leader(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    relation = mongos_harness.model.get_relation(RelationNames.MONGOS_PROXY.value, rel_id)
    # Answered: the role exists and its name is published to the client.
    mongos_harness.charm.operator.state.entity_state(relation).entity_name = GROUP_DN

    mongos_harness.update_relation_data(rel_id, "client-app", {"entity-permissions": "not json"})

    assert all(key in _cluster_data(mongos_harness, cluster_id) for key in CLIENT_ENTITY_KEYS)
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(mongos_harness)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_share_configuration_clears_stale_forwarded_request(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _mongos_leader(mongos_harness)
    with mongos_harness.hooks_disabled():
        _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")
        # Left by a previous client: the clear on this relation's events was missed.
        cluster = mongos_harness.charm.operator.state.cluster
        cluster.client_entity_type = "GROUP"
        cluster.client_entity_name = GROUP_DN
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )

    mongos_harness.charm.operator.share_connection_info()

    assert not [
        key for key in CLIENT_ENTITY_KEYS if key in _cluster_data(mongos_harness, cluster_id)
    ]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_share_connection_info_forwards_request_of_earlier_client(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    # The client relation exists before the config-server integration.
    with mongos_harness.hooks_disabled():
        _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(cluster_id, "mongodb/0")
    assert not [
        key for key in CLIENT_ENTITY_KEYS if key in _cluster_data(mongos_harness, cluster_id)
    ]
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )

    mongos_harness.charm.operator.share_connection_info()

    data = _cluster_data(mongos_harness, cluster_id)
    assert data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    assert data[ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value] == "monitor, admin"
    assert data[ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value] == PERMISSIONS
    assert data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == GROUP_DN


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_share_entity_name_relays_config_server_name(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _mongos_leader(mongos_harness)
    entity_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    user_id = _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )

    # Nothing to relay until the config-server publishes the name.
    mongos_harness.charm.operator.share_connection_info()
    assert _published(mongos_harness, entity_id, "entity-name") is None

    # The name of a previous request is not the answer to the current one.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(cluster_id, "mongodb", {"entity-name": "ou=old"})
    mongos_harness.charm.operator.share_connection_info()
    assert _published(mongos_harness, entity_id, "entity-name") is None

    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(cluster_id, "mongodb", {"entity-name": GROUP_DN})
    mongos_harness.charm.operator.share_connection_info()

    assert _published(mongos_harness, entity_id, "entity-name") == GROUP_DN
    assert _published(mongos_harness, user_id, "entity-name") is None


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_share_configuration_skips_entity_relations(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _mongos_leader(mongos_harness)
    entity_id = _client_relation(mongos_harness, GROUP_REQUEST)
    user_id = _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )

    mongos_harness.charm.operator.share_connection_info()

    for field in ("username", "password", "uris"):
        assert _published(mongos_harness, entity_id, field) is None
    assert _published(mongos_harness, user_id, "username") == f"relation-{cluster_id}"
    assert _published(mongos_harness, user_id, "uris")


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_reconcile_entities_creates_roles(mongos_harness: Harness[MongosTestCharm], mocker):
    cluster_id = _mongos_leader(mongos_harness)
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    mocker.patch(f"{CONNECTION}.get_role", return_value=None)
    create_role = mocker.patch(f"{CONNECTION}.create_role")
    drop_role = mocker.patch(f"{CONNECTION}.drop_role")
    # The request arrived while the router could not reach the cluster.
    with mongos_harness.hooks_disabled():
        rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    mongos_harness.charm.operator.state.app_peer_data.managed_entities = {999: "orphan-role"}

    mongos_harness.charm.operator.reconcile_entities()

    create_role.assert_called_once()
    assert create_role.call_args.args[0] == GROUP_DN
    drop_role.assert_called_once_with("orphan-role")
    assert mongos_harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    assert _published(mongos_harness, rel_id, "entity-name") == GROUP_DN


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_shows_event_time_entity_status_until_recompute(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _mongos_leader(mongos_harness)
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    get_role = mocker.patch(f"{CONNECTION}.get_role", return_value={"privileges": [], "roles": []})
    mocker.patch(f"{CONNECTION}.create_role")
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.is_mongos_running",
        return_value=True,
    )
    operator = mongos_harness.charm.operator

    # A hand-made role of another definition holds the name: refused at event time.
    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    assert _app_statuses(mongos_harness) == [MongodStatuses.ENTITY_ROLE_NOT_CREATED.value]

    get_role.return_value = None
    operator.reconcile_entities()
    operator.get_statuses(scope="app", recompute=True)

    assert MongodStatuses.ENTITY_ROLE_NOT_CREATED.value not in _app_statuses(mongos_harness)


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_k8s_get_statuses_includes_entity_statuses(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    _mongos_leader(mongos_harness)
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.is_mongos_running",
        return_value=True,
    )
    with mongos_harness.hooks_disabled():
        _client_relation(mongos_harness, {"database": "superdb", "entity-type": "USER"})

    statuses = mongos_harness.charm.operator.get_statuses(scope="app", recompute=True)

    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in statuses
