# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import PosixPath

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.model import SecretNotFoundError
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
FORWARDED_KEYS = (
    ClusterStateKeys.ENTITY_TYPE.value,
    ClusterStateKeys.EXTRA_GROUP_ROLES.value,
    ClusterStateKeys.ENTITY_PERMISSIONS.value,
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


def _vm_proxy(mongos_harness: Harness[MongosTestCharm]) -> int:
    """A VM mongos leader which received its router credentials from the config-server.

    Returns:
        The id of the cluster relation.
    """
    cluster_id = _mongos_leader(mongos_harness)
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    return cluster_id


def _forwarded(mongos_harness: Harness[MongosTestCharm], cluster_id: int) -> dict[str, str]:
    """The entity request this mongos forwards, the name read from its secret."""
    data = _cluster_data(mongos_harness, cluster_id)
    request = {key: data[key] for key in FORWARDED_KEYS if key in data}
    if secret_id := data.get(ClusterStateKeys.REQUESTED_ENTITY_SECRET.value):
        secret = mongos_harness.model.get_secret(id=secret_id)
        request["entity-name"] = secret.get_content(refresh=True)["entity-name"]
    return request


def _config_server_sees(mongos_harness: Harness[MongosTestCharm], cluster_id: int) -> None:
    """The config-server processes the mongos data: its library keeps it under `data`."""
    data = _cluster_data(mongos_harness, cluster_id)
    data.pop("data", None)
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(cluster_id, "mongodb", {"data": json.dumps(data)})


def _no_ip_update(mocker) -> None:
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_keeps_library_keys(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _vm_proxy(mongos_harness)

    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)

    assert _forwarded(mongos_harness, cluster_id) == {
        "entity-type": "GROUP",
        "extra-group-roles": "monitor, admin",
        "entity-permissions": PERMISSIONS,
        "entity-name": GROUP_DN,
    }
    data = _cluster_data(mongos_harness, cluster_id)
    assert data["database"] == "superdb"
    # The mongos cannot grant the secret of its client: it shares the name in its own.
    secret_id = data[ClusterStateKeys.REQUESTED_ENTITY_SECRET.value]
    assert mongos_harness.get_secret_grants(secret_id, cluster_id) == {"mongodb"}
    assert not [key for key in data if key.startswith("client-")]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_waits_for_router_credentials(
    mongos_harness: Harness[MongosTestCharm], mocker, caplog
):
    cluster_id = _mongos_leader(mongos_harness)
    _no_ip_update(mocker)

    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)

    # With `entity-type` on the relation the library would not emit `database_created`,
    # which delivers the router credentials.
    assert _forwarded(mongos_harness, cluster_id) == {}
    assert _cluster_data(mongos_harness, cluster_id)["database"] == "superdb"
    assert "router credentials not received yet" in caplog.text

    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    mongos_harness.charm.operator.share_connection_info()

    assert _forwarded(mongos_harness, cluster_id)["entity-name"] == GROUP_DN


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_unreadable_secret_forwards_nothing(
    mongos_harness: Harness[MongosTestCharm], caplog
):
    cluster_id = _vm_proxy(mongos_harness)

    rel_id = _client_relation(
        mongos_harness, GROUP_REQUEST | {"requested-entity-secret": "secret:nope"}
    )

    assert _forwarded(mongos_harness, cluster_id) == {}
    assert _cluster_data(mongos_harness, cluster_id)["database"] == "superdb"
    assert f"Cannot forward the entity request of relation {rel_id}" in caplog.text


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_forwards_invalid_request_as_is(
    mongos_harness: Harness[MongosTestCharm],
):
    cluster_id = _vm_proxy(mongos_harness)
    invalid = GROUP_REQUEST | {"entity-type": "USER", "entity-permissions": "not json"}

    _client_relation(mongos_harness, invalid, name="charmed-operator")

    # The config-server judges the request and blocks.
    assert _forwarded(mongos_harness, cluster_id) == {
        "entity-type": "USER",
        "extra-group-roles": "monitor, admin",
        "entity-permissions": "not json",
        "entity-name": "charmed-operator",
    }
    operator = mongos_harness.charm.operator
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value not in _app_statuses(mongos_harness)
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value not in operator.get_statuses(
        scope="app", recompute=True
    )


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_rewrites_changed_fields(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _vm_proxy(mongos_harness)
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
    forwarded = _forwarded(mongos_harness, cluster_id)
    assert forwarded["entity-name"] == "ou=villains"
    assert forwarded["entity-permissions"] == new_permissions

    # A field the request no longer carries is not kept.
    mongos_harness.update_relation_data(rel_id, "client-app", {"extra-group-roles": ""})
    assert "extra-group-roles" not in _forwarded(mongos_harness, cluster_id)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_forward_entity_request_replaces_roles_once_the_config_server_saw_the_clear(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _vm_proxy(mongos_harness)
    _no_ip_update(mocker)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    _config_server_sees(mongos_harness, cluster_id)
    operator = mongos_harness.charm.operator

    # A replacement client of this subordinate asks for other roles.
    mongos_harness.remove_relation(rel_id)
    _client_relation(
        mongos_harness, GROUP_REQUEST | {"extra-group-roles": "monitor"}, GROUP_DN, "new-app"
    )

    # The library of the config-server refuses a changed value: the request is cleared first.
    assert _forwarded(mongos_harness, cluster_id) == {}
    operator.share_connection_info()
    assert _forwarded(mongos_harness, cluster_id) == {}

    _config_server_sees(mongos_harness, cluster_id)
    operator.share_connection_info()

    assert _forwarded(mongos_harness, cluster_id)["extra-group-roles"] == "monitor"


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_user_client_after_entity_client_clears_forwarded_request(
    mongos_harness: Harness[MongosTestCharm],
):
    cluster_id = _vm_proxy(mongos_harness)
    rel_id = _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)
    secret_id = _cluster_data(mongos_harness, cluster_id)["requested-entity-secret"]
    # The remote data may be unreadable in relation-broken: a removal changes nothing, the
    # config-server ends the request once the mongos units are gone.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(
            rel_id, "client-app", dict.fromkeys([*GROUP_REQUEST, "requested-entity-secret"], "")
        )
    mongos_harness.remove_relation(rel_id)
    assert _forwarded(mongos_harness, cluster_id)["entity-name"] == GROUP_DN

    _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")

    assert _forwarded(mongos_harness, cluster_id) == {}
    with pytest.raises(SecretNotFoundError):
        mongos_harness.model.get_secret(id=secret_id)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_user_client_keeps_request_of_another_relation(mongos_harness: Harness[MongosTestCharm]):
    cluster_id = _vm_proxy(mongos_harness)
    _client_relation(mongos_harness, GROUP_REQUEST, name=GROUP_DN)

    _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")

    assert _forwarded(mongos_harness, cluster_id)["entity-name"] == GROUP_DN


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_share_configuration_clears_stale_forwarded_request(
    mongos_harness: Harness[MongosTestCharm], mocker
):
    cluster_id = _vm_proxy(mongos_harness)
    with mongos_harness.hooks_disabled():
        _client_relation(mongos_harness, {"database": "plaindb"}, app="plain-app")
        # Left by a previous client: the clear on this relation's events was missed.
        cluster = mongos_harness.charm.operator.state.cluster
        cluster.entity_type = "GROUP"
        cluster.requested_entity_name = GROUP_DN
    _no_ip_update(mocker)

    mongos_harness.charm.operator.share_connection_info()

    assert _forwarded(mongos_harness, cluster_id) == {}


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
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients(
        f"relation-{cluster_id}", "password"
    )
    assert _forwarded(mongos_harness, cluster_id) == {}
    _no_ip_update(mocker)

    mongos_harness.charm.operator.share_connection_info()

    assert _forwarded(mongos_harness, cluster_id) == {
        "entity-type": "GROUP",
        "extra-group-roles": "monitor, admin",
        "entity-permissions": PERMISSIONS,
        "entity-name": GROUP_DN,
    }


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
