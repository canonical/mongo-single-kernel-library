# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from pathlib import PosixPath

import pytest
from data_platform_helpers.advanced_statuses.utils import as_status
from ops.testing import Harness

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import EntityStatuses, MongosStatuses
from single_kernel_mongo.exceptions import EntityRequestError
from single_kernel_mongo.state.cluster_state import ClusterStateKeys
from tests.charms.mongos_test_charm.src.charm import MongosTestCharm
from tests.integration.helpers.types import Substrate

GROUP_DN = "ou=superheroes,ou=users,dc=glauth,dc=com"


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


def test_mongos_rejected_entity_status_in_recompute(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.is_mongos_running",
        return_value=True,
    )
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    # The provider may only write `status` once the requirer has set `database`.
    with mongos_harness.hooks_disabled():
        mongos_harness.update_relation_data(
            rel_id, "client-app", {"database": "superdb", "entity-type": "USER"}
        )
    relation = mongos_harness.model.get_relation(RelationNames.MONGOS_PROXY.value, rel_id)
    mongos_harness.charm.operator.mongo_manager.reject_entity(
        relation, "entity-type 'USER' is not supported, only GROUP"
    )

    recomputed = mongos_harness.charm.operator.get_statuses(scope="app", recompute=True)

    assert any(s.status == "blocked" and f"(relation {rel_id})" in s.message for s in recomputed)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_forwards_group_request_to_cluster(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    permissions = '[{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]'

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {
            "database": "superdb",
            "entity-type": "GROUP",
            "extra-group-roles": "admin",
            "entity-permissions": permissions,
            "requested-entity-secret": secret_id,
        },
    )

    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    assert cluster_data[ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value] == "admin"
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value] == permissions
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == GROUP_DN
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_RELATION.value] == str(rel_id)
    assert cluster_data["database"] == "superdb"
    assert mongos_harness.charm.operator.state.app_peer_data.client_entity_fields == {
        ClusterStateKeys.CLIENT_ENTITY_TYPE.value: "GROUP",
        ClusterStateKeys.CLIENT_EXTRA_GROUP_ROLES.value: "admin",
        ClusterStateKeys.CLIENT_ENTITY_PERMISSIONS.value: permissions,
        ClusterStateKeys.CLIENT_ENTITY_NAME.value: GROUP_DN,
        ClusterStateKeys.CLIENT_ENTITY_RELATION.value: str(rel_id),
    }


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_forwards_stored_request_when_cluster_relation_arrives_later(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )

    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    assert ClusterStateKeys.CLIENT_ENTITY_NAME.value not in cluster_data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_unreadable_secret_is_rejected_locally(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": "secret:nope"},
    )

    statuses = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )
    assert statuses[0]["code"] == EntityStatuses.INVALID_REQUEST_CODE
    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert ClusterStateKeys.CLIENT_ENTITY_TYPE.value not in cluster_data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_publishes_entity_name_to_client(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )
    mongos_harness.update_relation_data(cluster_id, "mongodb", {"entity-name": GROUP_DN})

    mongos_harness.charm.operator.share_connection_info()

    data = mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert data["entity-name"] == GROUP_DN
    assert "username" not in data and "password" not in data and "uris" not in data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_does_not_forward_an_already_rejected_request(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": "secret:nope"},
    )
    rejected = mongos_harness.charm.operator.state.statuses.get(
        scope="app", component=mongos_harness.charm.operator.name
    ).root
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)

    mongos_harness.update_relation_data(
        rel_id, "client-app", {"requested-entity-secret": secret_id}
    )

    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert not [key for key in cluster_data if key.startswith("client-")]
    statuses = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )
    assert [s["code"] for s in statuses] == [EntityStatuses.INVALID_REQUEST_CODE]
    entity_statuses = [
        s
        for s in mongos_harness.charm.operator.state.statuses.get(
            scope="app", component=mongos_harness.charm.operator.name
        ).root
        if f"(relation {rel_id})" in s.message
    ]
    assert len(entity_statuses) == 1
    assert entity_statuses[0] in rejected


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_does_not_reread_a_forwarded_request(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": secret_id},
    )
    cluster_data = dict(mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name))
    forwarded = mongos_harness.charm.operator.state.app_peer_data.client_entity_fields
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == GROUP_DN
    # The requester's library removes its helper secret once the role exists.
    read_secret = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.requested_entity_name_from_secret",
        side_effect=EntityRequestError("cannot read requested-entity-secret"),
    )

    mongos_harness.update_relation_data(rel_id, "client-app/0", {"data": json.dumps({"x": 1})})

    read_secret.assert_not_called()
    assert "status" not in mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert not [
        s
        for s in mongos_harness.charm.operator.state.statuses.get(
            scope="app", component=mongos_harness.charm.operator.name
        ).root
        if s.status == "blocked"
    ]
    assert (
        dict(mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name))
        == cluster_data
    )
    assert mongos_harness.charm.operator.state.app_peer_data.client_entity_fields == forwarded


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_never_writes_entity_type_on_cluster(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "extra-group-roles": "admin"},
    )

    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    # `entity-type` would switch the library into entity mode and stop the router user.
    for library_key in ("entity-type", "extra-group-roles", "entity-permissions"):
        assert library_key not in cluster_data


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_rejects_a_client_permissions_change(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )
    cluster_data = dict(mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name))
    assert cluster_data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {
            "entity-permissions": '[{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]'
        },
    )

    statuses = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )
    assert [s["code"] for s in statuses] == [EntityStatuses.INVALID_REQUEST_CODE]
    message = statuses[0]["message"]
    assert message == (
        "invalid or unsupported request: changes to entity-permissions are not supported"
    )
    assert EntityStatuses.rejected(message, rel_id) in (
        mongos_harness.charm.operator.state.statuses.get(
            scope="app", component=mongos_harness.charm.operator.name
        ).root
    )
    # The change stays on the mongos side: the config-server never sees it.
    assert (
        dict(mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name))
        == cluster_data
    )


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_never_forwards_the_request_of_a_removed_client_relation(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )
    forwarded = dict(mongos_harness.charm.operator.state.app_peer_data.client_entity_fields)
    assert forwarded[ClusterStateKeys.CLIENT_ENTITY_RELATION.value] == str(rel_id)
    plain_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "plain-app")
    mongos_harness.add_relation_unit(plain_id, "plain-app/0")
    mongos_harness.update_relation_data(plain_id, "plain-app", {"database": "plaindb"})

    mongos_harness.remove_relation(rel_id)
    # The record is kept (relation-broken also runs on a leader whose principal unit
    # leaves); it is checked against the live client relations when used.
    assert mongos_harness.charm.operator.state.app_peer_data.client_entity_fields == forwarded
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.charm.operator.cluster_manager.forward_client_entity_fields()

    cluster_data = mongos_harness.get_relation_data(cluster_id, mongos_harness.charm.app.name)
    assert not [key for key in cluster_data if key.startswith("client-")]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_reforwards_a_live_request_after_cluster_reintegration(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    mongos_harness.add_relation_unit(cluster_id, "mongodb/0")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": secret_id},
    )
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )
    mongos_harness.update_relation_data(cluster_id, "mongodb", {"entity-name": GROUP_DN})
    mongos_harness.charm.operator.share_connection_info()
    assert (
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["entity-name"]
        == GROUP_DN
    )
    # The requester removes its helper secret once it received entity-name.
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.requested_entity_name_from_secret",
        side_effect=EntityRequestError("cannot read requested-entity-secret"),
    )
    # A leader whose principal unit is removed runs relation-broken while the relation lives on.
    relation = mongos_harness.model.get_relation(RelationNames.MONGOS_PROXY.value, rel_id)
    mongos_harness.charm.on[RelationNames.MONGOS_PROXY.value].relation_broken.emit(
        relation, app=relation.app
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )
    mocker.patch("single_kernel_mongo.managers.mongos_operator.MongosOperator.stop_charm_services")

    # Un-integrated from the config-server (the role is dropped there) and integrated again.
    mongos_harness.remove_relation(cluster_id)
    new_cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")

    new_cluster_data = mongos_harness.get_relation_data(
        new_cluster_id, mongos_harness.charm.app.name
    )
    assert new_cluster_data[ClusterStateKeys.CLIENT_ENTITY_TYPE.value] == "GROUP"
    assert new_cluster_data[ClusterStateKeys.CLIENT_ENTITY_NAME.value] == GROUP_DN
    assert new_cluster_data[ClusterStateKeys.CLIENT_ENTITY_RELATION.value] == str(rel_id)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_rejected_client_relation_broken_clears_its_blocked_status(mongos_harness):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": "secret:nope"},
    )
    message = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )[0]["message"]
    operator = mongos_harness.charm.operator
    app_statuses = operator.state.statuses.get(scope="app", component=operator.name).root
    assert EntityStatuses.rejected(message, rel_id) in app_statuses

    mongos_harness.remove_relation(rel_id)

    app_statuses = operator.state.statuses.get(scope="app", component=operator.name).root
    assert EntityStatuses.rejected(message, rel_id) not in app_statuses


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_never_rereads_a_fulfilled_request(mongos_harness, mocker):
    mongos_harness.set_leader(True)
    mongos_harness.charm.operator.state.app_peer_data.db_initialised = True
    cluster_id = mongos_harness.add_relation(RelationNames.CLUSTER.value, "mongodb")
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    secret_id = mongos_harness.add_model_secret("client-app", {"entity-name": GROUP_DN})
    mongos_harness.grant_secret(secret_id, mongos_harness.charm.app.name)
    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": secret_id},
    )
    mongos_harness.charm.operator.cluster_manager.share_credentials_to_clients("relation-1", "pw")
    mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.MongosOperator.update_ips_in_databag"
    )
    mongos_harness.update_relation_data(cluster_id, "mongodb", {"entity-name": GROUP_DN})
    mongos_harness.charm.operator.share_connection_info()
    # The requester removes its helper secret once it received entity-name; the record of
    # the forwarded request is missing.
    read_secret = mocker.patch(
        "single_kernel_mongo.managers.mongos_operator.requested_entity_name_from_secret",
        side_effect=EntityRequestError("cannot read requested-entity-secret"),
    )
    mongos_harness.charm.operator.state.app_peer_data.client_entity_fields = {}

    mongos_harness.update_relation_data(rel_id, "client-app/0", {"data": json.dumps({"x": 1})})

    read_secret.assert_not_called()
    assert "status" not in mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)
    assert not [
        s
        for s in mongos_harness.charm.operator.state.statuses.get(
            scope="app", component=mongos_harness.charm.operator.name
        ).root
        if s.status == "blocked"
    ]


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_vm_mongos_rejects_a_permissions_change_before_it_reaches_a_config_server(
    mongos_harness,
):
    # The request is stored for forwarding at once, whatever the mongos state: a change
    # skipped here would be lost and the stored request forwarded unchanged.
    mongos_harness.set_leader(True)
    rel_id = mongos_harness.add_relation(RelationNames.MONGOS_PROXY.value, "client-app")
    mongos_harness.add_relation_unit(rel_id, "client-app/0")
    mongos_harness.update_relation_data(
        rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
    )
    assert not mongos_harness.charm.operator.state.db_initialised

    mongos_harness.update_relation_data(
        rel_id,
        "client-app",
        {
            "entity-permissions": '[{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]'
        },
    )

    statuses = json.loads(
        mongos_harness.get_relation_data(rel_id, mongos_harness.charm.app.name)["status"]
    )
    assert [s["code"] for s in statuses] == [EntityStatuses.INVALID_REQUEST_CODE]
