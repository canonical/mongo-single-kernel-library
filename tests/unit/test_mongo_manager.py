# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from ops.testing import Harness
from pymongo.errors import AutoReconnect, OperationFailure, PyMongoError, WriteConcernError

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import EntityStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
    RelationStatus,
)
from single_kernel_mongo.utils.mongo_connection import NotReadyError
from single_kernel_mongo.utils.mongodb_users import (
    OPERATOR_ROLE,
    CharmedBackupUser,
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
)
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.integration.helpers.types import Substrate
from tests.unit.helpers import MongoConfigurationFactory


def test_set_user_password(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password")
    harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == "deadbeef"


def test_set_user_not_ready(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=NotReadyError,
    )
    old_password = harness.charm.operator.state.get_user_password(CharmedOperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == old_password


def test_set_user_pymongo_error(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.set_user_password",
        side_effect=PyMongoError,
    )
    old_password = harness.charm.operator.state.get_user_password(CharmedOperatorUser)
    with pytest.raises(SetPasswordError):
        harness.charm.operator.mongo_manager.set_user_password(CharmedOperatorUser, "deadbeef")

    assert harness.charm.operator.state.get_user_password(CharmedOperatorUser) == old_password


def test_initialise_replica_set_operation_failure(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.init_replset",
        side_effect=OperationFailure(error="woooops", code=11),
    )
    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.initialise_replica_set()


@pytest.mark.skip_if_substrate(Substrate.k8s)
@pytest.mark.parametrize(("user"), (CharmedStatsUser, CharmedBackupUser))
def test_initialise_user_vm(harness: Harness[MongoTestCharm], mocker, user):
    harness.set_leader(True)
    mock_create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role",
    )
    mock_create_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
    )

    getattr(harness.charm.operator.mongo_manager, "_initialise_user")(user)
    config = getattr(
        harness.charm.operator.state, f"{user.username.replace('charmed-', '')}_config"
    )

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=[user.privileges])
    mock_create_user.assert_called_with(
        config.username,
        config.password,
        config.supported_roles,
        auth_restrictions=[
            {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
            {"clientSource": ["10.0.0.1/24"], "serverAddress": ["10.0.0.1/24"]},
        ],
    )

    assert harness.charm.operator.state.app_peer_data.is_user_created(user.username)


@pytest.mark.skip_if_substrate(Substrate.lxd)
@pytest.mark.parametrize(("user"), (CharmedStatsUser, CharmedBackupUser))
def test_initialise_user_k8s(harness: Harness[MongoTestCharm], mocker, user):
    harness.set_leader(True)
    mock_create_role = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role",
    )
    mock_create_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user",
    )

    getattr(harness.charm.operator.mongo_manager, "_initialise_user")(user)
    config = getattr(
        harness.charm.operator.state, f"{user.username.replace('charmed-', '')}_config"
    )

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=[user.privileges])
    mock_create_user.assert_called_with(
        config.username,
        config.password,
        config.supported_roles,
        auth_restrictions=[],
    )

    assert harness.charm.operator.state.app_peer_data.is_user_created(user.username)


@pytest.mark.skip_if_substrate(Substrate.k8s)
def test_reconcile_local_auth_restrictions_vm(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    state = harness.charm.operator.state
    for user in (CharmedStatsUser, CharmedBackupUser, CharmedLogRotateUser):
        state.app_peer_data.set_user_created(user.username)

    mock_update = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.update_user_auth_restrictions",
    )

    auth_restrictions = state.local_auth_restrictions
    harness.charm.operator.mongo_manager.update_users_local_auth_restrictions(auth_restrictions)

    assert mock_update.call_count == 3
    for call in mock_update.call_args_list:
        config = call.args[0]
        assert config.auth_restrictions == [
            {"clientSource": ["127.0.0.1"], "serverAddress": ["127.0.0.1"]},
            {"clientSource": ["10.0.0.1/24"], "serverAddress": ["10.0.0.1/24"]},
        ]


@pytest.mark.skip_if_substrate(Substrate.lxd)
def test_reconcile_local_auth_restrictions_k8s(harness: Harness[MongoTestCharm], mocker):
    harness.set_leader(True)
    state = harness.charm.operator.state
    for user in (CharmedStatsUser, CharmedBackupUser, CharmedLogRotateUser):
        state.app_peer_data.set_user_created(user.username)

    mock_update = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.update_user_auth_restrictions",
    )

    auth_restrictions = state.local_auth_restrictions
    harness.charm.operator.mongo_manager.update_users_local_auth_restrictions(auth_restrictions)

    assert mock_update.call_count == 3
    for call in mock_update.call_args_list:
        config = call.args[0]
        assert config.auth_restrictions == []


def test_update_cluster_ip_source_allowlist(harness: Harness[MongoTestCharm], mocker):
    mock_connection = mocker.patch("single_kernel_mongo.managers.mongo.MongoConnection")
    mock_update = (
        mock_connection.return_value.__enter__.return_value.set_cluster_ip_source_allowlist
    )

    harness.charm.operator.mongo_manager.update_cluster_ip_source_allowlist(["10.0.0.0/24"])

    config = mock_connection.call_args.args[0]
    assert config.username == CharmedOperatorUser.username
    assert config.hosts == {"localhost"}
    assert config.standalone is True
    assert mock_connection.call_args.kwargs == {"direct": True}
    mock_update.assert_called_once_with(["10.0.0.0/24"])


def test_initialise_operator_user(harness: Harness[MongoTestCharm], mocker, substrate: Substrate):
    harness.set_leader(True)
    if substrate == Substrate.lxd:
        mock_create_user = mocker.patch(
            "single_kernel_mongo.core.vm_workload.VMWorkload.run_bin_command"
        )
    else:
        mock_create_user = mocker.patch(
            "single_kernel_mongo.core.k8s_workload.KubernetesWorkload.run_bin_command"
        )

    getattr(harness.charm.operator.mongo_manager, "_initialise_charmed_operator_user")()
    config = getattr(harness.charm.operator.state, "operator_config")
    cmd = [
        "--quiet",
        "--eval",
        '"db.createUser({'
        f"  user: 'charmed-operator',"
        "  pwd: passwordPrompt(),"
        f"  roles: {OPERATOR_ROLE},"
        "  mechanisms: ['SCRAM-SHA-256'],"
        "  passwordDigestor: 'server',"
        '})"',
    ]

    mock_create_user.assert_called_with("mongodb://localhost/admin", cmd, input=config.password)

    assert harness.charm.operator.state.app_peer_data.is_user_created(CharmedOperatorUser.username)


GROUP_DN = "ou=superheroes,ou=users,dc=glauth,dc=com"


def _entity_setup(harness, mocker):
    harness.set_leader(True)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.REPLICATION
    harness.charm.operator.state.db_initialised = True
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists",
        return_value=False,
    )
    mocker.patch(
        "single_kernel_mongo.managers.mongo.MongoManager._compute_auth_restrictions",
        return_value=[],
    )
    return (
        mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.create_role"),
        mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.create_user"),
        mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_role"),
    )


def _group_relation(harness, data: dict[str, str], secret_content: dict | None = None):
    rel_id = harness.add_relation(RelationNames.DATABASE.value, "client-app")
    harness.add_relation_unit(rel_id, "client-app/0")
    if secret_content is not None:
        secret_id = harness.add_model_secret("client-app", secret_content)
        harness.grant_secret(secret_id, harness.charm.app.name)
        data = data | {"requested-entity-secret": secret_id}
    harness.update_relation_data(rel_id, "client-app", data)
    return rel_id


def _relation_statuses(harness, rel_id):
    return json.loads(harness.get_relation_data(rel_id, harness.charm.app.name).get("status", "[]"))


def _app_statuses(harness):
    return harness.charm.operator.state.statuses.get(
        scope="app", component=harness.charm.operator.name
    ).root


def test_group_entity_creates_role_and_publishes_name(harness, mocker):
    create_role, create_user, _ = _entity_setup(harness, mocker)
    permissions = [
        {"resource_name": "superdb.posts", "resource_type": "collection", "privileges": ["find"]}
    ]

    rel_id = _group_relation(
        harness,
        {
            "database": "superdb",
            "entity-type": "GROUP",
            "extra-group-roles": "default",
            "entity-permissions": json.dumps(permissions),
        },
        secret_content={"entity-name": GROUP_DN},
    )

    create_role.assert_called_once_with(
        GROUP_DN,
        [{"resource": {"db": "superdb", "collection": "posts"}, "actions": ["find"]}],
        [{"role": "readWrite", "db": "superdb"}, {"role": "enableSharding", "db": "superdb"}],
        exist_ok=False,
    )
    create_user.assert_not_called()
    data_interface = DatabaseProviderData(harness.model, RelationNames.DATABASE.value)
    assert data_interface.fetch_my_relation_field(rel_id, "entity-name") == GROUP_DN
    assert data_interface.fetch_my_relation_field(rel_id, "username") is None
    assert data_interface.fetch_my_relation_field(rel_id, "password") is None
    assert harness.charm.operator.state.app_peer_data.managed_entities == {str(rel_id): GROUP_DN}
    assert _relation_statuses(harness, rel_id) == []
    assert _app_statuses(harness) == []


def test_group_entity_default_name(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})

    assert create_role.call_args.args[0] == f"relation-{rel_id}"


def test_group_entity_is_idempotent(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)

    harness.charm.operator.mongo_manager.reconcile_mongo_users_and_dbs(relation)

    create_role.assert_called_once()


@pytest.mark.parametrize(
    ("data", "reason"),
    (
        ({"database": "superdb", "entity-type": "USER"}, "entity-type 'USER' is not supported"),
        ({"database": "superdb", "entity-type": "GROUP", "extra-group-roles": "root"}, "root"),
        (
            {"database": "superdb", "entity-type": "GROUP", "entity-permissions": "[1]"},
            "invalid entity-permissions",
        ),
    ),
)
def test_group_entity_invalid_request(harness, mocker, data, reason):
    create_role, _, _ = _entity_setup(harness, mocker)

    rel_id = _group_relation(harness, data)

    create_role.assert_not_called()
    statuses = _relation_statuses(harness, rel_id)
    assert len(statuses) == 1
    assert statuses[0]["code"] == EntityStatuses.INVALID_REQUEST_CODE
    assert reason in statuses[0]["message"]
    assert EntityStatuses.rejected(statuses[0]["message"], rel_id) in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_group_entity_mongodb_refused(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    create_role.side_effect = OperationFailure(
        "Role already exists", code=51002, details={"errmsg": "Role already exists"}
    )

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})

    statuses = _relation_statuses(harness, rel_id)
    assert statuses[0]["code"] == EntityStatuses.MONGODB_REFUSED_CODE
    assert statuses[0]["message"] == "MongoDB refused createRole: Role already exists"
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_group_entity_mongodb_refused_without_details(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    create_role.side_effect = OperationFailure("boom", code=2)

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})

    assert "boom" in _relation_statuses(harness, rel_id)[0]["message"]


def test_group_entity_rejected_stays_rejected(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    create_role.side_effect = OperationFailure("boom", code=2)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)
    create_role.side_effect = None

    harness.charm.operator.mongo_manager.reconcile_mongo_users_and_dbs(relation)

    create_role.assert_called_once()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_group_entity_non_fatal_status_does_not_stop_creation(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    rel_id = harness.add_relation(RelationNames.DATABASE.value, "client-app")
    harness.add_relation_unit(rel_id, "client-app/0")
    with harness.hooks_disabled():
        harness.update_relation_data(
            rel_id, "client-app", {"database": "superdb", "entity-type": "GROUP"}
        )
    data_interface = DatabaseProviderData(harness.model, RelationNames.DATABASE.value)
    data_interface.raise_status(
        rel_id, RelationStatus(code=1001, message="not fatal", resolution="wait")
    )
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)

    harness.charm.operator.mongo_manager.reconcile_mongo_users_and_dbs(relation)

    create_role.assert_called_once()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        str(rel_id): f"relation-{rel_id}"
    }


def test_group_entity_connection_error_defers_without_status(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    create_role.side_effect = AutoReconnect("no primary")
    defer = mocker.patch("ops.framework.EventBase.defer")

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})

    defer.assert_called()
    assert _relation_statuses(harness, rel_id) == []
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


@pytest.mark.parametrize("code", (13, 18))
def test_group_entity_auth_failure_defers_without_status(harness, mocker, code):
    create_role, _, _ = _entity_setup(harness, mocker)
    # The charm's own credentials failed, not the request: retried later.
    create_role.side_effect = OperationFailure("Authentication failed.", code=code)
    defer = mocker.patch("ops.framework.EventBase.defer")

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})

    create_role.assert_called()
    defer.assert_called()
    assert _relation_statuses(harness, rel_id) == []
    assert _app_statuses(harness) == []
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_group_entity_write_concern_error_records_the_role(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    # The primary applied createRole; only the replication acknowledgement is late.
    create_role.side_effect = WriteConcernError(
        "waiting for replication timed out",
        code=64,
        details={"errmsg": "waiting for replication timed out"},
    )
    defer = mocker.patch("ops.framework.EventBase.defer")

    rel_id = _group_relation(
        harness,
        {"database": "superdb", "entity-type": "GROUP"},
        secret_content={"entity-name": GROUP_DN},
    )

    create_role.assert_called_once()
    defer.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {str(rel_id): GROUP_DN}
    data_interface = DatabaseProviderData(harness.model, RelationNames.DATABASE.value)
    assert data_interface.fetch_my_relation_field(rel_id, "entity-name") == GROUP_DN
    assert _relation_statuses(harness, rel_id) == []
    assert _app_statuses(harness) == []


def test_group_entity_permissions_change_is_rejected(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    connection = mocker.patch("single_kernel_mongo.managers.mongo.MongoConnection")

    harness.update_relation_data(
        rel_id,
        "client-app",
        {
            "entity-permissions": '[{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]'
        },
    )

    connection.assert_not_called()
    statuses = _relation_statuses(harness, rel_id)
    assert statuses[0]["code"] == EntityStatuses.INVALID_REQUEST_CODE
    assert "changes to entity-permissions are not supported" in statuses[0]["message"]
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        str(rel_id): f"relation-{rel_id}"
    }


def test_permissions_change_on_plain_relation_is_ignored(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb"})

    harness.update_relation_data(
        rel_id,
        "client-app",
        {
            "entity-permissions": '[{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]'
        },
    )

    assert _relation_statuses(harness, rel_id) == []
    assert _app_statuses(harness) == []


def test_group_entity_relation_broken_drops_role(harness, mocker):
    _, _, drop_role = _entity_setup(harness, mocker)
    rel_id = _group_relation(
        harness,
        {"database": "superdb", "entity-type": "GROUP"},
        secret_content={"entity-name": GROUP_DN},
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )

    assert harness.charm.operator.state.app_peer_data.requested_entity_names == {
        str(rel_id): GROUP_DN
    }

    harness.remove_relation(rel_id)

    drop_role.assert_called_once_with(GROUP_DN)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    assert harness.charm.operator.state.app_peer_data.requested_entity_names == {}


def test_rejected_entity_relation_broken_clears_its_blocked_status(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "USER"})
    other_id = harness.add_relation(RelationNames.DATABASE.value, "other-app")
    harness.add_relation_unit(other_id, "other-app/0")
    harness.update_relation_data(
        other_id, "other-app", {"database": "otherdb", "entity-type": "USER"}
    )
    message = _relation_statuses(harness, rel_id)[0]["message"]
    other_message = _relation_statuses(harness, other_id)[0]["message"]
    assert EntityStatuses.rejected(message, rel_id) in _app_statuses(harness)
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )

    harness.remove_relation(rel_id)

    assert EntityStatuses.rejected(message, rel_id) not in _app_statuses(harness)
    assert EntityStatuses.rejected(other_message, other_id) in _app_statuses(harness)


def test_group_entity_scale_down_keeps_role(harness, mocker):
    _, _, drop_role = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )

    harness.remove_relation(rel_id)

    drop_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.requested_entity_names == {
        str(rel_id): f"relation-{rel_id}"
    }


def test_update_app_relation_data_skips_entity_relation(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)
    manager = harness.charm.operator.mongo_manager

    manager.update_app_relation_data(relation)
    manager.update_app_relation_data_for_config(relation, MongoConfigurationFactory.build())

    data = harness.get_relation_data(rel_id, harness.charm.app.name)
    assert "username" not in data and "password" not in data and "uris" not in data
    assert "endpoints" not in data


def test_group_entity_role_already_dropped(harness, mocker):
    _, _, drop_role = _entity_setup(harness, mocker)
    drop_role.side_effect = OperationFailure("no such role", code=31)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)

    harness.charm.operator.mongo_manager.remove_user(relation)

    drop_role.assert_called_once_with(f"relation-{rel_id}")
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_group_entity_drop_role_failure_keeps_record(harness, mocker):
    _, _, drop_role = _entity_setup(harness, mocker)
    drop_role.side_effect = OperationFailure("not authorized", code=13)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)

    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.remove_user(relation)

    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        str(rel_id): f"relation-{rel_id}"
    }


def test_rejected_entity_status_survives_recompute(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "USER"})
    operator = harness.charm.operator

    recomputed = operator.get_statuses(scope="app", recompute=True)

    message = _relation_statuses(harness, rel_id)[0]["message"]
    assert EntityStatuses.rejected(message, rel_id) in recomputed


def test_group_entity_publishes_only_entity_name(harness, mocker):
    _entity_setup(harness, mocker)
    mocker.patch(
        "single_kernel_mongo.state.tls_state.TLSState.get_secret", return_value="ext-ca-chain"
    )

    rel_id = _group_relation(
        harness,
        {"database": "superdb", "entity-type": "GROUP"},
        secret_content={"entity-name": GROUP_DN},
    )

    data = harness.get_relation_data(rel_id, harness.charm.app.name)
    # `data` is the charm's record of the requester's fields (update_diff), not a credential.
    assert set(data) == {"data", "entity-name"}
    assert data["entity-name"] == GROUP_DN


def test_refused_entity_relation_removal_drops_nothing(harness, mocker):
    create_role, _, drop_role = _entity_setup(harness, mocker)
    create_role.side_effect = OperationFailure(
        "Role already exists", code=51002, details={"errmsg": "Role already exists"}
    )
    rel_id = _group_relation(
        harness,
        {"database": "superdb", "entity-type": "GROUP"},
        secret_content={"entity-name": GROUP_DN},
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.has_departed_run", return_value=True
    )
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=False
    )

    harness.remove_relation(rel_id)

    # The role belongs to someone else: the charm never adopts it, so it never drops it.
    drop_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_update_user_skips_entity_relation(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    relation = harness.model.get_relation(RelationNames.DATABASE.value, rel_id)
    mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.user_exists",
        return_value=True,
    )
    update_user = mocker.patch(
        "single_kernel_mongo.utils.mongo_connection.MongoConnection.update_user"
    )

    harness.charm.operator.mongo_manager.update_user(relation)

    update_user.assert_not_called()


def test_healthy_entity_relation_reports_nothing_on_recompute(harness, mocker):
    _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    data_interface = DatabaseProviderData(harness.model, RelationNames.DATABASE.value)
    data_interface.raise_status(
        rel_id, RelationStatus(code=1001, message="not fatal", resolution="wait")
    )

    recomputed = harness.charm.operator.get_statuses(scope="app", recompute=True)

    assert not [s for s in recomputed if f"(relation {rel_id})" in s.message]


def test_start_reconciliation_creates_pending_group_role(harness, mocker):
    create_role, _, _ = _entity_setup(harness, mocker)
    harness.charm.operator.state.db_initialised = False
    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "GROUP"})
    create_role.assert_not_called()  # the request waits for the replica set
    manager = harness.charm.operator.mongo_manager
    mocker.patch.object(manager, "initialise_replica_set")
    mocker.patch.object(manager, "initialise_charm_admin_users")

    harness.charm.operator._initialise_replica_set()

    create_role.assert_called_once()
    assert create_role.call_args.args[0] == f"relation-{rel_id}"
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        str(rel_id): f"relation-{rel_id}"
    }
