# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
from types import SimpleNamespace

import pytest
from ops.testing import Harness
from pymongo.errors import AutoReconnect, OperationFailure, PyMongoError, WriteConcernError

from single_kernel_mongo.config.relations import RelationNames
from single_kernel_mongo.config.statuses import MongodStatuses
from single_kernel_mongo.core.structured_config import MongoDBRoles
from single_kernel_mongo.exceptions import SetPasswordError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
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
from tests.unit.helpers import CONNECTION, GROUP_DN


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

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=user.privileges)
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

    mock_create_role.assert_called_with(role_name=user.mongodb_role, privileges=user.privileges)
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


GROUP_REQUEST = {"database": "superdb", "entity-type": "GROUP"}
PERMISSIONS = [
    {"resource_name": "superdb.posts", "resource_type": "collection", "privileges": ["find"]}
]
# `rolesInfo` documents of an existing role: one granting what GROUP_REQUEST asks, one not.
MATCHING_ROLE = {
    "privileges": [],
    "roles": [{"role": "enableSharding", "db": "superdb"}, {"role": "readWrite", "db": "superdb"}],
}
FOREIGN_ROLE = {"privileges": [], "roles": [{"role": "read", "db": "superdb"}]}


def _entity_setup(harness: Harness[MongoTestCharm], mocker) -> SimpleNamespace:
    """Initialised replica set leader with the MongoDB user and role calls patched."""
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
    return SimpleNamespace(
        get_role=mocker.patch(f"{CONNECTION}.get_role", return_value=None),
        create_role=mocker.patch(f"{CONNECTION}.create_role"),
        create_user=mocker.patch(f"{CONNECTION}.create_user"),
        drop_role=mocker.patch(f"{CONNECTION}.drop_role"),
    )


def _group_relation(
    harness: Harness[MongoTestCharm],
    data: dict[str, str],
    name: str | None = None,
    app: str = "client-app",
) -> int:
    """Adds a `database` relation whose requester publishes `data`.

    With `name`, the requester also shares a `requested-entity-secret` carrying it.
    """
    rel_id = harness.add_relation(RelationNames.DATABASE.value, app)
    harness.add_relation_unit(rel_id, f"{app}/0")
    if name is not None:
        secret_id = harness.add_model_secret(app, {"entity-name": name})
        harness.grant_secret(secret_id, harness.charm.app.name)
        data = data | {"requested-entity-secret": secret_id}
    harness.update_relation_data(rel_id, app, data)
    return rel_id


def _relation(harness: Harness[MongoTestCharm], rel_id: int):
    return harness.model.get_relation(RelationNames.DATABASE.value, rel_id)


def _published(harness: Harness[MongoTestCharm], rel_id: int, field: str) -> str | None:
    data_interface = DatabaseProviderData(harness.model, RelationNames.DATABASE.value)
    return data_interface.fetch_my_relation_field(rel_id, field)


def _app_statuses(harness: Harness[MongoTestCharm]) -> list:
    return harness.charm.operator.state.statuses.get(
        scope="app", component=harness.charm.operator.mongo_manager.name
    ).root


def test_add_entity_creates_role_and_publishes_name(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)

    rel_id = _group_relation(
        harness,
        GROUP_REQUEST
        | {"extra-group-roles": "default", "entity-permissions": json.dumps(PERMISSIONS)},
        name=GROUP_DN,
    )

    mocks.create_role.assert_called_once_with(
        GROUP_DN,
        [{"resource": {"db": "superdb", "collection": "posts"}, "actions": ["find"]}],
        [{"role": "readWrite", "db": "superdb"}, {"role": "enableSharding", "db": "superdb"}],
    )
    mocks.create_user.assert_not_called()
    assert _published(harness, rel_id, "entity-name") == GROUP_DN
    assert _published(harness, rel_id, "username") is None
    assert _published(harness, rel_id, "password") is None
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    assert _app_statuses(harness) == []


def test_add_entity_default_name(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)

    rel_id = _group_relation(harness, GROUP_REQUEST)

    assert mocks.create_role.call_args.args[0] == f"relation-{rel_id}"
    assert _published(harness, rel_id, "entity-name") == f"relation-{rel_id}"
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        rel_id: f"relation-{rel_id}"
    }


def test_entity_requested_event_creates_role(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    with harness.hooks_disabled():
        rel_id = _group_relation(harness, GROUP_REQUEST)
    relation = _relation(harness, rel_id)

    harness.charm.operator.client_events.database_provides.on.database_entity_requested.emit(
        relation, app=relation.app
    )

    mocks.create_role.assert_called_once()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        rel_id: f"relation-{rel_id}"
    }


def test_add_entity_is_idempotent(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, GROUP_REQUEST)

    harness.charm.operator.mongo_manager.add_entity(_relation(harness, rel_id))

    mocks.create_role.assert_called_once()


def test_add_entity_is_idempotent_after_secret_removed(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)
    secret_id = harness.get_relation_data(rel_id, "client-app")["requested-entity-secret"]

    # The requester stops sharing its secret once the entity name is published.
    harness.revoke_secret(secret_id, harness.charm.app.name)
    harness.charm.operator.mongo_manager.add_entity(_relation(harness, rel_id))

    mocks.create_role.assert_called_once()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    assert _app_statuses(harness) == []


def test_add_entity_invalid_request_sets_status(harness: Harness[MongoTestCharm], mocker, caplog):
    mocks = _entity_setup(harness, mocker)

    rel_id = _group_relation(harness, {"database": "superdb", "entity-type": "USER"})

    mocks.create_role.assert_not_called()
    mocks.create_user.assert_not_called()
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    assert _published(harness, rel_id, "entity-name") is None
    assert f"relation {rel_id}" in caplog.text
    assert "entity-type 'USER' is not supported" in caplog.text


def test_add_entity_skips_recorded_direct_relation_without_reading_the_role(
    harness: Harness[MongoTestCharm], mocker
):
    mocks = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)
    mocks.get_role.reset_mock()

    harness.charm.operator.mongo_manager.add_entity(_relation(harness, rel_id))

    mocks.get_role.assert_not_called()
    mocks.create_role.assert_called_once()


def test_add_entity_reserved_name_sets_status(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)

    _group_relation(harness, GROUP_REQUEST, name="charmed-operator")

    mocks.create_role.assert_not_called()
    assert MongodStatuses.INVALID_ENTITY_REQUEST.value in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_add_entity_does_not_adopt_existing_role(harness: Harness[MongoTestCharm], mocker, caplog):
    mocks = _entity_setup(harness, mocker)
    mocks.get_role.return_value = FOREIGN_ROLE

    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)

    mocks.get_role.assert_called_with(GROUP_DN)
    mocks.create_role.assert_not_called()
    assert MongodStatuses.ENTITY_ROLE_NOT_CREATED.value in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    assert _published(harness, rel_id, "entity-name") is None
    assert (
        f"Role {GROUP_DN} already exists with another definition or for another relation, "
        "not adopting it." in caplog.text
    )


def test_add_entity_adopts_role_with_requested_definition(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    # Created by a hook that failed afterwards: its record was discarded.
    mocks.get_role.return_value = MATCHING_ROLE

    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)

    mocks.create_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    assert _published(harness, rel_id, "entity-name") == GROUP_DN
    assert _app_statuses(harness) == []


def test_add_entity_does_not_adopt_role_of_another_relation(
    harness: Harness[MongoTestCharm], mocker
):
    mocks = _entity_setup(harness, mocker)
    first_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)
    mocks.get_role.return_value = MATCHING_ROLE

    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN, app="other-app")

    mocks.create_role.assert_called_once()
    assert MongodStatuses.ENTITY_ROLE_NOT_CREATED.value in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {first_id: GROUP_DN}
    assert _published(harness, rel_id, "entity-name") is None


def test_add_entity_mongodb_refusal_sets_status(harness: Harness[MongoTestCharm], mocker, caplog):
    mocks = _entity_setup(harness, mocker)
    mocks.create_role.side_effect = OperationFailure("privilege refused", code=96)
    defer = mocker.patch("ops.framework.EventBase.defer")

    rel_id = _group_relation(harness, GROUP_REQUEST)

    mocks.create_role.assert_called()
    defer.assert_not_called()
    assert MongodStatuses.ENTITY_ROLE_NOT_CREATED.value in _app_statuses(harness)
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    assert _published(harness, rel_id, "entity-name") is None
    assert f"relation {rel_id}" in caplog.text
    assert "privilege refused" in caplog.text


def test_add_entity_write_concern_error_records_role(
    harness: Harness[MongoTestCharm], mocker, caplog
):
    mocks = _entity_setup(harness, mocker)
    # Applied on the primary, only the majority acknowledgement timed out.
    mocks.create_role.side_effect = WriteConcernError("wtimeout", code=64)

    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)

    mocks.create_role.assert_called_once()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {rel_id: GROUP_DN}
    assert _published(harness, rel_id, "entity-name") == GROUP_DN
    assert _app_statuses(harness) == []
    assert any(
        record.levelno == logging.WARNING
        and f"Entity role {GROUP_DN} was created with a write concern error" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize("code", (13, 18))
def test_add_entity_auth_failure_propagates(harness: Harness[MongoTestCharm], mocker, code):
    mocks = _entity_setup(harness, mocker)
    # The charm's own credentials failed, not the request: retried later.
    mocks.create_role.side_effect = OperationFailure("Authentication failed.", code=code)
    defer = mocker.patch("ops.framework.EventBase.defer")

    rel_id = _group_relation(harness, GROUP_REQUEST)

    defer.assert_called()
    assert _app_statuses(harness) == []
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}
    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.add_entity(_relation(harness, rel_id))


def test_entity_relation_gets_no_credentials(harness: Harness[MongoTestCharm], mocker):
    _entity_setup(harness, mocker)
    harness.charm.operator.state.unit_peer_data.database_address = "10.0.0.1"
    entity_id = _group_relation(harness, GROUP_REQUEST)
    with harness.hooks_disabled():
        user_id = _group_relation(harness, {"database": "userdb"}, app="user-app")

    harness.charm.operator.update_related_hosts()

    entity_data = harness.get_relation_data(entity_id, harness.charm.app.name)
    user_data = harness.get_relation_data(user_id, harness.charm.app.name)
    for field in ("username", "password", "endpoints", "uris"):
        assert field not in entity_data
        assert user_data[field]


def test_relation_broken_drops_role_without_reading_relation_data(
    harness: Harness[MongoTestCharm], mocker
):
    mocks = _entity_setup(harness, mocker)
    drop_user = mocker.patch("single_kernel_mongo.utils.mongo_connection.MongoConnection.drop_user")
    rel_id = _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)
    secret_id = harness.get_relation_data(rel_id, "client-app")["requested-entity-secret"]
    # Juju does not guarantee the remote data in relation-broken: wipe the request.
    harness.revoke_secret(secret_id, harness.charm.app.name)
    with harness.hooks_disabled():
        harness.update_relation_data(
            rel_id,
            "client-app",
            {"database": "", "entity-type": "", "requested-entity-secret": ""},
        )

    harness.remove_relation(rel_id)

    mocks.drop_role.assert_called_once_with(GROUP_DN)
    drop_user.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_remove_entity_without_record_drops_nothing(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    harness.charm.operator.state.app_peer_data.managed_entities = {7: "other-role"}

    harness.charm.operator.mongo_manager.remove_entity(42)

    mocks.drop_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {7: "other-role"}


def test_remove_entity_keeps_record_when_drop_fails(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    mocks.drop_role.side_effect = OperationFailure("not authorized", code=13)
    harness.charm.operator.state.app_peer_data.managed_entities = {42: GROUP_DN}

    with pytest.raises(OperationFailure):
        harness.charm.operator.mongo_manager.remove_entity(42)

    assert harness.charm.operator.state.app_peer_data.managed_entities == {42: GROUP_DN}


def test_scale_down_keeps_role(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, GROUP_REQUEST)
    mocker.patch(
        "single_kernel_mongo.state.charm_state.CharmState.is_scaling_down", return_value=True
    )

    harness.remove_relation(rel_id)

    mocks.drop_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        rel_id: f"relation-{rel_id}"
    }


def test_get_statuses_recompute_reports_invalid_and_not_created(
    harness: Harness[MongoTestCharm], mocker, caplog
):
    mocks = _entity_setup(harness, mocker)
    _group_relation(harness, {"database": "superdb", "entity-type": "USER"}, app="user-a")
    _group_relation(harness, {"database": "superdb", "entity-type": "USER"}, app="user-b")
    mocks.get_role.return_value = FOREIGN_ROLE
    rel_id = _group_relation(harness, GROUP_REQUEST, app="group-app")
    caplog.clear()

    statuses = harness.charm.operator.mongo_manager.get_statuses(scope="app", recompute=True)

    # De-duplicated, in relation order: the invalid relations come first.
    assert statuses == [
        MongodStatuses.INVALID_ENTITY_REQUEST.value,
        MongodStatuses.ENTITY_ROLE_NOT_CREATED.value,
    ]
    assert "entity-type 'USER' is not supported" in caplog.text
    assert f"relation {rel_id}" in caplog.text
    # A persistent condition, logged on every recompute: a warning, not an error.
    levels = {record.levelno for record in caplog.records if "relation" in record.getMessage()}
    assert levels == {logging.WARNING}


def test_get_statuses_recompute_clean_when_managed(harness: Harness[MongoTestCharm], mocker):
    _entity_setup(harness, mocker)
    _group_relation(harness, GROUP_REQUEST, name=GROUP_DN)

    statuses = harness.charm.operator.mongo_manager.get_statuses(scope="app", recompute=True)

    assert statuses == []


def test_reconcile_entities_creates_pending_and_drops_orphans(
    harness: Harness[MongoTestCharm], mocker
):
    mocks = _entity_setup(harness, mocker)
    with harness.hooks_disabled():
        rel_id = _group_relation(harness, GROUP_REQUEST)
        # Still alive, but no longer carries an entity request.
        live_id = _group_relation(harness, {"database": "userdb"}, app="user-app")
    harness.charm.operator.state.app_peer_data.managed_entities = {
        live_id: "live-role",
        999: "orphan-role",
    }

    harness.charm.operator.reconcile_entities()

    mocks.create_role.assert_called_once()
    assert mocks.create_role.call_args.args[0] == f"relation-{rel_id}"
    mocks.drop_role.assert_called_once_with("orphan-role")
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        rel_id: f"relation-{rel_id}",
        live_id: "live-role",
    }


def test_reconcile_entities_continues_after_a_failing_relation(
    harness: Harness[MongoTestCharm], mocker
):
    mocks = _entity_setup(harness, mocker)
    with harness.hooks_disabled():
        _group_relation(harness, GROUP_REQUEST, app="group-a")
        _group_relation(harness, GROUP_REQUEST, app="group-b")
    mocks.create_role.side_effect = [AutoReconnect("no primary"), None]

    harness.charm.operator.reconcile_entities()

    assert mocks.create_role.call_count == 2
    assert len(harness.charm.operator.state.app_peer_data.managed_entities) == 1


def test_shard_serves_no_entity_requests(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    harness.charm.operator.state.app_peer_data.role = MongoDBRoles.SHARD
    with harness.hooks_disabled():
        _group_relation(harness, GROUP_REQUEST)

    # The request is neither reported nor served: the shard refuses the database relation.
    assert harness.charm.operator.mongo_manager.get_statuses("app", recompute=True) == []
    harness.charm.operator.reconcile_entities()

    mocks.create_role.assert_not_called()
    assert harness.charm.operator.state.app_peer_data.managed_entities == {}


def test_self_healing_reconciles_entities_last(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    with harness.hooks_disabled():
        rel_id = _group_relation(harness, GROUP_REQUEST)
    operator = harness.charm.operator
    order: list[str] = []
    reconcile_entities = operator.reconcile_entities

    def record_and_reconcile_entities() -> None:
        order.append("reconcile_entities")
        reconcile_entities()

    mocker.patch.object(operator.workload, "active", return_value=False)
    mocker.patch.object(operator, "process_unremoved_units")
    mocker.patch.object(operator, "peer_changed", side_effect=lambda: order.append("peer_changed"))
    mocker.patch.object(
        operator.mongo_manager,
        "set_election_priority",
        side_effect=lambda priority: order.append("set_election_priority"),
    )
    mocker.patch.object(operator, "reconcile_entities", side_effect=record_and_reconcile_entities)

    operator.perform_self_healing()

    # An error raised by the earlier steps fails the hook before any role is created.
    assert order == ["peer_changed", "set_election_priority", "reconcile_entities"]
    assert operator.state.app_peer_data.managed_entities == {rel_id: f"relation-{rel_id}"}
    mocks.create_role.assert_called_once()


def test_permissions_change_is_logged_only(harness: Harness[MongoTestCharm], mocker, caplog):
    mocks = _entity_setup(harness, mocker)
    rel_id = _group_relation(harness, GROUP_REQUEST)
    new_permissions = [{"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]}]

    with caplog.at_level(logging.WARNING):
        harness.update_relation_data(
            rel_id, "client-app", {"entity-permissions": json.dumps(new_permissions)}
        )

    mocks.create_role.assert_called_once()
    mocks.drop_role.assert_not_called()
    assert _app_statuses(harness) == []
    assert any(
        record.levelno == logging.WARNING
        and f"entity-permissions is not supported yet, the role of relation {rel_id}"
        in record.getMessage()
        for record in caplog.records
    )


def test_start_reconciliation_creates_entities(harness: Harness[MongoTestCharm], mocker):
    mocks = _entity_setup(harness, mocker)
    harness.charm.operator.state.db_initialised = False
    entity_id = _group_relation(harness, GROUP_REQUEST)
    user_id = _group_relation(harness, {"database": "userdb"}, app="user-app")
    mocks.create_role.assert_not_called()
    mocker.patch.object(harness.charm.operator.mongo_manager, "initialise_replica_set")
    mocker.patch.object(harness.charm.operator.mongo_manager, "initialise_charm_admin_users")

    harness.charm.operator._initialise_replica_set()

    mocks.create_role.assert_called_once()
    assert mocks.create_role.call_args.args[0] == f"relation-{entity_id}"
    mocks.create_user.assert_called_once()
    assert mocks.create_user.call_args.args[0] == f"relation-{user_id}"
    assert harness.charm.operator.state.app_peer_data.managed_entities == {
        entity_id: f"relation-{entity_id}"
    }
    assert harness.charm.operator.state.db_initialised
