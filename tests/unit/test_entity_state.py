# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from ops.testing import Harness

from single_kernel_mongo.exceptions import InvalidEntityRequestError
from single_kernel_mongo.lib.charms.data_platform_libs.v0.data_interfaces import (
    DatabaseProviderData,
)
from single_kernel_mongo.state.entity_state import EntityState
from tests.charms.mongodb_test_charm.src.charm import MongoTestCharm
from tests.unit.helpers import GROUP_DN

GROUP_REQUEST = {"entity-type": "GROUP", "database": "blog"}


def _client_relation(harness: Harness[MongoTestCharm], data: dict[str, str]) -> int:
    """Adds a `database` relation whose requester published `data`."""
    with harness.hooks_disabled():
        harness.set_leader(True)
        rel_id = harness.add_relation("database", "client-app")
        harness.add_relation_unit(rel_id, "client-app/0")
        harness.update_relation_data(rel_id, "client-app", data)
    return rel_id


def _name_secret(harness: Harness[MongoTestCharm], name: str) -> str:
    """Adds a requester-owned `requested-entity-secret` granted to the provider."""
    secret_id = harness.add_model_secret("client-app", {"entity-name": name})
    harness.grant_secret(secret_id, harness.charm.app.name)
    return secret_id


def _state(harness: Harness[MongoTestCharm], rel_id: int) -> EntityState:
    return EntityState(
        harness.model.get_relation("database", rel_id),
        DatabaseProviderData(harness.model, "database"),
        harness.charm.app,
        harness.model,
    )


def test_not_requested_without_entity_type(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, {"database": "blog"})
    state = _state(harness, rel_id)

    assert state.requested is False
    assert state.entity_type == ""


def test_defaults(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    state = _state(harness, rel_id)

    assert state.requested is True
    assert state.entity_type == "GROUP"
    assert state.database == "blog"
    assert state.extra_group_roles == {"default"}
    assert state.permissions == []
    assert state.requested_name == f"relation-{rel_id}"
    assert state.entity_name == ""
    assert state.name == f"relation-{rel_id}"
    state.validate()


def test_name_from_secret(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    secret_id = _name_secret(harness, GROUP_DN)
    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "client-app", {"requested-entity-secret": secret_id})
    state = _state(harness, rel_id)

    assert state.requested_name == GROUP_DN
    assert state.name == GROUP_DN
    state.validate()


def test_name_prefers_published_entity_name(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    secret_id = _name_secret(harness, GROUP_DN)
    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "client-app", {"requested-entity-secret": secret_id})
    state = _state(harness, rel_id)
    state.entity_name = "x"

    # The requester no longer shares its secret: the requested name is unreadable.
    harness.revoke_secret(secret_id, harness.charm.app.name)
    with pytest.raises(InvalidEntityRequestError):
        state.requested_name

    assert state.name == "x"
    state.validate()


def test_entity_name_ignores_requester_value(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, GROUP_REQUEST | {"entity-name": "from-requester"})
    secret_id = _name_secret(harness, GROUP_DN)
    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "client-app", {"requested-entity-secret": secret_id})
    state = _state(harness, rel_id)

    assert state.entity_name == ""
    assert state.name == GROUP_DN


def test_entity_name_setter_publishes(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    state = _state(harness, rel_id)

    state.entity_name = GROUP_DN

    assert harness.get_relation_data(rel_id, harness.charm.app.name)["entity-name"] == GROUP_DN
    assert state.entity_name == GROUP_DN


def test_permissions_translation(harness: Harness[MongoTestCharm]):
    permissions = [
        {"resource_name": "blog", "resource_type": "db", "privileges": ["find", "insert"]},
        {"resource_name": "blog.posts", "resource_type": "collection", "privileges": ["update"]},
        {
            "resource_name": "blog.posts.archive",
            "resource_type": "collection",
            "privileges": ["remove"],
        },
        {"resource_name": "", "resource_type": "cluster", "privileges": ["serverStatus"]},
        {"resource_name": "ignored", "resource_type": "anyResource", "privileges": ["find"]},
    ]
    rel_id = _client_relation(
        harness, GROUP_REQUEST | {"entity-permissions": json.dumps(permissions)}
    )
    state = _state(harness, rel_id)

    assert state.permissions == [
        {"resource": {"db": "blog", "collection": ""}, "actions": ["find", "insert"]},
        {"resource": {"db": "blog", "collection": "posts"}, "actions": ["update"]},
        {"resource": {"db": "blog", "collection": "posts.archive"}, "actions": ["remove"]},
        {"resource": {"cluster": True}, "actions": ["serverStatus"]},
        {"resource": {"anyResource": True}, "actions": ["find"]},
    ]
    state.validate()


def _permission(**overrides) -> dict:
    return {"resource_name": "blog", "resource_type": "db", "privileges": ["find"]} | overrides


@pytest.mark.parametrize(
    "data, reason_part",
    [
        ({"entity-type": "USER"}, "entity-type 'USER' is not supported, only GROUP"),
        ({"database": ""}, "database is missing"),
        ({"extra-group-roles": "root"}, "unknown extra-group-roles value 'root'"),
        ({"extra-group-roles": "a,,b"}, "extra-group-roles contains an empty value"),
        ({"entity-permissions": "not json"}, "entity-permissions is not valid JSON"),
        (
            {"entity-permissions": json.dumps(_permission())},
            "entity-permissions must be a JSON list",
        ),
        (
            {"entity-permissions": json.dumps([{"resource_name": "blog", "actions": ["find"]}])},
            "invalid entity-permissions[0]: expected the keys resource_name, resource_type, "
            "privileges",
        ),
        (
            {"entity-permissions": json.dumps([_permission(resource_type="table")])},
            "invalid entity-permissions[0]: resource_type must be one of db, collection, "
            "cluster, anyResource",
        ),
        (
            {"entity-permissions": json.dumps([_permission(resource_name=1)])},
            "invalid entity-permissions[0]: resource_name must be a string",
        ),
        (
            {"entity-permissions": json.dumps([_permission(privileges=[])])},
            "invalid entity-permissions[0]: privileges must be a non-empty list of MongoDB "
            "actions",
        ),
        (
            {"entity-permissions": json.dumps([_permission(privileges=["find", ""])])},
            "invalid entity-permissions[0]: privileges must be a non-empty list of MongoDB "
            "actions",
        ),
        (
            {"entity-permissions": json.dumps([_permission(privileges="find")])},
            "invalid entity-permissions[0]: privileges must be a non-empty list of MongoDB "
            "actions",
        ),
        (
            {
                "entity-permissions": json.dumps(
                    [
                        _permission(),
                        _permission(resource_name="posts", resource_type="collection"),
                    ]
                )
            },
            "invalid entity-permissions[1]: a collection resource_name must be "
            "<db>.<collection>",
        ),
        (
            {
                "entity-permissions": json.dumps(
                    [_permission(resource_name="blog.", resource_type="collection")]
                )
            },
            "invalid entity-permissions[0]: a collection resource_name must be "
            "<db>.<collection>",
        ),
        (
            {
                "entity-permissions": json.dumps(
                    [_permission(resource_name=".posts", resource_type="collection")]
                )
            },
            "invalid entity-permissions[0]: a collection resource_name must be "
            "<db>.<collection>",
        ),
    ],
)
def test_validate_rejects(harness: Harness[MongoTestCharm], data: dict, reason_part: str):
    rel_id = _client_relation(harness, GROUP_REQUEST | data)
    state = _state(harness, rel_id)

    with pytest.raises(InvalidEntityRequestError) as exc_info:
        state.validate()

    assert reason_part in str(exc_info.value)


@pytest.mark.parametrize(
    "name",
    [
        "charmed-operator",
        "charmed-stats",
        "explainRole",
        "pbmAnyAction",
        "logRotate",
        "charmed-anything",
    ],
)
def test_validate_rejects_reserved_names(harness: Harness[MongoTestCharm], name: str):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    secret_id = _name_secret(harness, name)
    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "client-app", {"requested-entity-secret": secret_id})
    state = _state(harness, rel_id)

    with pytest.raises(InvalidEntityRequestError) as exc_info:
        state.validate()

    assert str(exc_info.value) == f"entity-name '{name}' is reserved"


def test_validate_rejects_unreadable_secret(harness: Harness[MongoTestCharm]):
    rel_id = _client_relation(
        harness, GROUP_REQUEST | {"requested-entity-secret": "secret:deadbeef"}
    )
    state = _state(harness, rel_id)

    with pytest.raises(InvalidEntityRequestError) as exc_info:
        state.validate()

    assert str(exc_info.value) == "cannot read requested-entity-secret"


@pytest.mark.parametrize(
    "content, reason",
    [
        ({"name": GROUP_DN}, "requested-entity-secret has no entity-name key"),
        ({"entity-name": ""}, "entity-name is empty"),
    ],
)
def test_validate_rejects_secret_without_name(
    harness: Harness[MongoTestCharm], content: dict[str, str], reason: str
):
    rel_id = _client_relation(harness, GROUP_REQUEST)
    secret_id = harness.add_model_secret("client-app", content)
    harness.grant_secret(secret_id, harness.charm.app.name)
    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "client-app", {"requested-entity-secret": secret_id})
    state = _state(harness, rel_id)

    with pytest.raises(InvalidEntityRequestError) as exc_info:
        state.validate()

    assert str(exc_info.value) == reason


def test_forwarded_reads_client_prefixed_keys(harness: Harness[MongoTestCharm]):
    permissions = [{"resource_name": "blog", "resource_type": "db", "privileges": ["find"]}]
    with harness.hooks_disabled():
        harness.set_leader(True)
        rel_id = harness.add_relation("cluster", "mongos")
        harness.add_relation_unit(rel_id, "mongos/0")
        harness.update_relation_data(
            rel_id,
            "mongos",
            {
                "database": "blog",
                "client-entity-type": "GROUP",
                "client-extra-group-roles": "admin",
                "client-entity-permissions": json.dumps(permissions),
                "client-entity-name": GROUP_DN,
            },
        )
    state = EntityState(
        harness.model.get_relation("cluster", rel_id),
        DatabaseProviderData(harness.model, "cluster"),
        harness.charm.app,
        harness.model,
        forwarded=True,
    )

    assert state.requested is True
    assert state.entity_type == "GROUP"
    assert state.database == "blog"
    assert state.extra_group_roles == {"admin"}
    assert state.permissions == [
        {"resource": {"db": "blog", "collection": ""}, "actions": ["find"]}
    ]
    assert state.requested_name == GROUP_DN
    assert state.name == GROUP_DN
    state.validate()
    # The mongos rewrites its request: the requested name wins over a published one.
    state.entity_name = "ou=previous"
    assert state.name == GROUP_DN

    with harness.hooks_disabled():
        harness.update_relation_data(rel_id, "mongos", {"client-entity-name": ""})

    with pytest.raises(InvalidEntityRequestError) as exc_info:
        state.validate()

    assert str(exc_info.value) == "entity-name is empty"
