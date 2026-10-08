# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import json

import pytest
from ops.model import SecretNotFoundError

from single_kernel_mongo.exceptions import EntityRequestError
from single_kernel_mongo.utils.entities import (
    EntityPermission,
    EntityRequest,
    entity_field_names,
    parse_entity_request,
)
from single_kernel_mongo.utils.mongo_config import roles_for


class FakeRelation:
    def __init__(self, name: str, relation_id: int = 7):
        self.name = name
        self.id = relation_id


class FakeDataInterface:
    def __init__(self, fields: dict[str, str]):
        self.fields = fields

    def fetch_relation_field(self, relation_id: int, field: str):
        return self.fields.get(field)


class FakeSecret:
    def __init__(self, content):
        self.content = content

    def get_content(self, refresh: bool = False):
        return self.content


class FakeModel:
    def __init__(self, secrets: dict[str, dict] | None = None):
        self.secrets = secrets or {}

    def get_secret(self, *, id: str):
        if id not in self.secrets:
            raise SecretNotFoundError(id)
        return FakeSecret(self.secrets[id])


def test_roles_for_default_and_admin():
    roles = roles_for("superdb", {"default", "admin"})
    assert {"role": "readWrite", "db": "superdb"} in roles
    assert {"role": "enableSharding", "db": "superdb"} in roles
    assert {"role": "userAdminAnyDatabase", "db": "admin"} in roles


@pytest.mark.parametrize(
    ("permission", "expected"),
    (
        (
            {"resource_name": "superdb", "resource_type": "db", "privileges": ["find"]},
            {"resource": {"db": "superdb", "collection": ""}, "actions": ["find"]},
        ),
        (
            {
                "resource_name": "superdb.posts.v2",
                "resource_type": "collection",
                "privileges": ["find", "insert"],
            },
            {
                "resource": {"db": "superdb", "collection": "posts.v2"},
                "actions": ["find", "insert"],
            },
        ),
        (
            {"resource_name": "", "resource_type": "cluster", "privileges": ["listShards"]},
            {"resource": {"cluster": True}, "actions": ["listShards"]},
        ),
        (
            {"resource_name": "x", "resource_type": "anyResource", "privileges": ["anyAction"]},
            {"resource": {"anyResource": True}, "actions": ["anyAction"]},
        ),
        (
            {"resource_name": ".posts", "resource_type": "collection", "privileges": ["find"]},
            {"resource": {"db": "", "collection": "posts"}, "actions": ["find"]},
        ),
    ),
)
def test_permission_to_mongodb(permission, expected):
    assert EntityPermission.model_validate(permission).to_mongodb() == expected


@pytest.mark.parametrize(
    "permission",
    (
        {"resource_name": "superdb", "resource_type": "DATABASE", "privileges": ["find"]},
        {"resource_name": "posts", "resource_type": "collection", "privileges": ["find"]},
        {"resource_name": "superdb", "resource_type": "db", "privileges": []},
        {"resource_name": "superdb", "resource_type": "db", "privileges": "find"},
        {"resource_name": "superdb", "resource_type": "db"},
        {"resource_name": "superdb", "resource_type": "db", "privileges": ["find"], "x": 1},
    ),
)
def test_permission_invalid(permission):
    with pytest.raises(ValueError):
        EntityPermission.model_validate(permission)


def test_permission_to_mongodb_rejects_an_unknown_resource_type():
    permission = EntityPermission.model_construct(
        resource_name="superdb", resource_type="DATABASE", privileges=["find"]
    )
    with pytest.raises(ValueError, match="DATABASE"):
        permission.to_mongodb()


@pytest.mark.parametrize(
    ("permissions", "reason"),
    (
        (
            [1],
            "invalid entity-permissions[0]: Input should be a valid dictionary or instance of "
            "EntityPermission",
        ),
        (
            [
                {"resource_name": "db", "resource_type": "db", "privileges": ["find"]},
                {"resource_name": "db", "resource_type": "DATABASE", "privileges": ["find"]},
            ],
            "invalid entity-permissions[1].resource_type: resource_type must be one of db, "
            "collection, cluster, anyResource",
        ),
        (
            [{"resource_name": "db", "resource_type": "db", "privileges": []}],
            "invalid entity-permissions[0].privileges: privileges must be a non-empty list of "
            "MongoDB actions",
        ),
        (
            [{"resource_name": "db", "resource_type": "db"}],
            "invalid entity-permissions[0].privileges: Field required",
        ),
        (
            [{"resource_name": "db", "resource_type": "db", "privileges": ["find", 1]}],
            "invalid entity-permissions[0].privileges[1]: Input should be a valid string",
        ),
        (
            [{"resource_name": "posts", "resource_type": "collection", "privileges": ["find"]}],
            "invalid entity-permissions[0]: a collection resource_name must be <db>.<collection>",
        ),
    ),
)
def test_parse_permission_reasons_name_the_item(permissions, reason):
    with pytest.raises(EntityRequestError) as exc:
        parse_entity_request(
            FakeModel(),
            FakeDataInterface(
                {
                    "database": "db",
                    "entity-type": "GROUP",
                    "entity-permissions": json.dumps(permissions),
                }
            ),
            FakeRelation("database"),
        )
    assert exc.value.reason == reason


def test_field_names_client_and_cluster():
    assert entity_field_names(FakeRelation("database"))["entity-type"] == "entity-type"
    assert entity_field_names(FakeRelation("mongos_proxy"))["entity-name"] == (
        "requested-entity-secret"
    )
    cluster = entity_field_names(FakeRelation("cluster"))
    assert cluster == {
        "entity-type": "client-entity-type",
        "extra-group-roles": "client-extra-group-roles",
        "entity-permissions": "client-entity-permissions",
        "entity-name": "client-entity-name",
    }


def test_parse_group_defaults():
    request = parse_entity_request(
        FakeModel(),
        FakeDataInterface({"database": "superdb", "entity-type": "GROUP"}),
        FakeRelation("database", 7),
    )
    assert request == EntityRequest(
        database="superdb", name="relation-7", extra_group_roles={"default"}, permissions=[]
    )
    assert request.roles() == roles_for("superdb", {"default"})
    assert request.privileges() == []


def test_parse_group_with_secret_name_and_permissions():
    permissions = [
        {"resource_name": "superdb.posts", "resource_type": "collection", "privileges": ["find"]}
    ]
    request = parse_entity_request(
        FakeModel({"secret:1": {"entity-name": "ou=superheroes,dc=glauth,dc=com"}}),
        FakeDataInterface(
            {
                "database": "superdb",
                "entity-type": "GROUP",
                "extra-group-roles": "admin,default",
                "requested-entity-secret": "secret:1",
                "entity-permissions": json.dumps(permissions),
            }
        ),
        FakeRelation("database", 7),
    )
    assert request.name == "ou=superheroes,dc=glauth,dc=com"
    assert request.extra_group_roles == {"admin", "default"}
    assert request.privileges() == [
        {"resource": {"db": "superdb", "collection": "posts"}, "actions": ["find"]}
    ]


def test_parse_ignores_password_in_requested_secret():
    request = parse_entity_request(
        FakeModel({"secret:1": {"entity-name": "cn=dba,dc=glauth,dc=com", "password": "pw"}}),
        FakeDataInterface(
            {"database": "superdb", "entity-type": "GROUP", "requested-entity-secret": "secret:1"}
        ),
        FakeRelation("database", 7),
    )
    assert request.name == "cn=dba,dc=glauth,dc=com"


def test_parse_cluster_relation_uses_client_keys():
    request = parse_entity_request(
        FakeModel(),
        FakeDataInterface(
            {
                "database": "superdb",
                "client-entity-type": "GROUP",
                "client-extra-group-roles": "admin",
                "client-entity-name": "cn=dba,dc=glauth,dc=com",
            }
        ),
        FakeRelation("cluster", 3),
    )
    assert request.name == "cn=dba,dc=glauth,dc=com"
    assert request.extra_group_roles == {"admin"}


@pytest.mark.parametrize(
    ("relation_name", "fields"),
    (
        ("database", {"requested-entity-secret": "secret:gone"}),
        ("cluster", {"client-entity-name": "cn=other,dc=glauth,dc=com"}),
    ),
)
def test_parse_with_a_known_name_does_not_read_the_name(relation_name, fields):
    names = entity_field_names(FakeRelation(relation_name))
    request = parse_entity_request(
        FakeModel(),
        FakeDataInterface(
            {
                "database": "superdb",
                names["entity-type"]: "GROUP",
                names["extra-group-roles"]: "admin",
            }
            | fields
        ),
        FakeRelation(relation_name, 7),
        name="ou=superheroes,dc=glauth,dc=com",
    )
    assert request.name == "ou=superheroes,dc=glauth,dc=com"
    assert request.extra_group_roles == {"admin"}


def test_parse_with_a_known_name_still_validates_the_request():
    with pytest.raises(EntityRequestError) as exc:
        parse_entity_request(
            FakeModel(),
            FakeDataInterface({"database": "superdb", "entity-type": "USER"}),
            FakeRelation("database", 7),
            name="ou=superheroes,dc=glauth,dc=com",
        )
    assert "entity-type 'USER' is not supported" in exc.value.reason


@pytest.mark.parametrize(
    ("fields", "secrets", "reason"),
    (
        ({"database": "db", "entity-type": "USER"}, {}, "entity-type 'USER' is not supported"),
        ({"entity-type": "GROUP"}, {}, "database is missing"),
        ({"database": "db", "entity-type": "GROUP", "extra-group-roles": "root"}, {}, "root"),
        ({"database": "db", "entity-type": "GROUP", "extra-group-roles": "admin, "}, {}, "empty"),
        (
            {"database": "db", "entity-type": "GROUP", "requested-entity-secret": "secret:9"},
            {},
            "requested-entity-secret",
        ),
        (
            {"database": "db", "entity-type": "GROUP", "requested-entity-secret": ""},
            {},
            "requested-entity-secret is empty",
        ),
        (
            {"database": "db", "entity-type": "GROUP", "requested-entity-secret": "secret:9"},
            {"secret:9": {"password": "x"}},
            "entity-name",
        ),
        (
            {"database": "db", "entity-type": "GROUP", "requested-entity-secret": "secret:9"},
            {"secret:9": {"entity-name": ""}},
            "empty",
        ),
        ({"database": "db", "entity-type": "GROUP", "entity-permissions": "nope"}, {}, "JSON"),
        (
            {"database": "db", "entity-type": "GROUP", "entity-permissions": '{"a": 1}'},
            {},
            "list",
        ),
        (
            {
                "database": "db",
                "entity-type": "GROUP",
                "entity-permissions": '[{"resource_name": "posts", "resource_type": "collection", "privileges": ["find"]}]',
            },
            {},
            "<db>.<collection>",
        ),
    ),
)
def test_parse_rejections(fields, secrets, reason):
    with pytest.raises(EntityRequestError) as exc:
        parse_entity_request(
            FakeModel(secrets), FakeDataInterface(fields), FakeRelation("database")
        )
    assert reason in exc.value.reason
