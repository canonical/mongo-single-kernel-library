# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from parameterized import parameterized

from single_kernel_mongo.config.literals import MAX_PASSWORD_LENGTH
from single_kernel_mongo.exceptions import InvalidPasswordError
from single_kernel_mongo.utils.mongodb_users import (
    INTERNAL_ROLE_NAMES,
    CharmedBackupUser,
    CharmedLogRotateUser,
    CharmedOperatorUser,
    CharmedStatsUser,
    InternalUsers,
    MongoDBUser,
    get_user_from_username,
    roles_for_database,
    same_role_definition,
    validate_charm_user_password_config,
)

RANDOM_USER = MongoDBUser(
    username="deadbeef",
    database_name="abadcafe",
    roles={"default"},
    privileges=[{"resource": {"anyResource": True}, "actions": ["anyAction"]}],
    mongodb_role="",
    hosts=set("127.0.0.1"),
)


@parameterized.expand(
    [[CharmedBackupUser], [CharmedStatsUser], [CharmedOperatorUser], [CharmedLogRotateUser]]
)
def test_users_username(user: MongoDBUser):
    assert user.username == user.get_username()
    assert user.database_name == user.get_database_name()
    assert user.roles == user.get_roles()
    assert user.mongodb_role == user.get_mongodb_role()
    assert user.privileges == user.get_privileges()
    assert user.hosts == user.get_hosts()
    assert user.password_key_name == user.get_password_key_name()

    assert get_user_from_username(user.username) == user


def test_get_user_invalid_username():
    with pytest.raises(ValueError):
        get_user_from_username("invalid")


def test_valid_system_users_password_all_users():
    user_passwords = {user.username: "valid-password" for user in InternalUsers}
    validate_charm_user_password_config(user_passwords)


def test_valid_single_user():
    user_passwords = {"charmed-stats": "secure123"}
    validate_charm_user_password_config(user_passwords)


def test_valid_multiple_users_subset():
    user_passwords = {
        "charmed-operator": "secure123",
        "charmed-stats": "passw0rd",
    }
    validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_extra_user():
    user_passwords = {user.username: "something-valid123" for user in InternalUsers}
    user_passwords["intruder"] = "my-new_password"
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_empty_password():
    user_passwords = {user.username: "something-valid123" for user in InternalUsers}
    user_passwords["charmed-operator"] = ""
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_empty_space_password():
    user_passwords = {user.username: "something-valid123" for user in InternalUsers}
    user_passwords["charmed-operator"] = " "
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_password_too_long():
    user_passwords = {user.username: "something-valid123" for user in InternalUsers}
    user_passwords["charmed-stats"] = "x" * (MAX_PASSWORD_LENGTH + 1)
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_roles_for_database_expands_default_on_the_database():
    assert roles_for_database("superdb", {"default"}) == [
        {"role": "readWrite", "db": "superdb"},
        {"role": "enableSharding", "db": "superdb"},
    ]


def test_internal_users_privileges_are_lists():
    for user in InternalUsers:
        assert isinstance(user.privileges, list)
    assert CharmedLogRotateUser.privileges == [
        {"resource": {"cluster": True}, "actions": ["logRotate"]}
    ]


def test_internal_role_names():
    assert INTERNAL_ROLE_NAMES == frozenset({"explainRole", "pbmAnyAction", "logRotate"})


POSTS = {"db": "superdb", "collection": "posts"}
ROLE_PRIVILEGES = [
    {"resource": POSTS, "actions": ["find", "insert"]},
    {"resource": {"cluster": True}, "actions": ["serverStatus"]},
]
ROLE_ROLES = [{"role": "readWrite", "db": "superdb"}, {"role": "enableSharding", "db": "superdb"}]


def test_same_role_definition_ignores_order():
    # As `rolesInfo` may return it: reordered, with the privileges on a resource split.
    existing = {
        "privileges": [
            {"resource": {"cluster": True}, "actions": ["serverStatus"]},
            {"resource": {"collection": "posts", "db": "superdb"}, "actions": ["insert"]},
            {"resource": POSTS, "actions": ["find"]},
        ],
        "roles": list(reversed(ROLE_ROLES)),
    }

    assert same_role_definition(existing, ROLE_PRIVILEGES, ROLE_ROLES)


@pytest.mark.parametrize(
    "existing",
    (
        {"privileges": [ROLE_PRIVILEGES[0]], "roles": ROLE_ROLES},
        {"privileges": ROLE_PRIVILEGES, "roles": [{"role": "readWrite", "db": "superdb"}]},
        {"privileges": ROLE_PRIVILEGES, "roles": [{"role": "readWrite", "db": "other"}]},
    ),
)
def test_same_role_definition_detects_a_difference(existing: dict):
    assert not same_role_definition(existing, ROLE_PRIVILEGES, ROLE_ROLES)
