# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from parameterized import parameterized

from single_kernel_mongo.config.literals import MAX_PASSWORD_LENGTH
from single_kernel_mongo.exceptions import InvalidPasswordError
from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    CharmUsernames,
    LogRotateUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
    get_user_from_username,
    validate_charm_user_password_config,
)

RANDOM_USER = MongoDBUser(
    username="deadbeef",
    database_name="abadcafe",
    roles={"default"},
    privileges={"resource": {"anyResource": True}, "actions": ["anyAction"]},
    mongodb_role="",
    hosts=set("127.0.0.1"),
)


@parameterized.expand([[BackupUser], [MonitorUser], [OperatorUser], [LogRotateUser]])
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
    user_passwords = {username: "valid-password" for username in CharmUsernames}
    validate_charm_user_password_config(user_passwords)


def test_valid_single_user():
    user_passwords = {"monitor": "secure123"}
    validate_charm_user_password_config(user_passwords)


def test_valid_multiple_users_subset():
    user_passwords = {
        "operator": "secure123",
        "monitor": "passw0rd",
    }
    validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_extra_user():
    user_passwords = {username: "something-valid123" for username in CharmUsernames}
    user_passwords["intruder"] = "my-new_password"
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_empty_password():
    user_passwords = {username: "something-valid123" for username in CharmUsernames}
    user_passwords["operator"] = ""
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_empty_space_password():
    user_passwords = {username: "something-valid123" for username in CharmUsernames}
    user_passwords["operator"] = " "
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)


def test_invalid_system_users_password_too_long():
    user_passwords = {username: "something-valid123" for username in CharmUsernames}
    user_passwords["monitor"] = "x" * (MAX_PASSWORD_LENGTH + 1)
    with pytest.raises(InvalidPasswordError):
        validate_charm_user_password_config(user_passwords)
