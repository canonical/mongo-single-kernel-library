# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from parameterized import parameterized

from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
    get_user_from_username,
)

RANDOM_USER = MongoDBUser(
    username="deadbeef",
    database_name="abadcafe",
    roles={"default"},
    privileges={"resource": {"anyResource": True}, "actions": ["anyAction"]},
    mongodb_role="",
    hosts=set("127.0.0.1"),
)


@parameterized.expand([[BackupUser], [MonitorUser], [OperatorUser]])
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
