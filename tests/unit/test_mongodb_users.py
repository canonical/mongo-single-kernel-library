# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from parameterized import parameterized

from single_kernel_mongo.utils.mongodb_users import (
    BackupUser,
    MongoDBUser,
    MonitorUser,
    OperatorUser,
)

RANDOM_USER = MongoDBUser(
    username="deadbeef",
    database_name="abadcafe",
    roles={"default"},
    privileges={"resource": {"anyResource": True}, "actions": ["anyAction"]},
    mongodb_role="",
    hosts=["127.0.0.1"],
)


@parameterized.expand(
    [
        [BackupUser, "backup-password"],
        [MonitorUser, "monitor-password"],
        [OperatorUser, "operator-password"],
    ]
)
def test_get_password_key_name_for_user(user: MongoDBUser, expected: str):
    assert MongoDBUser.get_password_key_name_for_user(user.username) == expected


def test_get_password_key_name_for_invalid_user():
    with pytest.raises(ValueError) as err:
        MongoDBUser.get_password_key_name_for_user(RANDOM_USER.username)
    assert RANDOM_USER.username in err.value.args[0]


@parameterized.expand([[BackupUser], [MonitorUser], [OperatorUser]])
def test_users_username(user: MongoDBUser):
    assert user.username == user.get_username()
    assert user.database_name == user.get_database_name()
    assert user.roles == user.get_roles()
    assert user.mongodb_role == user.get_mongodb_role()
    assert user.privileges == user.get_privileges()
    assert user.hosts == user.get_hosts()
    assert user.password_key_name == user.get_password_key_name()
