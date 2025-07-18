# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB users and their configuration."""

from enum import Enum
from typing import Any, NewType, TypedDict

from pydantic import BaseModel, Field, computed_field

from single_kernel_mongo.config.literals import LOCALHOST, InternalUsers


class DBPrivilege(TypedDict, total=False):
    """A DB Privilege on db."""

    role: str
    db: str
    collection: str


UserRole = NewType("UserRole", list[DBPrivilege])


class SystemDBS(str, Enum):
    """MongoDB System databases."""

    ADMIN = "admin"
    LOCAL = "local"
    CONFIG = "config"


class RoleNames(str, Enum):
    """Charm defined roles."""

    ADMIN = "admin"
    MONITOR = "monitor"
    BACKUP = "backup"
    DEFAULT = "default"
    OPERATOR = "operator"
    LOGROTATE = "logRotate"


OPERATOR_ROLE = UserRole(
    [
        DBPrivilege(role="userAdminAnyDatabase", db="admin"),
        DBPrivilege(role="readWriteAnyDatabase", db="admin"),
        DBPrivilege(role="clusterAdmin", db="admin"),
    ]
)

REGULAR_ROLES = {
    RoleNames.ADMIN: UserRole(
        [
            DBPrivilege(role="userAdminAnyDatabase", db="admin"),
            DBPrivilege(role="readWriteAnyDatabase", db="admin"),
            DBPrivilege(role="userAdmin", db="admin"),
            DBPrivilege(role="enableSharding", db="admin"),
        ]
    ),
    RoleNames.MONITOR: UserRole(
        [
            DBPrivilege(role="explainRole", db="admin"),
            DBPrivilege(role="clusterMonitor", db="admin"),
            DBPrivilege(role="read", db="local"),
        ]
    ),
    RoleNames.BACKUP: UserRole(
        [
            DBPrivilege(db="admin", role="readWrite", collection=""),
            DBPrivilege(db="admin", role="backup"),
            DBPrivilege(db="admin", role="clusterMonitor"),
            DBPrivilege(db="admin", role="restore"),
            DBPrivilege(db="admin", role="pbmAnyAction"),
        ]
    ),
    RoleNames.LOGROTATE: UserRole(
        [
            DBPrivilege(db="admin", role="logRotate"),
        ]
    ),
}


class MongoDBUser(BaseModel):
    """Base model for MongoDB users."""

    username: str = Field(default="")
    database_name: str = Field(default="")
    roles: set[str] = Field(default=set())
    privileges: dict[str, Any] = Field(default={})
    mongodb_role: str = Field(default="")
    hosts: set[str] = Field(default=set())

    @computed_field  # type: ignore[misc]
    @property
    def password_key_name(self) -> str:
        """Returns the key name for the password of the user."""
        return f"{self.username}-password"

    # DEPRECATE: All the following methods are for backward compatibility and
    # will be deprecated soon
    def get_username(self) -> str:
        """Returns the username of the user."""
        return self.username

    def get_password_key_name(self) -> str:
        """Returns the key name for the password of the user."""
        return self.password_key_name

    def get_database_name(self) -> str:
        """Returns the database of the user."""
        return self.database_name

    def get_roles(self) -> set[str]:
        """Returns the role of the user."""
        return self.roles

    def get_mongodb_role(self) -> str:
        """Returns the MongoDB role of the user."""
        return self.mongodb_role

    def get_privileges(self) -> dict:
        """Returns the privileges of the user."""
        return self.privileges

    def get_hosts(self) -> set[str]:
        """Returns the hosts of the user."""
        return self.hosts


OperatorUser = MongoDBUser(
    username=InternalUsers.OPERATOR,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.DEFAULT},
)

MonitorUser = MongoDBUser(
    username=InternalUsers.MONITOR,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.MONITOR},
    privileges={
        "resource": {"db": "", "collection": ""},
        "actions": [
            "listIndexes",
            "listCollections",
            "dbStats",
            "dbHash",
            "collStats",
            "find",
        ],
    },
    mongodb_role="explainRole",
    hosts={LOCALHOST},  # MongoDB Exporter can only connect to one replica.
)

BackupUser = MongoDBUser(
    username=InternalUsers.BACKUP,
    roles={RoleNames.BACKUP},
    privileges={"resource": {"anyResource": True}, "actions": ["anyAction"]},
    mongodb_role="pbmAnyAction",
    hosts={LOCALHOST},  # pbm cannot make a direct connection if multiple hosts are used
)

LogRotateUser = MongoDBUser(
    username=InternalUsers.LOGROTATE,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.LOGROTATE},
    privileges={"resource": {"cluster": True}, "actions": ["logRotate"]},
    mongodb_role="logRotate",
    hosts={LOCALHOST},
)


CharmUsers = (
    OperatorUser.username,
    BackupUser.username,
    MonitorUser.username,
    LogRotateUser.username,
)


def get_user_from_username(username: str) -> MongoDBUser:
    """Returns the key name for the password of the user."""
    if username == OperatorUser.username:
        return OperatorUser
    if username == MonitorUser.username:
        return MonitorUser
    if username == BackupUser.username:
        return BackupUser
    if username == LogRotateUser.username:
        return LogRotateUser
    raise ValueError(f"Unknown user: {username}")
