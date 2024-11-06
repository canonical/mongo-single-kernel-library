# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB users and their configuration."""


from typing import Any, NewType, TypedDict

from pydantic import BaseModel, Field, computed_field

from single_kernel_mongo.config.literals import InternalUsers


class DBPrivilege(TypedDict, total=False):
    """A DB Privilege on db."""

    role: str
    db: str
    collection: str


UserRole = NewType("UserRole", list[DBPrivilege])

SYSTEM_DBS = ["admin", "local", "config"]

REGULAR_ROLES = {
    "admin": UserRole(
        [
            DBPrivilege(role="userAdminAnyDatabase", db="admin"),
            DBPrivilege(role="readWriteAnyDatabase", db="admin"),
            DBPrivilege(role="userAdmin", db="admin"),
            DBPrivilege(role="enableSharding", db="admin"),
        ]
    ),
    "monitor": UserRole(
        [
            DBPrivilege(role="explainRole", db="admin"),
            DBPrivilege(role="clusterMonitor", db="admin"),
            DBPrivilege(role="read", db="local"),
        ]
    ),
    "backup": UserRole(
        [
            DBPrivilege(db="admin", role="readWrite", collection=""),
            DBPrivilege(db="admin", role="backup"),
            DBPrivilege(db="admin", role="clusterMonitor"),
            DBPrivilege(db="admin", role="restore"),
            DBPrivilege(db="admin", role="pbmAnyAction"),
        ]
    ),
}


class MongoDBUser(BaseModel):
    """Base model for MongoDB users."""

    username: str = ""
    database_name: str = ""
    roles: set[str] = Field(default=set())
    privileges: dict[str, Any] = Field(default={})
    mongodb_role: str = ""
    hosts: list = []

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

    def get_hosts(self) -> list:
        """Returns the hosts of the user."""
        return self.hosts

    @staticmethod
    def get_password_key_name_for_user(username: str) -> str:
        """Returns the key name for the password of the user."""
        if username == OperatorUser.get_username():
            return OperatorUser.get_password_key_name()
        if username == MonitorUser.get_username():
            return MonitorUser.get_password_key_name()
        if username == BackupUser.get_username():
            return BackupUser.get_password_key_name()
        raise ValueError(f"Unknown user: {username}")


OperatorUser = MongoDBUser(
    username=InternalUsers.OPERATOR,
    database_name="admin",
    roles={"default"},
)

MonitorUser = MongoDBUser(
    username=InternalUsers.MONITOR,
    database_name="admin",
    roles={"monitor"},
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
    hosts=[
        "127.0.0.1"
    ],  # MongoDB Exporter can only connect to one replica - not the entire set.
)

BackupUser = MongoDBUser(
    username=InternalUsers.BACKUP,
    roles={"backup"},
    mongodb_role="pbmAnyAction",
    privileges={"resource": {"anyResource": True}, "actions": ["anyAction"]},
    hosts=[
        "127.0.0.1"
    ],  # pbm cannot make a direct connection if multiple hosts are used
)
