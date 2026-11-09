# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
"""Definition of MongoDB users and their configuration."""

from enum import Enum
from itertools import chain
from typing import Any, NewType, TypedDict

from pydantic import BaseModel, Field, computed_field

from single_kernel_mongo.config.literals import LOCALHOST, MAX_PASSWORD_LENGTH, InternalUsernames
from single_kernel_mongo.exceptions import InvalidPasswordError


class AuthRestrictions(TypedDict, total=False):
    """Authentication Restrictions.

    See https://www.mongodb.com/docs/manual/reference/method/db.createUser/#authentication-restrictions.
    """

    clientSource: list[str]  # List of IPs / CIDRS
    serverAddress: list[str]  # List of IPs / CIDRS


class DBPrivilege(TypedDict, total=False):
    """A DB Privilege on db."""

    role: str
    db: str
    collection: str


class RolePrivilege(TypedDict):
    """A MongoDB privilege document: a resource and the actions allowed on it."""

    resource: dict[str, Any]
    actions: list[str]


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
    privileges: list[RolePrivilege] = Field(default=[])
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

    def get_privileges(self) -> list[RolePrivilege]:
        """Returns the privileges of the user."""
        return self.privileges

    def get_hosts(self) -> set[str]:
        """Returns the hosts of the user."""
        return self.hosts


CharmedOperatorUser = MongoDBUser(
    username=InternalUsernames.CHARMED_OPERATOR,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.DEFAULT},
)

CharmedStatsUser = MongoDBUser(
    username=InternalUsernames.CHARMED_STATS,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.MONITOR},
    privileges=[
        {
            "resource": {"db": "", "collection": ""},
            "actions": [
                "listIndexes",
                "listCollections",
                "dbStats",
                "dbHash",
                "collStats",
                "find",
            ],
        }
    ],
    mongodb_role="explainRole",
    hosts={LOCALHOST},  # MongoDB Exporter can only connect to one replica.
)

CharmedBackupUser = MongoDBUser(
    username=InternalUsernames.CHARMED_BACKUP,
    roles={RoleNames.BACKUP},
    privileges=[{"resource": {"anyResource": True}, "actions": ["anyAction"]}],
    mongodb_role="pbmAnyAction",
    hosts={LOCALHOST},  # pbm cannot make a direct connection if multiple hosts are used
)

CharmedLogRotateUser = MongoDBUser(
    username=InternalUsernames.CHARMED_LOGROTATE,
    database_name=SystemDBS.ADMIN,
    roles={RoleNames.LOGROTATE},
    privileges=[{"resource": {"cluster": True}, "actions": ["logRotate"]}],
    mongodb_role="logRotate",
    hosts={LOCALHOST},
)

InternalUsers = (
    CharmedOperatorUser,
    CharmedBackupUser,
    CharmedStatsUser,
    CharmedLogRotateUser,
)

INTERNAL_ROLE_NAMES = frozenset(user.mongodb_role for user in InternalUsers if user.mongodb_role)


def roles_for_database(database: str, roles: set[str]) -> UserRole:
    """Expand charm role names into MongoDB roles for the given database.

    Args:
        database: the database the "default" role applies to.
        roles: charm role names (see RoleNames), e.g. {"default", "admin"}.

    Returns:
        The MongoDB role documents granted by those charm roles.
    """
    default_role = UserRole(
        [
            DBPrivilege(role="readWrite", db=database),
            DBPrivilege(role="enableSharding", db=database),
        ]
    )
    all_roles = REGULAR_ROLES | {"default": default_role}
    return UserRole(list(chain.from_iterable(all_roles[role] for role in roles)))


def same_role_definition(
    existing: dict, privileges: list[RolePrivilege], roles: list[DBPrivilege]
) -> bool:
    """Whether a role read with `rolesInfo` grants exactly these privileges and roles.

    The order of the privileges, of their actions and of the roles does not matter.

    Args:
        existing: the role document, read with `showPrivileges`.
        privileges: the privileges the role should grant.
        roles: the roles it should inherit from.
    """

    def actions_by_resource(items: list) -> dict[tuple, set[str]]:
        actions: dict[tuple, set[str]] = {}
        for item in items:
            actions.setdefault(tuple(sorted(item["resource"].items())), set()).update(
                item["actions"]
            )
        return actions

    existing_actions = actions_by_resource(existing.get("privileges", []))
    existing_roles = {(role["role"], role["db"]) for role in existing.get("roles", [])}
    wanted_roles = {(role["role"], role["db"]) for role in roles}
    return existing_actions == actions_by_resource(privileges) and existing_roles == wanted_roles


def get_user_from_username(username: str) -> MongoDBUser:
    """Return the MongoDBUser instance that matches the given username.

    Raises:
        ValueError: If the username is not one of the known users.
    """
    if username == CharmedOperatorUser.username:
        return CharmedOperatorUser
    if username == CharmedStatsUser.username:
        return CharmedStatsUser
    if username == CharmedBackupUser.username:
        return CharmedBackupUser
    if username == CharmedLogRotateUser.username:
        return CharmedLogRotateUser
    raise ValueError(f"Unknown user: {username}")


def validate_charm_user_password_config(user_passwords: dict[str, str]) -> None:
    """Validate a mapping of charm usernames to passwords.

    Rules:
      - Only internal charmed usernames are allowed.
      - Passwords must not be empty or only whitespace.
      - Passwords must not exceed MAX_PASSWORD_LENGTH characters.

    Raises:
        InvalidPasswordError: if any validation rule is violated.
    """
    internal_usernames = {user.username for user in InternalUsers}
    if extra_users := set(user_passwords.keys()) - internal_usernames:
        raise InvalidPasswordError(f"Unexpected usernames provided: {', '.join(extra_users)}")

    for username, password in user_passwords.items():
        if not (pwd := password.strip()):
            raise InvalidPasswordError(
                f"Password for user '{username}' cannot be empty or whitespace"
            )
        if len(pwd) > MAX_PASSWORD_LENGTH:
            raise InvalidPasswordError(
                f"Password for user '{username}' exceeds max length of {MAX_PASSWORD_LENGTH} characters"
            )
