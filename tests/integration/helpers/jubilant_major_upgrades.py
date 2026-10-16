#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import jubilant

from tests.integration.helpers.constants import (
    CHARMED_BACKUP_USERNAME,
    CHARMED_LOGROTATE_USERNAME,
    CHARMED_OPERATOR_USERNAME,
    CHARMED_STATS_USERNAME,
)
from tests.integration.helpers.jubilant_common import (
    execute_on_mongod,
    get_mongodb_hostnames_for_app,
    get_password,
    replica_set_uri,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

USERNAME_MAPPING = {
    CHARMED_OPERATOR_USERNAME: "operator",
    CHARMED_STATS_USERNAME: "monitor",
    CHARMED_BACKUP_USERNAME: "backup",
    CHARMED_LOGROTATE_USERNAME: "logrotate",
}


def add_rel8_internal_users(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> None:
    """Add all internal MongoDB8 user with given roles."""
    rel8_internal_users = {
        "charmed-operator": [
            {"role": "userAdminAnyDatabase", "db": "admin"},
            {"role": "readWriteAnyDatabase", "db": "admin"},
            {"role": "clusterAdmin", "db": "admin"},
        ],
        "charmed-backup": [
            {"role": "backup", "db": "admin"},
            {"role": "readWrite", "db": "admin"},
            {"role": "clusterMonitor", "db": "admin"},
            {"role": "restore", "db": "admin"},
            {"role": "pbmAnyAction", "db": "admin"},
        ],
        "charmed-logrotate": [
            {"role": "logRotate", "db": "admin"},
        ],
        "charmed-stats": [
            {"role": "explainRole", "db": "admin"},
            {"role": "clusterMonitor", "db": "admin"},
            {"role": "read", "db": "local"},
        ],
    }

    for rel8_username, roles in rel8_internal_users.items():
        rel6_username = USERNAME_MAPPING[rel8_username]
        password = get_password(juju, username=rel6_username, app_name=app_name)
        _add_internal_user(juju, substrate, app_name, rel8_username, password, roles)


def _build_create_user_command(username: str, password: str, roles: list[dict[str, str]]) -> str:
    """Build a MongoDB createUser command string."""
    roles_str = ", ".join([f"{{role: '{r['role']}', db: '{r['db']}'}}" for r in roles])
    return (
        "db.createUser({"
        f"user: '{username}', "
        f"pwd: '{password}', "
        f"roles: [{roles_str}], "
        "mechanisms: ['SCRAM-SHA-256'], "
        "passwordDigestor: 'server'"
        "})"
    )


def _add_internal_user(
    juju: jubilant.Juju,
    substrate: Substrate,
    app_name: str,
    username: str,
    password: str,
    roles: list[dict[str, str]],
) -> None:
    """Add an internal MongoDB user with given roles."""
    operator_password = get_password(juju, username="operator", app_name=app_name)
    replica_set_hosts = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    uri = replica_set_uri(
        username="operator",
        password=operator_password,
        ip_addresses=list(replica_set_hosts),
        replica_set=app_name,
    )

    add_user_cmd = _build_create_user_command(username, password, roles)

    result = execute_on_mongod(juju, substrate, app_name, uri, add_user_cmd, expecting_output=False)
    assert result.succeeded, f"Failed to add internal user {username} to {app_name}."


def delete_rel6_internal_users(juju: jubilant.Juju, substrate: Substrate, app_name: str) -> None:
    """Delete all the internal MongoDB6 users."""
    operator_password = get_password(juju, username=CHARMED_OPERATOR_USERNAME, app_name=app_name)
    replica_set_hosts = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    uri = replica_set_uri(
        username=CHARMED_OPERATOR_USERNAME,
        password=operator_password,
        ip_addresses=list(replica_set_hosts),
        replica_set=app_name,
    )

    for rel6_username in USERNAME_MAPPING.values():
        delete_user_cmd = f"db.dropUser('{rel6_username}')"
        result = execute_on_mongod(
            juju, substrate, app_name, uri, delete_user_cmd, expecting_output=False
        )
        assert result.succeeded, f"Failed to delete internal user {rel6_username} from {app_name}."


def set_fcv(
    juju: jubilant.Juju, substrate: Substrate, app_name: str, fcv: str, username: str
) -> None:
    password = get_password(juju, username=username, app_name=app_name)
    replica_set_hosts = get_mongodb_hostnames_for_app(juju, substrate, app_name)

    uri = replica_set_uri(
        username=username,
        password=password,
        ip_addresses=list(replica_set_hosts),
        replica_set=app_name,
    )

    admin_mongod_cmd = (
        f"db.adminCommand({{setFeatureCompatibilityVersion: '{fcv}', confirm: true}})"
    )

    result = execute_on_mongod(
        juju, substrate, app_name, uri, admin_mongod_cmd, expecting_output=False
    )
    assert result.succeeded, f"Failed to set fcv to {fcv}."


def get_password_action(
    juju: jubilant.Juju,
    username: str,
    app_name: str,
) -> str:
    """Use the charm action to retrieve the password from provided unit.

    This action is only used for MongoDB 6.

    Returns:
        String with the password stored on the peer relation databag.
    """
    unit_name = next(iter(juju.status().get_units(app_name)))

    task = juju.run(unit_name, "get-password", {"username": username})
    try:
        return task.results["password"]
    except KeyError:
        logger.error("Failed to get password. Action %s. Results %s", task, task.results)
        raise
