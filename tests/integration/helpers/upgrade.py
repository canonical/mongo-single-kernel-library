#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import tomllib
from pytest_operator.plugin import OpsTest

from tests.integration.helpers.common import (
    CHARMED_BACKUP_USERNAME,
    CHARMED_OPERATOR_USERNAME,
    CHARMED_STATS_USERNAME,
    MONGOD_PORT,
    execute_on_mongod,
    find_unit,
    get_address_of_unit,
    get_juju_status,
    get_password,
    get_unit_id,
)
from tests.integration.helpers.types import Substrate

logger = logging.getLogger(__name__)

USERNAME_MAPPING = {
    CHARMED_OPERATOR_USERNAME: "operator",
    CHARMED_STATS_USERNAME: "monitor",
    CHARMED_BACKUP_USERNAME: "backup",
    "charmed-logrotate": "logrotate",
}


async def get_workload_version(ops_test: OpsTest, unit_name: str) -> str:
    """Get the workload version of the deployed router charm."""
    return_code, output, _ = await ops_test.juju(
        "ssh",
        unit_name,
        "sudo",
        "cat",
        f"/var/lib/juju/agents/unit-{unit_name.replace('/', '-')}/charm/refresh_versions.toml",
    )

    assert return_code == 0
    data = tomllib.loads(output)
    return data["workload"]


async def refresh_charm(
    ops_test: OpsTest, substrate: Substrate, app_name: str, mongo_charm: str, mongod_resource: dict
):
    if substrate == "lxd":
        await ops_test.model.applications[app_name].refresh(path=mongo_charm)
    else:
        await ops_test.model.applications[app_name].refresh(
            path=mongo_charm, resources=mongod_resource
        )


async def assert_successful_run_upgrade_sequence(
    ops_test: OpsTest, substrate: Substrate, app_name: str, new_charm: str, mongod_resource: dict
) -> None:
    """Runs the upgrade sequence on a given app."""
    number_of_units = len(ops_test.model.applications[app_name].units)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    leader_id = get_unit_id(leader_unit.name)

    mongodb_application = ops_test.model.applications[app_name]
    refresh_order = sorted(
        mongodb_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )

    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "completed", "pre-refresh-check failed, expected to succeed."

    logger.info(f"Upgrading {app_name}")

    await refresh_charm(ops_test, substrate, app_name, new_charm, mongod_resource)
    # TODO future work, resolve flickering status of app
    async with ops_test.fast_forward(fast_interval="120s"):
        await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=20)

    if any(
        item in get_juju_status(ops_test.model.name, app_name)
        for item in ("incompatible", "missing/incorrect")
    ):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0].name}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_action = await refresh_order[0].run_action(
            "force-refresh-start",
            **{
                "check-compatibility": False,
                "run-pre-refresh-checks": False,
                "check-workload-container": False,
            },
        )
        force_refresh_response = await force_refresh_action.wait()
        assert force_refresh_response.results.get("return-code") == 0, "action failed"

    await ops_test.model.wait_for_idle(apps=[app_name], raise_on_blocked=False)

    if "resume-refresh" in get_juju_status(ops_test.model.name, app_name):
        logger.info(f"Calling resume-refresh for {app_name}")
        action = await leader_unit.run_action("resume-refresh")
        await action.wait()
        # Resume-refresh can fail while still triggering the upgrade if the leader
        # unit is the second unit to upgrade because it will be shut down
        # immediately on k8S.
        # This is a known limitation, so in that case we allow the action to fail.
        if (substrate == "lxd") or (substrate == "microk8s" and leader_id != number_of_units - 2):
            assert action.status == "completed", "resume-refresh failed, expected to succeed."

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=30)


async def refresh_with_juju(
    ops_test: OpsTest, app_name: str, channel: str, charm_name: str
) -> None:
    refresh_cmd = f"refresh {app_name} --model {ops_test.model.info.name} --channel {channel} --switch ch:{charm_name}"
    logger.info(f"[refresh_with_juju] {refresh_cmd}")
    await ops_test.juju(*refresh_cmd.split())


async def set_fcv(
    ops_test: OpsTest, substrate: Substrate, app_name: str, fcv: str, username: str
) -> None:
    password = await get_password(ops_test, username=username, app_name=app_name)
    replica_set_hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    replica_set_hosts = [f"{host}:{MONGOD_PORT}" for host in replica_set_hosts]

    hosts = ",".join(replica_set_hosts)
    replica_set_uri = f"mongodb://{username}:{password}@{hosts}/admin?replicaSet={app_name}"

    admin_mongod_cmd = (
        f"db.adminCommand({{setFeatureCompatibilityVersion: '{fcv}', confirm: true}})"
    )

    result = await execute_on_mongod(
        ops_test, app_name, substrate, replica_set_uri, admin_mongod_cmd, expecting_output=False
    )
    assert result.succeeded, f"Failed to set fcv to {fcv}."


def _build_create_user_command(username: str, password: str, roles: list[dict]) -> str:
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


async def _add_internal_user(
    ops_test: OpsTest,
    substrate: Substrate,
    app_name: str,
    username: str,
    password: str,
    roles: list[dict],
) -> None:
    """Add an internal MongoDB user with given roles."""
    operator_password = await get_password(ops_test, username="operator", app_name=app_name)
    replica_set_hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    replica_set_hosts = [f"{host}:{MONGOD_PORT}" for host in replica_set_hosts]
    hosts = ",".join(replica_set_hosts)

    replica_set_uri = f"mongodb://operator:{operator_password}@{hosts}/admin?replicaSet={app_name}"
    add_user_cmd = _build_create_user_command(username, password, roles)

    result = await execute_on_mongod(
        ops_test, app_name, substrate, replica_set_uri, add_user_cmd, expecting_output=False
    )
    assert result.succeeded, f"Failed to add internal user {username} to {app_name}."


async def add_rel8_internal_users(ops_test: OpsTest, substrate: Substrate, app_name: str) -> None:
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
        password = await get_password(ops_test, username=rel6_username, app_name=app_name)
        await _add_internal_user(ops_test, substrate, app_name, rel8_username, password, roles)


async def delete_rel6_internal_users(
    ops_test: OpsTest, substrate: Substrate, app_name: str
) -> None:
    """Delete all the internal MongoDB6 users."""
    operator_password = await get_password(
        ops_test, username=CHARMED_OPERATOR_USERNAME, app_name=app_name
    )
    replica_set_hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    replica_set_hosts = [f"{host}:{MONGOD_PORT}" for host in replica_set_hosts]
    hosts = ",".join(replica_set_hosts)

    replica_set_uri = f"mongodb://{CHARMED_OPERATOR_USERNAME}:{operator_password}@{hosts}/admin?replicaSet={app_name}"

    for rel6_username in USERNAME_MAPPING.values():
        delete_user_cmd = f"db.dropUser('{rel6_username}')"
        result = await execute_on_mongod(
            ops_test, app_name, substrate, replica_set_uri, delete_user_cmd, expecting_output=False
        )
        assert result.succeeded, f"Failed to delete internal user {rel6_username} from {app_name}."


async def get_password_action(
    ops_test: OpsTest,
    username: str,
    app_name: str,
) -> str:
    """Use the charm action to retrieve the password from provided unit.

    This action is only used for MongoDB 6.

    Returns:
        String with the password stored on the peer relation databag.
    """
    unit_name = ops_test.model.applications[app_name].units[0].name
    unit_id = unit_name.split("/")[1]

    action = await ops_test.model.units.get(f"{app_name}/{unit_id}").run_action(
        "get-password", **{"username": username}
    )
    action = await action.wait()
    try:
        return action.results["password"]
    except KeyError:
        logger.error("Failed to get password. Action %s. Results %s", action, action.results)
        return None
