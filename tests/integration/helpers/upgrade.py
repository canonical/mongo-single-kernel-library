#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    MONGOD_PORT,
    OPERATOR_USERNAME,
    execute_on_mongod,
    find_unit,
    get_address_of_unit,
    get_password,
    get_unit_id,
)
from ..helpers.types import Substrate

logger = logging.getLogger(__name__)


async def get_workload_version(ops_test: OpsTest, unit_name: str) -> str:
    """Get the workload version of the deployed router charm."""
    return_code, output, _ = await ops_test.juju(
        "ssh",
        unit_name,
        "sudo",
        "cat",
        f"/var/lib/juju/agents/unit-{unit_name.replace('/', '-')}/charm/workload_version",
    )

    assert return_code == 0
    return output.strip()


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

    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "completed", "pre-refresh-check failed, expected to succeed."

    logger.info(f"Upgrading {app_name}")

    await refresh_charm(ops_test, substrate, app_name, new_charm, mongod_resource)
    # TODO future work, resolve flickering status of app
    async with ops_test.fast_forward(fast_interval="120s"):
        await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=60)

    # resume upgrade only needs to be ran when:
    # 1. there are more than one units in the application
    # 2. AND the underlying workload was updated
    if len(ops_test.model.applications[app_name].units) < 2:
        return

    if "resume-refresh" not in ops_test.model.applications[app_name].status_message:
        return

    logger.info(f"Calling resume-refresh for {app_name}")
    action = await leader_unit.run_action("resume-refresh")
    await action.wait()

    # Resume-refresh can fail while still triggering the upgrade if the leader
    # unit is the second unit to upgrade because it will be shut down
    # immediately on k8S.
    # This is a known limitation, so in that case we allow the action to fail.
    if "lxd" or (substrate == "microk8s" and leader_id != number_of_units - 2):
        assert action.status == "completed", "resume-refresh failed, expected to succeed."

    async with ops_test.fast_forward(fast_interval="60s"):
        await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=30)


async def refresh_with_juju(ops_test: OpsTest, app_name: str, channel: str) -> None:
    refresh_cmd = f"refresh {app_name} --model {ops_test.model.info.name} --channel {channel} --switch ch:mongodb"
    await ops_test.juju(*refresh_cmd.split())


async def set_fcv(
    ops_test: OpsTest, substrate: Substrate, app_name: str, fcv: str, port: int = MONGOD_PORT
) -> None:
    password = await get_password(ops_test, username=OPERATOR_USERNAME, app_name=app_name)
    replica_set_hosts = [
        await get_address_of_unit(ops_test, substrate, int(unit.name.split("/")[1]), app_name)
        for unit in ops_test.model.applications[app_name].units
    ]
    replica_set_hosts = [f"{host}:{port}" for host in replica_set_hosts]

    hosts = ",".join(replica_set_hosts)
    replica_set_uri = f"mongodb://operator:{password}@{hosts}/admin?replicaSet={app_name}"

    admin_mongod_cmd = (
        f"db.adminCommand({{setFeatureCompatibilityVersion: '{fcv}', confirm: true}})"
    )

    result = await execute_on_mongod(
        ops_test, app_name, substrate, replica_set_uri, admin_mongod_cmd, expecting_output=False
    )
    assert result.succeeded, f"Failed to set fcv to {fcv}."


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
