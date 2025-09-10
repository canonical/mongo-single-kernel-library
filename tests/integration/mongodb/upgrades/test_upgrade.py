#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    OPERATOR_USERNAME,
    deploy_charm,
    find_unit,
    get_app_name,
    get_password,
    set_password,
    unit_hostname,
)
from ...helpers.ha import (
    cut_network_from_unit,
    restore_network_for_unit,
    verify_writes,
    wait_until_unit_in_status,
)
from ...helpers.types import Substrate
from ...helpers.upgrade import refresh_charm

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, substrate: Substrate, base_app_name) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    await deploy_charm(
        ops_test,
        mongodb_charm_name,
        substrate,
        app_name=base_app_name,
        mongod_resource={},  # unused
        channel="6/stable",
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name],
        status="active",
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=120,
        raise_on_error=False,
        raise_on_blocked=False,
    )


@pytest.mark.abort_on_fail
async def test_upgrade(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict,
    continuous_writes_to_db,
) -> None:
    """Verifies that the upgrade can run successfully."""
    app_name = await get_app_name(ops_test)

    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()

    assert action.status == "completed", "pre-refresh-check-failed, expected to succeed"

    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=120
    )

    app_name = await get_app_name(ops_test)
    await refresh_charm(ops_test, substrate, app_name, mongodb_charm, mongod_resource)
    await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=120)

    if "resume-refresh" in ops_test.model.applications[app_name].status_message:
        logger.info("Calling resume refresh")
        action = await leader_unit.run_action("resume-refresh")
        await action.wait()
        assert action.status == "completed", "resume-refresh failed, expected to succeed"

        await ops_test.model.wait_for_idle(
            apps=[app_name], status="active", timeout=1000, idle_period=120
        )

    # verify that the no writes were skipped
    await verify_writes(ops_test, substrate, app_name)


@pytest.mark.abort_on_fail
async def test_preflight_check(ops_test: OpsTest) -> None:
    """Verifies that the preflight check can run successfully."""
    app_name = await get_app_name(ops_test)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "completed", "pre-refresh-check failed, expected to succeed."

    await ops_test.model.wait_for_idle(
        apps=[app_name], status="active", timeout=1000, idle_period=20
    )


@pytest.mark.abort_on_fail
async def test_preflight_check_failure(ops_test: OpsTest, substrate: Substrate, chaos_mesh) -> None:
    """Verifies that the preflight check can run successfully."""
    app_name = await get_app_name(ops_test)
    unit = await find_unit(ops_test, leader=False, app_name=app_name)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    machine_name = await unit_hostname(ops_test, unit.name)
    cut_network_from_unit(ops_test, substrate, machine_name)

    await wait_until_unit_in_status(
        ops_test, substrate, unit, leader_unit, "(not reachable/healthy)", app_name
    )

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "failed", "pre-refresh-check succeeded, expected to fail."

    restore_network_for_unit(ops_test, substrate, machine_name)

    await ops_test.model.wait_for_idle(
        apps=[app_name],
        status="active",
        timeout=1000,
        idle_period=30,
        raise_on_error=False,
    )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_substrate("lxd")  # This test does not work well on VM if no snap refresh
async def test_upgrade_password_change_fail(
    ops_test: OpsTest, substrate: Substrate, mongodb_charm: str, mongod_resource: dict
):
    app_name = await get_app_name(ops_test)
    current_password = await get_password(
        ops_test,
        username=OPERATOR_USERNAME,
        app_name=app_name,
    )

    await refresh_charm(ops_test, substrate, app_name, mongodb_charm, mongod_resource)
    await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=120)

    app_name = await get_app_name(ops_test)
    await set_password(
        ops_test, username=OPERATOR_USERNAME, password="new-password", app_name=app_name
    )
    await ops_test.model.wait_for_idle(apps=[app_name], status="blocked", idle_period=12)
    # test status

    after_action_password = await get_password(
        ops_test,
        username=OPERATOR_USERNAME,
        app_name=app_name,
    )
    assert current_password == after_action_password

    # wait for update to be finished and check password
