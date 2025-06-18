#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    find_unit,
    get_app_name,
    unit_hostname,
)
from ...helpers.ha import cut_network_from_unit, verify_writes, wait_until_unit_in_status
from ...helpers.types import Substrate
from ...helpers.upgrade import refresh_charm

logger = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, substrate: Substrate, base_app_name) -> None:
    """Build and deploy one unit of MongoDB."""
    mongodb_charm_name = "mongodb" if substrate == "lxd" else "mongodb-k8s"

    await ops_test.model.deploy(
        mongodb_charm_name, channel="6/edge", num_units=3, application_name=base_app_name
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name], status="active", timeout=DEPLOYMENT_TIMEOUT, idle_period=120
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
    try:
        action = await leader_unit.run_action("pre-refresh-check")
        await action.wait()
    # Catch renaming of pre-upgrade-check to pre-refresh-check
    except Exception:
        action = await leader_unit.run_action("pre-upgrade-check")
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
    cut_network_from_unit(ops_test, substrate, await unit_hostname(ops_test, unit.name))

    await wait_until_unit_in_status(
        ops_test, substrate, unit, leader_unit, "(not reachable/healthy)", app_name
    )

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()
    assert action.status == "failed", "pre-refresh-check succeeded, expected to fail."
