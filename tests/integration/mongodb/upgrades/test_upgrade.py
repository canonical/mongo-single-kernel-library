#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

import pytest
from pytest_operator.plugin import OpsTest

from ...helpers.common import (
    DEPLOYMENT_TIMEOUT,
    deploy_charm,
    find_unit,
    get_app_name,
    get_juju_status,
    get_unit_id,
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
        channel="8/edge",
    )

    await ops_test.model.wait_for_idle(
        apps=[base_app_name],
        status="active",
        timeout=DEPLOYMENT_TIMEOUT,
        idle_period=20,
        raise_on_error=False,
        raise_on_blocked=False,
    )


@pytest.mark.abort_on_fail
async def test_upgrade(
    ops_test: OpsTest,
    substrate: Substrate,
    mongodb_charm: str,
    mongod_resource: dict[str, str],
    continuous_writes_to_db,
) -> None:
    """Verifies that the upgrade can run successfully."""
    app_name = await get_app_name(ops_test)

    number_of_units = len(ops_test.model.applications[app_name].units)
    leader_unit = await find_unit(ops_test, leader=True, app_name=app_name)
    leader_id = get_unit_id(leader_unit.name)
    mongodb_application = ops_test.model.applications[app_name]
    # Refresh always happens from highest to lowest unit number
    refresh_order = sorted(
        mongodb_application.units,
        key=lambda unit: int(unit.name.split("/")[1]),
        reverse=True,
    )

    logger.info("Calling pre-refresh-check")
    action = await leader_unit.run_action("pre-refresh-check")
    await action.wait()

    assert action.status == "completed", "pre-refresh-check-failed, expected to succeed"

    logger.info("Refreshing the application")
    await refresh_charm(ops_test, substrate, app_name, mongodb_charm, mongod_resource)
    await ops_test.model.wait_for_idle(apps=[app_name], timeout=1000, idle_period=120)

    if "incompatible" in get_juju_status(ops_test.model.name, app_name):
        logger.info("Upgrade is blocked due to incompatibility")

        logger.info(f"Continue refresh on unit {refresh_order[0].name}")
        logger.info("Running `force-refresh-start` action with check-compatibility=false")
        force_refresh_action = await refresh_order[0].run_action(
            "force-refresh-start",
            **{"check-compatibility": False, "run-pre-refresh-checks": False},
        )
        force_refresh_response = await force_refresh_action.wait()
        assert force_refresh_response.results.get("return-code") == 0, "action failed"

    await ops_test.model.wait_for_idle(apps=[app_name], idle_period=20)

    if "resume-refresh" in mongodb_application.status_message:
        logger.info("Continue refresh on all other units with `resume-refresh` action")
        logger.info("Calling resume refresh")
        if substrate == "lxd":
            unit = refresh_order[1]
        else:
            unit = leader_unit

        action = await unit.run_action("resume-refresh")
        await action.wait()
        if (substrate == "lxd") or (substrate == "microk8s" and leader_id != number_of_units - 2):
            assert action.status == "completed", "resume-refresh failed, expected to succeed."

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
