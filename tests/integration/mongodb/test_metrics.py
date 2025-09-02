#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import time

import httpx
import pytest
from juju.unit import Unit as JujuUnit
from pytest_operator.plugin import OpsTest

from ..helpers.common import (
    CHARMED_MONITOR_USERNAME,
    DEPLOYMENT_TIMEOUT,
    UNIT_IDS,
    check_or_scale_app,
    deploy_charm,
    find_unit,
    get_address_of_unit,
    get_app_name,
    get_unit_app,
    get_unit_id,
    unit_hostname,
)
from ..helpers.ha import cut_network_from_unit, restore_network_for_unit, wait_network_restore
from ..helpers.types import Substrate

MONGODB_EXPORTER_PORT = 9216
MEDIAN_REELECTION_TIME = 12


@pytest.mark.abort_on_fail
async def test_build_and_deploy(
    ops_test: OpsTest,
    mongodb_charm: str,
    substrate: Substrate,
    mongod_resource: dict,
    base_app_name: str,
) -> None:
    """Build and deploy one unit of MongoDB."""
    app_name = await get_app_name(ops_test)
    if app_name:
        await check_or_scale_app(ops_test, substrate, app_name, len(UNIT_IDS))
        return

    await deploy_charm(
        ops_test=ops_test,
        charm=mongodb_charm,
        substrate=substrate,
        mongod_resource=mongod_resource,
        app_name=base_app_name,
        num_units=len(UNIT_IDS),
    )
    await ops_test.model.wait_for_idle(timeout=DEPLOYMENT_TIMEOUT)


async def test_endpoints(ops_test: OpsTest, substrate: Substrate):
    """Sanity check that endpoints are running."""
    app_name = await get_app_name(ops_test)
    application = ops_test.model.applications[app_name]

    for unit in application.units:
        await verify_endpoints(ops_test, substrate, unit)


async def test_endpoints_new_password(ops_test: OpsTest, substrate: Substrate):
    """Verify that endpoints still function correctly after the monitor user password changes."""
    app_name = await get_app_name(ops_test)
    application = ops_test.model.applications[app_name]
    leader_unit = await find_unit(ops_test, leader=True)
    action = await leader_unit.run_action("set-password", **{"username": CHARMED_MONITOR_USERNAME})
    action = await action.wait()
    # wait for non-leader units to receive relation changed event.
    time.sleep(3)
    await ops_test.model.wait_for_idle(apps=[app_name], status="active", idle_period=15)
    for unit in application.units:
        await verify_endpoints(ops_test, substrate, unit)


async def test_endpoints_network_cut(ops_test: OpsTest, substrate: Substrate, chaos_mesh):
    """Verify that endpoint still function correctly after a network cut."""
    app_name = await get_app_name(ops_test)
    unit = ops_test.model.applications[app_name].units[0]
    unit_ip = await get_address_of_unit(
        ops_test, substrate, get_unit_id(unit.name), unit.name.split("/")[0]
    )
    if substrate == "lxd":
        hostname = await unit_hostname(ops_test, unit.name)
    else:
        hostname = unit.name

    cut_network_from_unit(ops_test, substrate, hostname)
    # sleep for twice the median election time
    time.sleep(MEDIAN_REELECTION_TIME * 2)

    # wait until network is reestablished for the unit
    restore_network_for_unit(ops_test, substrate, hostname)
    await wait_network_restore(
        ops_test, substrate, ops_test.model.info.name, app_name, hostname, unit_ip
    )
    await verify_endpoints(ops_test, substrate, unit)


# helpers


async def verify_endpoints(ops_test: OpsTest, substrate: Substrate, unit: JujuUnit) -> str:
    """Verifies mongodb endpoint is functional on a given unit."""
    unit_id, app_name = get_unit_app(unit.name)
    unit_address = await get_address_of_unit(ops_test, substrate, unit_id, app_name)
    mongodb_exporter_url = f"http://{unit_address}:{MONGODB_EXPORTER_PORT}/metrics"
    mongo_resp = httpx.get(mongodb_exporter_url)

    assert mongo_resp.status_code == 200

    # if configured correctly there should be more than one mongodb metric present
    mongodb_metrics = mongo_resp.text
    assert mongodb_metrics.count("mongo") > 1
